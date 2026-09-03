#!/usr/bin/env python3
"""Target six data-facing methods reached during final Home startup.

The methods are selected from the proven one-hop Home startup report. This helper
emits only:
- exact method name/RVA/signature;
- a small initial ARM64 window;
- direct named calls excluding framework/runtime noise;
- small contexts around calls whose names look like user/work/temp/master state.

It never emits a global method index, strings table, or complete decompilation.
"""
from __future__ import annotations

import argparse
import bisect
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

TARGET_NAMES = (
    "Stage.Home$$CardDownloadList",
    "Stage.WorkDataUtil$$GetFavoriteUnitData",
    "Stage.PresentAllPopup$$GetAllPresentPopupItemList",
    "Stage.HomeCustomUtil$$SetBannerAssetList",
    "Stage.TempData.GenericSpPageTempData$$ExistsAnyLoginBonus",
    "Stage.DirectAndLimitedLoginBonusPopup$$GetDirectAndLimitedLoginBonusPopupAssetName",
)
INITIAL_WINDOW = 0x240
FULL_SCAN_MAX_SIZE = 0x5000
CONTEXT_INSTRUCTIONS = 5
MAX_NAMED_CALLS = 160
FRAMEWORK_PREFIXES = (
    "UnityEngine.",
    "System.",
    "CodeStage.",
    "Cysharp.",
)
STATE_TERMS = (
    "User",
    "Work",
    "TempData",
    "LocalData",
    "Savedata",
    "Card",
    "Unit",
    "Chara",
    "Idol",
    "Present",
    "LoginBonus",
    "Banner",
    "Master",
    "Asset",
    "Data",
    "Manager",
)


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: str | None


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(f"unsupported address: {value!r}")


def load_methods(path: Path) -> tuple[dict[int, Method], dict[str, Method], list[int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    by_addr: dict[int, Method] = {}
    by_name: dict[str, Method] = {}
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        method = Method(address, str(item["Name"]), item.get("Signature"))
        by_addr.setdefault(address, method)
        by_name.setdefault(method.name, method)
    starts = set(by_addr)
    for value in data.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    return by_addr, by_name, sorted(starts)


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.segments: list[tuple[int, int, int, int]] = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            self.segments.append(
                (
                    int(segment["p_vaddr"]),
                    int(segment["p_memsz"]),
                    int(segment["p_offset"]),
                    int(segment["p_filesz"]),
                )
            )

    def close(self) -> None:
        self.stream.close()

    def read(self, address: int, size: int) -> bytes:
        for vaddr, memsz, offset, filesz in self.segments:
            if vaddr <= address < vaddr + memsz:
                relative = address - vaddr
                if relative >= filesz:
                    return b""
                count = min(size, filesz - relative)
                self.stream.seek(offset + relative)
                return self.stream.read(count)
        return b""


def disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def function_end(address: int, starts: list[int], max_size: int) -> int:
    index = bisect.bisect_right(starts, address)
    next_start = starts[index] if index < len(starts) else address + max_size
    return min(next_start, address + max_size)


def format_instruction(instruction: Any) -> str:
    return f"0x{instruction.address:X}: {instruction.mnemonic} {instruction.op_str}"


def call_from_instruction(instruction: Any, by_addr: dict[int, Method]) -> dict[str, Any] | None:
    if (
        instruction.id != ARM64_INS_BL
        or not instruction.operands
        or instruction.operands[0].type != ARM64_OP_IMM
    ):
        return None
    target = int(instruction.operands[0].imm)
    method = by_addr.get(target)
    if method is None:
        return None
    return {"site": instruction.address, "target": target, "name": method.name}


def relevant_call_name(name: str) -> bool:
    if name.startswith(FRAMEWORK_PREFIXES):
        return False
    return any(term in name for term in STATE_TERMS)


def analyze_method(
    view: BinaryView,
    method: Method,
    starts: list[int],
    by_addr: dict[int, Method],
) -> dict[str, Any]:
    end = function_end(method.address, starts, FULL_SCAN_MAX_SIZE)
    instructions = list(disassembler().disasm(view.read(method.address, end - method.address), method.address))

    named_calls: list[dict[str, Any]] = []
    relevant_contexts: list[dict[str, Any]] = []
    for index, instruction in enumerate(instructions):
        call = call_from_instruction(instruction, by_addr)
        if call is None:
            continue
        if call["name"].startswith(FRAMEWORK_PREFIXES):
            continue
        named_calls.append(call)
        if relevant_call_name(call["name"]):
            lo = max(0, index - CONTEXT_INSTRUCTIONS)
            hi = min(len(instructions), index + CONTEXT_INSTRUCTIONS + 1)
            relevant_contexts.append(
                {
                    **call,
                    "context": [format_instruction(item) for item in instructions[lo:hi]],
                }
            )
    if len(named_calls) > MAX_NAMED_CALLS:
        raise RuntimeError(
            f"{method.name} has {len(named_calls)} non-framework named calls; refine before emitting"
        )

    initial_end = min(end, method.address + INITIAL_WINDOW)
    initial = list(
        disassembler().disasm(
            view.read(method.address, initial_end - method.address),
            method.address,
        )
    )
    return {
        "name": method.name,
        "rva": method.address,
        "signature": method.signature,
        "scanned_size": end - method.address,
        "named_calls": named_calls,
        "state_contexts": relevant_contexts,
        "initial_disassembly": [format_instruction(item) for item in initial],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    by_addr, by_name, starts = load_methods(args.script_json)
    missing = [name for name in TARGET_NAMES if name not in by_name]
    if missing:
        raise RuntimeError(f"missing exact Home state targets: {missing}")
    targets = [by_name[name] for name in TARGET_NAMES]

    view = BinaryView(args.lib)
    try:
        analyses = [analyze_method(view, method, starts, by_addr) for method in targets]
    finally:
        view.close()

    report = {"schema": 1, "target_count": len(analyses), "targets": analyses}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Final 11.6.3 targeted Home state dependency analysis",
        "",
        f"Exact targets: {len(analyses)}",
        "",
    ]
    for target in analyses:
        lines.append(
            f"## `{target['name']}` @ `0x{target['rva']:X}` "
            f"(scanned 0x{target['scanned_size']:X})"
        )
        if target["signature"]:
            lines.append(f"Signature: `{target['signature']}`")
        lines.append(f"Non-framework named calls: {len(target['named_calls'])}")
        for call in target["named_calls"]:
            lines.append(f"- `0x{call['site']:X}` -> `{call['name']}`")
        lines.append(f"State-related call contexts: {len(target['state_contexts'])}")
        for context in target["state_contexts"]:
            lines.append(f"- `0x{context['site']:X}` -> `{context['name']}`")
            for instruction in context["context"]:
                lines.append(f"  - `{instruction}`")
        lines.append("Initial bounded instructions:")
        for instruction in target["initial_disassembly"]:
            lines.append(f"- `{instruction}`")
        lines.append("")

    args.output.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
