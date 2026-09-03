#!/usr/bin/env python3
"""Target data-facing methods reached during final Home startup.

The helper emits only exact selected method/RVA metadata, bounded initial ARM64,
direct named calls excluding framework noise, and compact contexts around
state-related calls. For ``SetBannerAssetList`` it additionally follows only the
conditional branches immediately preceding those state calls and emits tiny
landing windows, allowing null/default guards to be distinguished from shared
exception paths without exporting the full CFG.
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

# CardDownloadList is overloaded. The startup call from PreDownloadList resolves
# to the worker at 0x3EC0D70; the later 0x3ED57F4 method is only a tiny wrapper.
TARGET_SPECS = (
    ("Stage.Home$$CardDownloadList", 0x3EC0D70),
    ("Stage.WorkDataUtil$$GetFavoriteUnitData", None),
    ("Stage.PresentAllPopup$$GetAllPresentPopupItemList", None),
    ("Stage.HomeCustomUtil$$SetBannerAssetList", None),
    ("Stage.TempData.GenericSpPageTempData$$ExistsAnyLoginBonus", None),
    ("Stage.DirectAndLimitedLoginBonusPopup$$GetDirectAndLimitedLoginBonusPopupAssetName", None),
)
INITIAL_WINDOW = 0x240
FULL_SCAN_MAX_SIZE = 0x5000
CONTEXT_INSTRUCTIONS = 5
GUARD_LOOKBACK = 12
LANDING_INSTRUCTIONS = 12
MAX_NAMED_CALLS = 160
MAX_GUARD_LANDINGS = 48
KNOWN_SHARED_EXCEPTION_HELPER = 0x32EE7D8
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
CONDITIONAL_BRANCH_MNEMONICS = {
    "cbz",
    "cbnz",
    "tbz",
    "tbnz",
    "b.eq",
    "b.ne",
    "b.lt",
    "b.le",
    "b.gt",
    "b.ge",
    "b.lo",
    "b.ls",
    "b.hi",
    "b.hs",
    "b.mi",
    "b.pl",
    "b.vs",
    "b.vc",
}


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


def load_methods(path: Path) -> tuple[dict[int, Method], dict[str, list[Method]], list[int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    by_addr: dict[int, Method] = {}
    by_name: dict[str, list[Method]] = {}
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        method = Method(address, str(item["Name"]), item.get("Signature"))
        by_addr.setdefault(address, method)
        by_name.setdefault(method.name, []).append(method)
    starts = set(by_addr)
    for value in data.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    for methods in by_name.values():
        methods.sort(key=lambda method: method.address)
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


def conditional_branch_target(instruction: Any) -> int | None:
    if instruction.mnemonic.lower() not in CONDITIONAL_BRANCH_MNEMONICS:
        return None
    for operand in reversed(instruction.operands):
        if operand.type == ARM64_OP_IMM:
            return int(operand.imm)
    return None


def resolve_target(
    name: str,
    requested_rva: int | None,
    by_addr: dict[int, Method],
    by_name: dict[str, list[Method]],
) -> Method:
    if requested_rva is not None:
        method = by_addr.get(requested_rva)
        if method is None:
            raise RuntimeError(f"missing target RVA 0x{requested_rva:X} for {name}")
        if method.name != name:
            raise RuntimeError(
                f"target RVA 0x{requested_rva:X} resolved to {method.name}, expected {name}"
            )
        return method
    candidates = by_name.get(name, [])
    if len(candidates) != 1:
        raise RuntimeError(
            f"expected one method named {name}, found {len(candidates)}; pin an RVA"
        )
    return candidates[0]


def guard_landings_for_state_calls(
    view: BinaryView,
    method: Method,
    instructions: list[Any],
    state_call_indices: list[int],
    function_start: int,
    function_end_address: int,
) -> list[dict[str, Any]]:
    unique: dict[tuple[int, int], dict[str, Any]] = {}
    md = disassembler()
    for call_index in state_call_indices:
        for branch in instructions[max(0, call_index - GUARD_LOOKBACK) : call_index]:
            target = conditional_branch_target(branch)
            if target is None or not (function_start <= target < function_end_address):
                continue
            key = (branch.address, target)
            if key in unique:
                continue
            landing = list(md.disasm(view.read(target, LANDING_INSTRUCTIONS * 4), target))
            calls_exception_helper = False
            for instruction in landing:
                if (
                    instruction.id == ARM64_INS_BL
                    and instruction.operands
                    and instruction.operands[0].type == ARM64_OP_IMM
                    and int(instruction.operands[0].imm) == KNOWN_SHARED_EXCEPTION_HELPER
                ):
                    calls_exception_helper = True
                    break
            unique[key] = {
                "branch_site": branch.address,
                "branch": format_instruction(branch),
                "target": target,
                "forward_distance": target - branch.address,
                "calls_known_exception_helper": calls_exception_helper,
                "landing": [format_instruction(item) for item in landing],
            }
    if len(unique) > MAX_GUARD_LANDINGS:
        raise RuntimeError(
            f"{method.name} produced {len(unique)} state guard landings; refine lookback"
        )
    return sorted(unique.values(), key=lambda item: (item["branch_site"], item["target"]))


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
    state_call_indices: list[int] = []
    for index, instruction in enumerate(instructions):
        call = call_from_instruction(instruction, by_addr)
        if call is None:
            continue
        if call["name"].startswith(FRAMEWORK_PREFIXES):
            continue
        named_calls.append(call)
        if relevant_call_name(call["name"]):
            state_call_indices.append(index)
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

    guard_landings: list[dict[str, Any]] = []
    if method.name == "Stage.HomeCustomUtil$$SetBannerAssetList":
        guard_landings = guard_landings_for_state_calls(
            view,
            method,
            instructions,
            state_call_indices,
            method.address,
            end,
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
        "guard_landings": guard_landings,
        "initial_disassembly": [format_instruction(item) for item in initial],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    by_addr, by_name, starts = load_methods(args.script_json)
    targets = [resolve_target(name, rva, by_addr, by_name) for name, rva in TARGET_SPECS]

    view = BinaryView(args.lib)
    try:
        analyses = [analyze_method(view, method, starts, by_addr) for method in targets]
    finally:
        view.close()

    report = {"schema": 2, "target_count": len(analyses), "targets": analyses}
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
        if target["guard_landings"]:
            lines.append(f"State guard landings: {len(target['guard_landings'])}")
            for guard in target["guard_landings"]:
                lines.append(
                    f"- branch `0x{guard['branch_site']:X}` -> `0x{guard['target']:X}`; "
                    f"known_exception_helper={str(guard['calls_known_exception_helper']).lower()}"
                )
                lines.append(f"  - `{guard['branch']}`")
                for instruction in guard["landing"]:
                    lines.append(f"  - `{instruction}`")
        lines.append("Initial bounded instructions:")
        for instruction in target["initial_disassembly"]:
            lines.append(f"- `{instruction}`")
        lines.append("")

    args.output.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
