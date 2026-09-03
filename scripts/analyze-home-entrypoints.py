#!/usr/bin/env python3
"""Bounded clean-room analysis of final 11.6.3 Stage.Home entrypoints.

The helper deliberately avoids bulk decompiler output. It:
- counts the exact Stage.Home method set without emitting all method names;
- emits only a tiny lifecycle/entry selector;
- keeps a bounded initial instruction window for each selected entry;
- scans the selected function body for named direct calls, but emits only the
  compact call list and small contexts around data/Home-related calls.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

HOME_PREFIX = "Stage.Home$$"
MAX_ENTRY_METHODS = 32
INITIAL_DISASM_SIZE = 0x200
FULL_SCAN_MAX_SIZE = 0x4000
MAX_NAMED_CALLS_PER_ENTRY = 160
CONTEXT_INSTRUCTIONS = 6

ENTRY_PATTERNS = (
    re.compile(r"^(?:Awake|Start|OnEnable|Initialize|Init|Setup|Create|Load|Refresh|Ready)$", re.I),
    re.compile(r"^(?:StartView|StartViewProcess|ViewProcess|HomeView)(?:$|[_<].*)", re.I),
    re.compile(r"^(?:StartView|StartViewProcess|ViewProcess|HomeView).*", re.I),
)

DEPENDENCY_TERMS = (
    "Card",
    "Chara",
    "Unit",
    "Idol",
    "User",
    "Home",
    "Banner",
    "Mission",
    "Present",
    "Login",
    "Room",
    "Gacha",
    "Live",
    "Story",
    "Event",
    "Currency",
    "Jewel",
    "Gold",
    "Stamina",
    "Manager",
    "Data",
    "ReleaseFlag",
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
    raise TypeError(f"unsupported address value: {value!r}")


def load_methods(path: Path) -> tuple[list[Method], dict[int, Method], list[int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    methods: list[Method] = []
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        methods.append(Method(address, str(item["Name"]), item.get("Signature")))
    by_addr: dict[int, Method] = {}
    for method in methods:
        by_addr.setdefault(method.address, method)
    starts = set(by_addr)
    for value in data.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    return methods, by_addr, sorted(starts)


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


def member_name(method: Method) -> str:
    return method.name.split("$$", 1)[1] if "$$" in method.name else method.name


def is_entry_like(method: Method) -> bool:
    member = member_name(method)
    return any(pattern.search(member) for pattern in ENTRY_PATTERNS)


def function_end(address: int, starts: list[int], max_size: int) -> int:
    index = bisect.bisect_right(starts, address)
    next_start = starts[index] if index < len(starts) else address + max_size
    return min(next_start, address + max_size)


def make_disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def format_instruction(instruction: Any) -> str:
    return f"0x{instruction.address:X}: {instruction.mnemonic} {instruction.op_str}"


def direct_call(instruction: Any, by_addr: dict[int, Method]) -> dict[str, Any] | None:
    if (
        instruction.id != ARM64_INS_BL
        or not instruction.operands
        or instruction.operands[0].type != ARM64_OP_IMM
    ):
        return None
    target = int(instruction.operands[0].imm)
    method = by_addr.get(target)
    return {
        "site": instruction.address,
        "target": target,
        "name": method.name if method else None,
    }


def analyze_entry(
    view: BinaryView,
    method: Method,
    starts: list[int],
    by_addr: dict[int, Method],
) -> dict[str, Any]:
    full_end = function_end(method.address, starts, FULL_SCAN_MAX_SIZE)
    full_instructions = list(
        make_disassembler().disasm(
            view.read(method.address, full_end - method.address),
            method.address,
        )
    )

    named_calls: list[dict[str, Any]] = []
    dependency_contexts: list[dict[str, Any]] = []
    for index, instruction in enumerate(full_instructions):
        call = direct_call(instruction, by_addr)
        if call is None or call["name"] is None:
            continue
        named_calls.append(call)
        if any(term in call["name"] for term in DEPENDENCY_TERMS):
            lo = max(0, index - CONTEXT_INSTRUCTIONS)
            hi = min(len(full_instructions), index + CONTEXT_INSTRUCTIONS + 1)
            dependency_contexts.append(
                {
                    **call,
                    "context": [format_instruction(item) for item in full_instructions[lo:hi]],
                }
            )

    if len(named_calls) > MAX_NAMED_CALLS_PER_ENTRY:
        raise RuntimeError(
            f"{method.name} has {len(named_calls)} named direct calls; "
            "refine analysis before emitting a large call list"
        )

    initial_end = min(full_end, method.address + INITIAL_DISASM_SIZE)
    initial_instructions = list(
        make_disassembler().disasm(
            view.read(method.address, initial_end - method.address),
            method.address,
        )
    )

    return {
        "name": method.name,
        "rva": method.address,
        "signature": method.signature,
        "scanned_size": full_end - method.address,
        "named_calls": named_calls,
        "dependency_contexts": dependency_contexts,
        "initial_disassembly": [format_instruction(item) for item in initial_instructions],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    methods, by_addr, starts = load_methods(args.script_json)
    home_methods = sorted(
        (method for method in methods if method.name.startswith(HOME_PREFIX)),
        key=lambda method: (method.address, method.name),
    )
    entry_methods = [method for method in home_methods if is_entry_like(method)]
    if len(entry_methods) > MAX_ENTRY_METHODS:
        raise RuntimeError(
            f"Stage.Home entry selector too broad ({len(entry_methods)} > {MAX_ENTRY_METHODS}); "
            "refine lifecycle patterns before emitting output"
        )

    view = BinaryView(args.lib)
    try:
        entries = [analyze_entry(view, method, starts, by_addr) for method in entry_methods]
    finally:
        view.close()

    report = {
        "schema": 4,
        "class": "Stage.Home",
        "class_method_count": len(home_methods),
        "selected_method_count": len(entry_methods),
        "selected_method_index": [
            {"name": method.name, "rva": method.address, "signature": method.signature}
            for method in entry_methods
        ],
        "entry_candidates": entries,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Final 11.6.3 Stage.Home bounded entry analysis",
        "",
        f"Exact Stage.Home method count (names not bulk-emitted): {len(home_methods)}",
        f"Selected lifecycle/entry methods: {len(entries)}",
        "",
        "## Selected method index",
        "",
    ]
    for method in entry_methods:
        lines.append(f"- `0x{method.address:X}` `{method.name}`")

    lines += ["", "## Entry dependency summary", ""]
    for entry in entries:
        lines.append(
            f"### `{entry['name']}` @ `0x{entry['rva']:X}` "
            f"(scanned 0x{entry['scanned_size']:X} bytes)"
        )
        lines.append(f"Named direct calls: {len(entry['named_calls'])}")
        for call in entry["named_calls"]:
            lines.append(
                f"- `0x{call['site']:X}` -> `0x{call['target']:X}` `{call['name']}`"
            )
        lines.append("Dependency call contexts:")
        if not entry["dependency_contexts"]:
            lines.append("- none")
        for context in entry["dependency_contexts"]:
            lines.append(
                f"- `0x{context['site']:X}` -> `{context['name']}`"
            )
            for instruction in context["context"]:
                lines.append(f"  - `{instruction}`")
        lines.append("Initial bounded instructions:")
        for instruction in entry["initial_disassembly"]:
            lines.append(f"- `{instruction}`")
        lines.append("")

    args.output.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())