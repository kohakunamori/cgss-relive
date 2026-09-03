#!/usr/bin/env python3
"""Bounded clean-room analysis of final 11.6.3 Stage.Home entrypoints.

This helper intentionally avoids bulk decompiler output. It counts the exact
Stage.Home method set but emits names/RVAs and bounded instructions only for a
small lifecycle/entry-like selector.
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
MAX_ENTRY_METHODS = 48
MAX_ENTRY_SIZE = 0x200

ENTRY_PATTERNS = (
    re.compile(r"^(?:Awake|Start|OnEnable|Initialize|Init|Setup|Create|Load|Refresh|Ready)$", re.I),
    re.compile(r"(?:StartView|ViewProcess|Initialize|Setup|Create|Load|Refresh|UpdateHome|HomeView)", re.I),
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


def function_end(address: int, starts: list[int]) -> int:
    index = bisect.bisect_right(starts, address)
    next_start = starts[index] if index < len(starts) else address + MAX_ENTRY_SIZE
    return min(next_start, address + MAX_ENTRY_SIZE)


def analyze_entry(
    view: BinaryView,
    method: Method,
    starts: list[int],
    by_addr: dict[int, Method],
) -> dict[str, Any]:
    end = function_end(method.address, starts)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    instructions = list(md.disasm(view.read(method.address, end - method.address), method.address))

    calls: list[dict[str, Any]] = []
    for instruction in instructions:
        if (
            instruction.id == ARM64_INS_BL
            and instruction.operands
            and instruction.operands[0].type == ARM64_OP_IMM
        ):
            target = int(instruction.operands[0].imm)
            target_method = by_addr.get(target)
            calls.append(
                {
                    "site": instruction.address,
                    "target": target,
                    "name": target_method.name if target_method else None,
                }
            )

    named_dependencies = [
        call
        for call in calls
        if call["name"] and any(term in call["name"] for term in DEPENDENCY_TERMS)
    ]
    return {
        "name": method.name,
        "rva": method.address,
        "signature": method.signature,
        "size": end - method.address,
        "calls": calls,
        "named_dependencies": named_dependencies,
        "disassembly": [
            f"0x{instruction.address:X}: {instruction.mnemonic} {instruction.op_str}"
            for instruction in instructions
        ],
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

    selected_index = [
        {"name": method.name, "rva": method.address, "signature": method.signature}
        for method in entry_methods
    ]
    report = {
        "schema": 2,
        "class": "Stage.Home",
        "class_method_count": len(home_methods),
        "selected_method_count": len(entry_methods),
        "selected_method_index": selected_index,
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

    lines += ["", "## Bounded entry candidates", ""]
    for entry in entries:
        lines.append(f"### `{entry['name']}` @ `0x{entry['rva']:X}`")
        if entry["named_dependencies"]:
            lines.append("Named dependency calls:")
            for call in entry["named_dependencies"]:
                lines.append(
                    f"- `0x{call['site']:X}` -> `0x{call['target']:X}` `{call['name']}`"
                )
        else:
            lines.append("Named dependency calls: none in bounded window.")
        lines.append("Bounded instructions:")
        for instruction in entry["disassembly"]:
            lines.append(f"- `{instruction}`")
        lines.append("")

    args.output.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())