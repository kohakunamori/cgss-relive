#!/usr/bin/env python3
"""Trace only immediate Stage.Home helpers reached by Home startup.

Clean-room boundary:
- entry roots are exact ``Stage.Home.Start`` and ``StartViewProcess``;
- only one-hop ``Stage.Home`` helpers with startup-like names are selected;
- helper bodies are scanned to find direct named calls, but the report emits only
  dependency-related calls plus small instruction contexts;
- no complete helper disassembly, global method list, strings, or binary data is
  emitted.
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

ROOT_NAMES = (
    "Stage.Home$$Start",
    "Stage.Home$$StartViewProcess",
)
HELPER_PREFIXES = (
    "Pre",
    "Create",
    "IsOpen",
    "SetTex",
)
MAX_ROOT_SIZE = 0x4000
MAX_HELPER_SIZE = 0x3000
MAX_HELPERS = 40
MAX_DEPENDENCY_CALLS_PER_HELPER = 64
CONTEXT_INSTRUCTIONS = 4

DEPENDENCY_TERMS = (
    "User",
    "Data",
    "Manager",
    "Card",
    "Unit",
    "Chara",
    "Idol",
    "Present",
    "Mission",
    "Login",
    "Banner",
    "Birthday",
    "Friend",
    "Campaign",
    "Agreement",
    "Policy",
    "Gacha",
    "Live",
    "Story",
    "Event",
    "Jewel",
    "Gold",
    "Stamina",
    "Master",
    "Network",
    "Task",
    "ReleaseFlag",
    "Savedata",
    "TempData",
    "Certification",
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


def load_methods(path: Path) -> tuple[list[Method], dict[int, Method], dict[str, Method], list[int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    methods: list[Method] = []
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        methods.append(Method(address, str(item["Name"]), item.get("Signature")))

    by_addr: dict[int, Method] = {}
    by_name: dict[str, Method] = {}
    for method in methods:
        by_addr.setdefault(method.address, method)
        by_name.setdefault(method.name, method)

    starts = set(by_addr)
    for value in data.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    return methods, by_addr, by_name, sorted(starts)


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


def make_disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def function_end(address: int, starts: list[int], max_size: int) -> int:
    index = bisect.bisect_right(starts, address)
    next_start = starts[index] if index < len(starts) else address + max_size
    return min(next_start, address + max_size)


def instructions_for(view: BinaryView, method: Method, starts: list[int], max_size: int) -> list[Any]:
    end = function_end(method.address, starts, max_size)
    return list(make_disassembler().disasm(view.read(method.address, end - method.address), method.address))


def direct_named_call(instruction: Any, by_addr: dict[int, Method]) -> dict[str, Any] | None:
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


def member_name(name: str) -> str:
    return name.split("$$", 1)[1] if "$$" in name else name


def is_immediate_helper(name: str) -> bool:
    if not name.startswith("Stage.Home$$"):
        return False
    member = member_name(name)
    return any(member.startswith(prefix) for prefix in HELPER_PREFIXES)


def format_instruction(instruction: Any) -> str:
    return f"0x{instruction.address:X}: {instruction.mnemonic} {instruction.op_str}"


def collect_helpers(
    view: BinaryView,
    roots: list[Method],
    starts: list[int],
    by_addr: dict[int, Method],
) -> list[Method]:
    selected: dict[int, Method] = {}
    for root in roots:
        for instruction in instructions_for(view, root, starts, MAX_ROOT_SIZE):
            call = direct_named_call(instruction, by_addr)
            if call is None or not is_immediate_helper(call["name"]):
                continue
            method = by_addr[call["target"]]
            selected.setdefault(method.address, method)
    helpers = sorted(selected.values(), key=lambda method: (method.address, method.name))
    if len(helpers) > MAX_HELPERS:
        raise RuntimeError(
            f"immediate Home helper selector too broad ({len(helpers)} > {MAX_HELPERS}); refine prefixes"
        )
    return helpers


def analyze_helper(
    view: BinaryView,
    method: Method,
    starts: list[int],
    by_addr: dict[int, Method],
) -> dict[str, Any]:
    instructions = instructions_for(view, method, starts, MAX_HELPER_SIZE)
    dependency_calls: list[dict[str, Any]] = []
    total_named_calls = 0
    for index, instruction in enumerate(instructions):
        call = direct_named_call(instruction, by_addr)
        if call is None:
            continue
        total_named_calls += 1
        if not any(term in call["name"] for term in DEPENDENCY_TERMS):
            continue
        lo = max(0, index - CONTEXT_INSTRUCTIONS)
        hi = min(len(instructions), index + CONTEXT_INSTRUCTIONS + 1)
        dependency_calls.append(
            {
                **call,
                "context": [format_instruction(item) for item in instructions[lo:hi]],
            }
        )

    if len(dependency_calls) > MAX_DEPENDENCY_CALLS_PER_HELPER:
        raise RuntimeError(
            f"{method.name} has too many dependency calls "
            f"({len(dependency_calls)} > {MAX_DEPENDENCY_CALLS_PER_HELPER})"
        )

    end = function_end(method.address, starts, MAX_HELPER_SIZE)
    return {
        "name": method.name,
        "rva": method.address,
        "signature": method.signature,
        "scanned_size": end - method.address,
        "total_named_calls": total_named_calls,
        "dependency_calls": dependency_calls,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    _, by_addr, by_name, starts = load_methods(args.script_json)
    missing = [name for name in ROOT_NAMES if name not in by_name]
    if missing:
        raise RuntimeError(f"missing exact Home roots: {missing}")
    roots = [by_name[name] for name in ROOT_NAMES]

    view = BinaryView(args.lib)
    try:
        helpers = collect_helpers(view, roots, starts, by_addr)
        analyses = [analyze_helper(view, method, starts, by_addr) for method in helpers]
    finally:
        view.close()

    report = {
        "schema": 1,
        "roots": [{"name": method.name, "rva": method.address} for method in roots],
        "helper_count": len(analyses),
        "helpers": analyses,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Final 11.6.3 immediate Home helper dependency analysis",
        "",
        "Roots:",
    ]
    for method in roots:
        lines.append(f"- `0x{method.address:X}` `{method.name}`")
    lines += ["", f"Immediate startup-like Home helpers: {len(analyses)}", ""]

    for helper in analyses:
        lines.append(
            f"## `{helper['name']}` @ `0x{helper['rva']:X}` "
            f"(scanned 0x{helper['scanned_size']:X})"
        )
        lines.append(f"Total named direct calls: {helper['total_named_calls']}")
        lines.append(f"Dependency-related calls: {len(helper['dependency_calls'])}")
        if not helper["dependency_calls"]:
            lines.append("- none")
        for call in helper["dependency_calls"]:
            lines.append(
                f"- `0x{call['site']:X}` -> `0x{call['target']:X}` `{call['name']}`"
            )
            for instruction in call["context"]:
                lines.append(f"  - `{instruction}`")
        lines.append("")

    args.output.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
