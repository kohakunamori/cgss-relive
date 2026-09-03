#!/usr/bin/env python3
"""Bounded clean-room analysis of final 11.6.3 BaseTask.setupTutorial.

The uploaded final-client report identifies RVA 0x476E1E4 as the tutorial gate
called from LoadTask.Parse with the decoded tutorial_flag. This helper emits only
that exact method's bounded ARM64 instructions, signature/name from script.json,
direct named calls, and immediate compare/conditional-branch sites. It does not
export strings, a global method list, or neighboring function bodies.
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

TARGET_RVA = 0x476E1E4
MAX_FUNCTION_SIZE = 0x800
MAX_INSTRUCTIONS = MAX_FUNCTION_SIZE // 4


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


def load_methods(path: Path) -> tuple[dict[int, Method], list[int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    by_addr: dict[int, Method] = {}
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        by_addr.setdefault(address, Method(address, str(item["Name"]), item.get("Signature")))
    starts = set(by_addr)
    for value in data.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    return by_addr, sorted(starts)


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


def function_end(address: int, starts: list[int]) -> int:
    index = bisect.bisect_right(starts, address)
    if index >= len(starts):
        raise RuntimeError("could not determine setupTutorial function end")
    next_start = starts[index]
    size = next_start - address
    if size <= 0 or size > MAX_FUNCTION_SIZE:
        raise RuntimeError(
            f"setupTutorial bounded size is 0x{size:X}; expected 1..0x{MAX_FUNCTION_SIZE:X}"
        )
    return next_start


def format_instruction(instruction: Any) -> str:
    return f"0x{instruction.address:X}: {instruction.mnemonic} {instruction.op_str}"


def direct_named_call(instruction: Any, by_addr: dict[int, Method]) -> dict[str, Any] | None:
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
        "name": method.name if method is not None else None,
    }


def immediate_operands(instruction: Any) -> list[int]:
    values: list[int] = []
    for operand in instruction.operands:
        if operand.type == ARM64_OP_IMM:
            values.append(int(operand.imm))
    return values


def is_compare_or_conditional(instruction: Any) -> bool:
    mnemonic = instruction.mnemonic.lower()
    return (
        mnemonic in {"cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz"}
        or mnemonic.startswith("b.")
        or mnemonic in {"csel", "csinc", "csinv", "csneg", "cset", "csetm"}
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    by_addr, starts = load_methods(args.script_json)
    method = by_addr.get(TARGET_RVA)
    if method is None:
        raise RuntimeError(f"script.json has no method at setupTutorial RVA 0x{TARGET_RVA:X}")

    end = function_end(TARGET_RVA, starts)
    view = BinaryView(args.lib)
    try:
        instructions = list(disassembler().disasm(view.read(TARGET_RVA, end - TARGET_RVA), TARGET_RVA))
    finally:
        view.close()
    if not instructions or len(instructions) > MAX_INSTRUCTIONS:
        raise RuntimeError("unexpected setupTutorial instruction count")

    calls = [call for insn in instructions if (call := direct_named_call(insn, by_addr)) is not None]
    control = []
    for instruction in instructions:
        if not is_compare_or_conditional(instruction):
            continue
        control.append(
            {
                "address": instruction.address,
                "instruction": format_instruction(instruction),
                "immediates": immediate_operands(instruction),
                "mentions_1000": 1000 in immediate_operands(instruction),
            }
        )

    report = {
        "schema": 1,
        "target": {
            "name": method.name,
            "rva": method.address,
            "signature": method.signature,
            "size": end - TARGET_RVA,
        },
        "mentions_immediate_1000": any(item["mentions_1000"] for item in control),
        "control_sites": control,
        "direct_calls": calls,
        "disassembly": [format_instruction(instruction) for instruction in instructions],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Final 11.6.3 tutorial-flag gate",
        "",
        f"Method: `{method.name}`",
        f"RVA: `0x{method.address:X}`",
        f"Size: `0x{end - TARGET_RVA:X}`",
        f"Signature: `{method.signature}`",
        f"Immediate 1000 observed: `{report['mentions_immediate_1000']}`",
        "",
        "## Compare / conditional sites",
        "",
    ]
    for item in control:
        marker = " **[1000]**" if item["mentions_1000"] else ""
        lines.append(f"- `{item['instruction']}`{marker}")
    lines += ["", "## Direct named calls", ""]
    for call in calls:
        lines.append(
            f"- `0x{call['site']:X}` -> `0x{call['target']:X}` `{call['name'] or 'unnamed'}`"
        )
    lines += ["", "## Bounded instructions", ""]
    for instruction in report["disassembly"]:
        lines.append(f"- `{instruction}`")
    args.output.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
