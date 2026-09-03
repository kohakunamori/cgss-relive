#!/usr/bin/env python3
"""Bounded final-client analysis of LoadTask unit cosmetic helper parsers.

The primary user_unit_list parser always invokes ParseUnitCostume and
ParseUnitDressCustomize. This pass inspects only those two exact final 11.6.3
functions and emits string-literal accesses plus named direct-call contexts so
missing-field guard semantics can be determined without exporting large
decompiler output.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import (
    ARM64_INS_ADD,
    ARM64_INS_ADR,
    ARM64_INS_ADRP,
    ARM64_INS_B,
    ARM64_INS_BL,
    ARM64_INS_BR,
    ARM64_INS_LDR,
    ARM64_INS_RET,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
)
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

FUNCTIONS = {
    "ParseUnitCostume": 0x04878524,
    "ParseUnitDressCustomize": 0x04878820,
}
LOOKAHEAD = 20
CONTEXT_RADIUS = 6
MAX_FUNCTION_SIZE = 0x2000
MAX_LITERAL_HITS = 80
MAX_NAMED_CALLS = 160
_CONTEXT_CALL_SUFFIXES = (
    "JsonData$$get_Keys",
    "JsonData$$get_Item",
    "String$$Format",
    "JsonData$$op_Explicit",
)


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
        self.relocations: dict[int, int] = {}
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            for relocation in section.iter_relocations():
                if relocation.is_RELA():
                    addend = int(relocation.entry.get("r_addend", 0))
                    if addend:
                        self.relocations[int(relocation.entry["r_offset"])] = addend

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

    def qword(self, address: int) -> int | None:
        if address in self.relocations:
            return self.relocations[address]
        blob = self.read(address, 8)
        if len(blob) != 8:
            return None
        value = struct.unpack("<Q", blob)[0]
        return value or None


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def load_script(path: Path) -> tuple[dict[int, str], list[int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    methods: dict[int, str] = {}
    starts: set[int] = set()
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address > 0:
            starts.add(address)
            methods.setdefault(address, str(item["Name"]))
    for item in data.get("Addresses", []):
        address = as_int(item)
        if address > 0:
            starts.add(address)
    return methods, sorted(starts)


def load_literals(path: Path) -> dict[int, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise RuntimeError("unexpected stringliteral.json root")
    result: dict[int, str] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        address = item.get("address")
        if isinstance(value, str) and address is not None:
            result[as_int(address)] = value
    return result


def next_start(starts: list[int], address: int) -> int:
    for value in starts:
        if value > address:
            if value - address > MAX_FUNCTION_SIZE:
                raise RuntimeError(f"unexpected function bound after 0x{address:X}")
            return value
    raise RuntimeError(f"no function bound after 0x{address:X}")


def md() -> Cs:
    dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    dis.detail = True
    return dis


def invalidate_destination(state: dict[int, int], ins: Any) -> None:
    if ins.operands and ins.operands[0].type == ARM64_OP_REG:
        state.pop(int(ins.operands[0].reg), None)


def context(instructions: list[Any], index: int) -> list[str]:
    lo = max(0, index - CONTEXT_RADIUS)
    hi = min(len(instructions), index + CONTEXT_RADIUS + 1)
    return [
        f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}" for ins in instructions[lo:hi]
    ]


def literal_hits(view: BinaryView, instructions: list[Any], literals: dict[int, str]):
    addresses = set(literals)
    raw: dict[tuple[int, int], dict[str, Any]] = {}
    for start_index, first in enumerate(instructions):
        if first.id not in {ARM64_INS_ADR, ARM64_INS_ADRP}:
            continue
        state: dict[int, int] = {}
        for ins in instructions[start_index : min(len(instructions), start_index + LOOKAHEAD)]:
            ops = ins.operands
            if ins.id in {ARM64_INS_B, ARM64_INS_BR, ARM64_INS_RET}:
                break
            if ins.id in {ARM64_INS_ADR, ARM64_INS_ADRP} and len(ops) >= 2:
                if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
                    state[int(ops[0].reg)] = int(ops[1].imm)
                    continue
            if ins.id == ARM64_INS_ADD and len(ops) >= 3:
                if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
                    base = state.get(int(ops[1].reg))
                    if base is not None:
                        state[int(ops[0].reg)] = base + int(ops[2].imm)
                        continue
                invalidate_destination(state, ins)
                continue
            if ins.id == ARM64_INS_LDR and len(ops) >= 2:
                if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_MEM:
                    mem = ops[1].mem
                    base = state.get(int(mem.base))
                    if base is not None and int(mem.index) == 0:
                        loaded = view.qword(base + int(mem.disp))
                        if loaded in addresses:
                            raw.setdefault(
                                (ins.address, loaded),
                                {"site": ins.address, "value": literals[loaded]},
                            )
                        if loaded is not None:
                            state[int(ops[0].reg)] = loaded
                            continue
                invalidate_destination(state, ins)
                continue
            if ops and ops[0].type == ARM64_OP_REG and ins.mnemonic.lower() not in {
                "cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz"
            } and not ins.mnemonic.lower().startswith("b."):
                invalidate_destination(state, ins)

    if len(raw) > MAX_LITERAL_HITS:
        raise RuntimeError(f"unit cosmetic helper exposed too many literals: {len(raw)}")
    indexes = {ins.address: index for index, ins in enumerate(instructions)}
    ordered = sorted(raw.values(), key=lambda item: item["site"])
    for hit in ordered:
        hit["context"] = context(instructions, indexes[hit["site"]])
    return ordered


def analyze_function(
    view: BinaryView,
    start: int,
    end: int,
    literals: dict[int, str],
    methods: dict[int, str],
) -> dict[str, Any]:
    instructions = list(md().disasm(view.read(start, end - start), start))
    hits = literal_hits(view, instructions, literals)
    calls: list[dict[str, Any]] = []
    for index, ins in enumerate(instructions):
        if ins.id == ARM64_INS_BL and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            target = int(ins.operands[0].imm)
            name = methods.get(target)
            if name is not None:
                item: dict[str, Any] = {"site": ins.address, "target": target, "name": name}
                if name.endswith(_CONTEXT_CALL_SUFFIXES):
                    item["context"] = context(instructions, index)
                calls.append(item)
    if len(calls) > MAX_NAMED_CALLS:
        raise RuntimeError("unit cosmetic helper exposed too many named calls")
    return {
        "start": start,
        "end": end,
        "size": end - start,
        "literal_hit_count": len(hits),
        "literal_hits": hits,
        "named_call_count": len(calls),
        "named_calls": calls,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    methods, starts = load_script(args.script_json)
    literals = load_literals(args.stringliteral_json)
    view = BinaryView(args.lib)
    try:
        functions = {
            label: analyze_function(
                view,
                start,
                next_start(starts, start),
                literals,
                methods,
            )
            for label, start in FUNCTIONS.items()
        }
    finally:
        view.close()

    report = {"schema": 2, "functions": functions}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                label: [hit["value"] for hit in record["literal_hits"]]
                for label, record in functions.items()
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
