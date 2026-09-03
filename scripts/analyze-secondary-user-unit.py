#!/usr/bin/env python3
"""Bounded final-client analysis of the secondary user_unit_list parser entry.

The primary unit parser is already closed. This pass inspects only the small
0x485DE00..0x485E900 region around the independently observed secondary entry at
0x485DE38. It emits resolved string-literal accesses plus named direct calls and
tiny contexts, sufficient to distinguish hard get_Item reads from guarded fields
without exporting the full LoadTask.Parse body.
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

START_RVA = 0x0485DE00
END_RVA = 0x0485E900
LOOKAHEAD = 20
CONTEXT_RADIUS = 6
MAX_LITERAL_HITS = 80
MAX_NAMED_CALLS = 160


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


def load_methods(path: Path) -> dict[int, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    result: dict[int, str] = {}
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address > 0:
            result.setdefault(address, str(item["Name"]))
    return result


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


def md() -> Cs:
    dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    dis.detail = True
    return dis


def invalidate_destination(state: dict[int, int], ins: Any) -> None:
    if ins.operands and ins.operands[0].type == ARM64_OP_REG:
        state.pop(int(ins.operands[0].reg), None)


def find_literal_hits(view: BinaryView, instructions: list[Any], literals: dict[int, str]):
    addresses = set(literals)
    hits: dict[tuple[int, int], dict[str, Any]] = {}
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
                        effective = base + int(mem.disp)
                        loaded = view.qword(effective)
                        if loaded in addresses:
                            hits.setdefault(
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

    if len(hits) > MAX_LITERAL_HITS:
        raise RuntimeError(f"secondary unit region exposed too many literals: {len(hits)}")
    indexes = {ins.address: index for index, ins in enumerate(instructions)}
    ordered = sorted(hits.values(), key=lambda item: item["site"])
    for hit in ordered:
        index = indexes[hit["site"]]
        lo = max(0, index - CONTEXT_RADIUS)
        hi = min(len(instructions), index + CONTEXT_RADIUS + 1)
        hit["context"] = [
            f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}" for ins in instructions[lo:hi]
        ]
    return ordered


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    methods = load_methods(args.script_json)
    literals = load_literals(args.stringliteral_json)
    view = BinaryView(args.lib)
    try:
        instructions = list(md().disasm(view.read(START_RVA, END_RVA - START_RVA), START_RVA))
        literal_hits = find_literal_hits(view, instructions, literals)
    finally:
        view.close()

    named_calls: list[dict[str, Any]] = []
    for ins in instructions:
        if ins.id != ARM64_INS_BL or not ins.operands or ins.operands[0].type != ARM64_OP_IMM:
            continue
        target = int(ins.operands[0].imm)
        name = methods.get(target)
        if name is not None:
            named_calls.append({"site": ins.address, "target": target, "name": name})
    if len(named_calls) > MAX_NAMED_CALLS:
        raise RuntimeError(f"secondary unit region exposed too many named calls: {len(named_calls)}")

    values = [hit["value"] for hit in literal_hits]
    if "user_unit_list" not in values:
        raise RuntimeError("secondary region did not resolve user_unit_list")

    report = {
        "schema": 1,
        "region": {"start": START_RVA, "end": END_RVA, "size": END_RVA - START_RVA},
        "literal_hit_count": len(literal_hits),
        "literal_hits": literal_hits,
        "named_call_count": len(named_calls),
        "named_calls": named_calls,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"literal_values": values}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
