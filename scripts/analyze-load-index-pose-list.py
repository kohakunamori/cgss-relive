#!/usr/bin/env python3
"""Resolve only ``pose_list`` xrefs inside the final LoadTask.Parse body.

An older bounded report associated pose_list with the secondary user_unit_list
path. This exact-specimen pass tests that narrow claim across the whole actual
LoadTask.Parse body and emits only matching xref sites plus tiny contexts.
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
    ARM64_INS_BR,
    ARM64_INS_LDR,
    ARM64_INS_RET,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
)
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

PARSE_START = 0x04852398
PARSE_END = 0x0486FAB4
TARGET = "pose_list"
LOOKAHEAD = 20
CONTEXT_RADIUS = 6
MAX_HITS = 32


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.segments: list[tuple[int, int, int, int]] = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
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
                rel = address - vaddr
                if rel >= filesz:
                    return b""
                self.stream.seek(offset + rel)
                return self.stream.read(min(size, filesz - rel))
        return b""

    def qword(self, address: int) -> int | None:
        if address in self.relocations:
            return self.relocations[address]
        blob = self.read(address, 8)
        return struct.unpack("<Q", blob)[0] if len(blob) == 8 else None


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def target_addresses(path: Path) -> list[int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise RuntimeError("unexpected stringliteral.json root")
    return sorted(
        {
            as_int(item["address"])
            for item in data
            if isinstance(item, dict) and item.get("value") == TARGET and item.get("address") is not None
        }
    )


def md() -> Cs:
    dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    dis.detail = True
    return dis


def invalidate_destination(state: dict[int, int], ins: Any) -> None:
    if ins.operands and ins.operands[0].type == ARM64_OP_REG:
        state.pop(int(ins.operands[0].reg), None)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    targets = set(target_addresses(args.stringliteral_json))
    view = BinaryView(args.lib)
    dis = md()
    try:
        instructions = list(dis.disasm(view.read(PARSE_START, PARSE_END - PARSE_START), PARSE_START))
        raw_hits: set[int] = set()
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
                            if loaded in targets:
                                raw_hits.add(ins.address)
                            if loaded is not None:
                                state[int(ops[0].reg)] = loaded
                                continue
                    invalidate_destination(state, ins)
                    continue
                if ops and ops[0].type == ARM64_OP_REG and ins.mnemonic.lower() not in {
                    "cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz"
                } and not ins.mnemonic.lower().startswith("b."):
                    invalidate_destination(state, ins)
    finally:
        view.close()

    if len(raw_hits) > MAX_HITS:
        raise RuntimeError("pose_list produced unexpectedly many parse xrefs")
    indexes = {ins.address: index for index, ins in enumerate(instructions)}
    hits = []
    for address in sorted(raw_hits):
        index = indexes[address]
        lo = max(0, index - CONTEXT_RADIUS)
        hi = min(len(instructions), index + CONTEXT_RADIUS + 1)
        hits.append(
            {
                "site": address,
                "context": [
                    f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}" for ins in instructions[lo:hi]
                ],
            }
        )

    report = {
        "schema": 1,
        "target": TARGET,
        "string_literal_present": bool(targets),
        "parse_body": {"start": PARSE_START, "end": PARSE_END},
        "xref_count": len(hits),
        "xrefs": hits,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"string_literal_present": bool(targets), "xref_count": len(hits)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
