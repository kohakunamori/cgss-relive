#!/usr/bin/env python3
"""Bounded clean-room analysis of final LoadTask load_state/next_api literals.

The pass answers one narrow question: whether the request parameter names
``load_state`` and ``next_api`` are referenced by the final 11.6.3 LoadTask
SetParameter path and/or by the actual LoadTask.Parse response body. It emits
only xref sites and tiny disassembly contexts for those two literals.
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

SET_PARAMETER_START = 0x04877A14
PARSE_BODY_START = 0x04852398
PARSE_BODY_END = 0x0486FAB4
TARGET_VALUES = {"load_state", "next_api"}
LOOKAHEAD = 20
CONTEXT_RADIUS = 5


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


def load_target_literals(path: Path) -> dict[int, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise RuntimeError("unexpected stringliteral.json root")
    found: dict[int, str] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        value = item.get("value")
        address = item.get("address")
        if value in TARGET_VALUES and address is not None:
            found[as_int(address)] = str(value)
    if set(found.values()) != TARGET_VALUES:
        raise RuntimeError("final string literal table does not contain both target parameter names")
    return found


def next_function_start(path: Path, address: int) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    starts: set[int] = set()
    for item in data.get("ScriptMethod", []):
        value = as_int(item.get("Address", 0))
        if value > 0:
            starts.add(value)
    for value in data.get("Addresses", []):
        parsed = as_int(value)
        if parsed > 0:
            starts.add(parsed)
    later = sorted(value for value in starts if value > address)
    if not later:
        raise RuntimeError(f"could not bound function after 0x{address:X}")
    return later[0]


def md() -> Cs:
    dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    dis.detail = True
    return dis


def invalidate_destination(state: dict[int, int], ins: Any) -> None:
    if ins.operands and ins.operands[0].type == ARM64_OP_REG:
        state.pop(int(ins.operands[0].reg), None)


def find_hits(view: BinaryView, instructions: list[Any], literals: dict[int, str]) -> list[dict[str, Any]]:
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

    indexes = {ins.address: index for index, ins in enumerate(instructions)}
    ordered = sorted(hits.values(), key=lambda item: (item["site"], item["value"]))
    for hit in ordered:
        index = indexes[hit["site"]]
        lo = max(0, index - CONTEXT_RADIUS)
        hi = min(len(instructions), index + CONTEXT_RADIUS + 1)
        hit["context"] = [
            f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}" for ins in instructions[lo:hi]
        ]
    return ordered


def analyze_region(view: BinaryView, start: int, end: int, literals: dict[int, str]) -> dict[str, Any]:
    instructions = list(md().disasm(view.read(start, end - start), start))
    hits = find_hits(view, instructions, literals)
    counts = {value: 0 for value in sorted(TARGET_VALUES)}
    for hit in hits:
        counts[hit["value"]] += 1
    return {
        "start": start,
        "end": end,
        "size": end - start,
        "hit_counts": counts,
        "hits": hits,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    literals = load_target_literals(args.stringliteral_json)
    set_parameter_end = next_function_start(args.script_json, SET_PARAMETER_START)
    if set_parameter_end - SET_PARAMETER_START > 0x4000:
        raise RuntimeError("unexpectedly large LoadTask.SetParameter bound")

    view = BinaryView(args.lib)
    try:
        report = {
            "schema": 1,
            "targets": sorted(TARGET_VALUES),
            "set_parameter": analyze_region(
                view, SET_PARAMETER_START, set_parameter_end, literals
            ),
            "parse_body": analyze_region(
                view, PARSE_BODY_START, PARSE_BODY_END, literals
            ),
        }
    finally:
        view.close()

    report["request_side_reference_observed"] = any(
        report["set_parameter"]["hit_counts"][value] > 0 for value in TARGET_VALUES
    )
    report["response_parse_reference_observed"] = any(
        report["parse_body"]["hit_counts"][value] > 0 for value in TARGET_VALUES
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "set_parameter_counts": report["set_parameter"]["hit_counts"],
                "parse_body_counts": report["parse_body"]["hit_counts"],
                "request_side_reference_observed": report["request_side_reference_observed"],
                "response_parse_reference_observed": report["response_parse_reference_observed"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
