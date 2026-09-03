#!/usr/bin/env python3
"""Find bounded ARM64 static-data xrefs to one exact IL2CPP string-literal slot.

The analysis is intentionally local: it only scans one exact function and emits
small contexts around accesses whose effective address or loaded relocation value
matches the requested slot. A known unit_slot literal can be supplied as a
self-check before trusting a new target.
"""
from __future__ import annotations

import argparse
import bisect
import json
import struct
from dataclasses import dataclass
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


DEFAULT_FUNCTION_RVA = 0x4850A94
MAX_FUNCTION_SIZE = 0x22000
WINDOW_INSTRUCTIONS = 20
CONTEXT_RADIUS = 5
MAX_HITS = 32


@dataclass(frozen=True)
class Method:
    address: int
    name: str


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def load_methods(path: Path) -> tuple[dict[int, Method], list[int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    by_addr: dict[int, Method] = {}
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address > 0:
            by_addr.setdefault(address, Method(address, str(item["Name"])))
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
        self.relocations: dict[int, int] = {}
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            for relocation in section.iter_relocations():
                if not relocation.is_RELA():
                    continue
                addend = int(relocation.entry.get("r_addend", 0))
                offset = int(relocation.entry["r_offset"])
                if addend:
                    self.relocations[offset] = addend

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


def disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def function_end(address: int, starts: list[int]) -> int:
    index = bisect.bisect_right(starts, address)
    if index >= len(starts):
        raise RuntimeError("function end unavailable")
    end = starts[index]
    size = end - address
    if size <= 0 or size > MAX_FUNCTION_SIZE:
        raise RuntimeError(f"unexpected function size 0x{size:X}")
    return end


def fmt(instruction: Any) -> str:
    return f"0x{instruction.address:X}: {instruction.mnemonic} {instruction.op_str}"


def invalidate_destination(state: dict[int, int], instruction: Any) -> None:
    if instruction.operands and instruction.operands[0].type == ARM64_OP_REG:
        state.pop(int(instruction.operands[0].reg), None)


def simulate_window(view: BinaryView, instructions: list[Any], start_index: int, target: int):
    state: dict[int, int] = {}
    hits: list[dict[str, Any]] = []
    for instruction in instructions[start_index : min(len(instructions), start_index + WINDOW_INSTRUCTIONS)]:
        ops = instruction.operands
        if instruction.id in {ARM64_INS_B, ARM64_INS_BR, ARM64_INS_RET}:
            break

        if instruction.id in {ARM64_INS_ADR, ARM64_INS_ADRP} and len(ops) >= 2:
            if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
                state[int(ops[0].reg)] = int(ops[1].imm)
                continue

        if instruction.id == ARM64_INS_ADD and len(ops) >= 3:
            if (
                ops[0].type == ARM64_OP_REG
                and ops[1].type == ARM64_OP_REG
                and ops[2].type == ARM64_OP_IMM
            ):
                source = state.get(int(ops[1].reg))
                if source is not None:
                    state[int(ops[0].reg)] = source + int(ops[2].imm)
                    continue
            invalidate_destination(state, instruction)
            continue

        if instruction.id == ARM64_INS_LDR and len(ops) >= 2:
            if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_MEM:
                mem = ops[1].mem
                base = state.get(int(mem.base))
                if base is not None and int(mem.index) == 0:
                    effective = base + int(mem.disp)
                    loaded = view.qword(effective)
                    if effective == target or loaded == target:
                        hits.append(
                            {
                                "site": instruction.address,
                                "effective_address": effective,
                                "loaded_value": loaded,
                            }
                        )
                    if loaded is not None:
                        state[int(ops[0].reg)] = loaded
                        continue
            invalidate_destination(state, instruction)
            continue

        # Keep state through compare/move-like instructions that do not overwrite
        # a known destination; conservatively invalidate explicit destination for
        # other instructions.
        if ops and ops[0].type == ARM64_OP_REG and instruction.mnemonic.lower() not in {
            "cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz"
        } and not instruction.mnemonic.lower().startswith("b."):
            invalidate_destination(state, instruction)
    return hits


def find_hits(view: BinaryView, instructions: list[Any], target: int):
    raw: dict[int, dict[str, Any]] = {}
    for index, instruction in enumerate(instructions):
        if instruction.id not in {ARM64_INS_ADR, ARM64_INS_ADRP}:
            continue
        for hit in simulate_window(view, instructions, index, target):
            raw.setdefault(hit["site"], hit)
    if len(raw) > MAX_HITS:
        raise RuntimeError(f"too many literal xrefs: {len(raw)}")

    by_address = {ins.address: idx for idx, ins in enumerate(instructions)}
    output = []
    for site in sorted(raw):
        index = by_address[site]
        lo = max(0, index - CONTEXT_RADIUS)
        hi = min(len(instructions), index + CONTEXT_RADIUS + 1)
        output.append({**raw[site], "context": [fmt(ins) for ins in instructions[lo:hi]]})
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--target", type=lambda x: int(x, 0), required=True)
    parser.add_argument("--function-rva", type=lambda x: int(x, 0), default=DEFAULT_FUNCTION_RVA)
    parser.add_argument("--expect-site", type=lambda x: int(x, 0))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    by_addr, starts = load_methods(args.script_json)
    method = by_addr.get(args.function_rva)
    if method is None:
        raise RuntimeError(f"no method at 0x{args.function_rva:X}")
    end = function_end(args.function_rva, starts)

    view = BinaryView(args.lib)
    try:
        instructions = list(
            disassembler().disasm(
                view.read(args.function_rva, end - args.function_rva),
                args.function_rva,
            )
        )
        hits = find_hits(view, instructions, args.target)
    finally:
        view.close()

    if args.expect_site is not None and not any(hit["site"] == args.expect_site for hit in hits):
        raise RuntimeError(
            f"self-check failed: target 0x{args.target:X} did not hit expected site 0x{args.expect_site:X}"
        )

    report = {
        "schema": 1,
        "function": {"name": method.name, "rva": method.address, "size": end - method.address},
        "target": args.target,
        "hit_count": len(hits),
        "hits": hits,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"target": args.target, "hit_count": len(hits), "sites": [h["site"] for h in hits]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
