#!/usr/bin/env python3
"""Bounded native semantics pass for final-11.6.3 MemberUnitEdit.

This pass consumes the exact final ARM64 specimen plus Il2CppDumper metadata and
exports only sanitized evidence for three managed methods:

- MemberUnitEditTask.SetParameter
- MemberUnitEditTask.Parse
- LiveSelectParty.<StartUnitEditTask>d__296.MoveNext (when present)

For each method it records referenced managed string literals and selected direct
managed calls with small instruction contexts. It never emits raw bytes or bulk
disassembly.
"""
from __future__ import annotations

import argparse
import bisect
import json
import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_ADRP, ARM64_INS_BL, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile

TARGET_SUFFIXES = (
    "MemberUnitEditTask$$SetParameter",
    "MemberUnitEditTask$$Parse",
    "LiveSelectParty.<StartUnitEditTask>d__296$$MoveNext",
)
MAX_FUNCTION_SIZE = 0x7000
MAX_LITERAL_LENGTH = 160
LITERAL_WINDOW = 10
CONTEXT_RADIUS = 6
MAX_SELECTED_CALLS = 180

INTEREST_TERMS = (
    "BaseTask$$Parse",
    "MemberUnitEditTask",
    "MemberUnitEditTaskParam",
    "WorkUnitData",
    "UnitData",
    "GetSerial",
    "Dress",
    "JsonData",
    "NetworkManager",
    "Dictionary",
    "List",
)


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: str | None


class BinaryView:
    def __init__(self, path: Path) -> None:
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.loads: list[tuple[int, int, int, int]] = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            self.loads.append(
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
        for vaddr, memsz, offset, filesz in self.loads:
            if vaddr <= address < vaddr + memsz:
                rel = address - vaddr
                if rel >= filesz:
                    return b""
                self.stream.seek(offset + rel)
                return self.stream.read(min(size, filesz - rel))
        return b""

    def relocation_slots(self, literal_addresses: set[int]) -> dict[int, int]:
        result: dict[int, int] = {}
        for section in self.elf.iter_sections():
            if not hasattr(section, "iter_relocations"):
                continue
            for relocation in section.iter_relocations():
                if not relocation.is_RELA():
                    continue
                addend = int(relocation["r_addend"])
                if addend in literal_addresses:
                    result[int(relocation["r_offset"])] = addend
        return result


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def load_methods(path: Path) -> tuple[dict[int, list[Method]], list[int], dict[str, Method]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    by_rva: dict[int, list[Method]] = defaultdict(list)
    starts: set[int] = set()
    targets: dict[str, Method] = {}
    for row in raw.get("ScriptMethod", []):
        address = as_int(row.get("Address", 0))
        name = str(row.get("Name") or "")
        if address <= 0 or not name:
            continue
        method = Method(address, name, row.get("Signature"))
        by_rva[address].append(method)
        starts.add(address)
        for suffix in TARGET_SUFFIXES:
            if name.endswith(suffix):
                if suffix in targets and targets[suffix].name != name:
                    raise RuntimeError(f"ambiguous UnitEdit target suffix {suffix!r}")
                targets[suffix] = method
    for value in raw.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    for suffix in TARGET_SUFFIXES[:2]:
        if suffix not in targets:
            raise RuntimeError(f"required UnitEdit method not found: *{suffix}")
    return dict(by_rva), sorted(starts), targets


def function_end(starts: list[int], start: int) -> int:
    index = bisect.bisect_right(starts, start)
    if index >= len(starts):
        return start + MAX_FUNCTION_SIZE
    return min(starts[index], start + MAX_FUNCTION_SIZE)


def load_string_literals(path: Path) -> tuple[dict[int, set[str]], set[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = raw.values() if isinstance(raw, dict) else raw
    by_address: dict[int, set[str]] = defaultdict(set)
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get("value", item.get("Value", item.get("string", item.get("String"))))
        address = item.get("address", item.get("Address"))
        if not isinstance(value, str) or address is None:
            continue
        if not value or len(value) > MAX_LITERAL_LENGTH:
            continue
        addr = as_int(address)
        by_address[addr].add(value)
    return dict(by_address), set(by_address)


def adrp_page(word: int, pc: int) -> int | None:
    if word & 0x9F000000 != 0x90000000:
        return None
    immlo = (word >> 29) & 3
    immhi = (word >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def direct_call(ins: Any, by_rva: dict[int, list[Method]]) -> tuple[int, list[str]] | None:
    if ins.id != ARM64_INS_BL or not ins.operands or ins.operands[0].type != ARM64_OP_IMM:
        return None
    target = int(ins.operands[0].imm)
    return target, [row.name for row in by_rva.get(target, ())]


def sanitize_instruction(ins: Any, by_rva: dict[int, list[Method]]) -> str:
    call = direct_call(ins, by_rva)
    if call is not None and call[1]:
        return f"0x{ins.address:X}: bl {' | '.join(call[1])}"
    return f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}"


def instruction_context(insns: list[Any], index: int, by_rva: dict[int, list[Method]]) -> list[str]:
    lo = max(0, index - CONTEXT_RADIUS)
    hi = min(len(insns), index + CONTEXT_RADIUS + 1)
    return [sanitize_instruction(ins, by_rva) for ins in insns[lo:hi]]


def selected_call(names: list[str]) -> bool:
    joined = " ".join(names)
    return any(term in joined for term in INTEREST_TERMS)


def analyze_method(
    method: Method,
    *,
    starts: list[int],
    by_rva: dict[int, list[Method]],
    view: BinaryView,
    literal_values: dict[int, set[str]],
    slot_to_literal: dict[int, int],
) -> dict[str, Any]:
    end = function_end(starts, method.address)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(method.address, end - method.address), method.address))

    literal_refs: list[dict[str, Any]] = []
    for index, ins in enumerate(insns):
        if ins.id != ARM64_INS_ADRP:
            continue
        raw = view.read(int(ins.address), 4)
        if len(raw) != 4:
            continue
        page = adrp_page(struct.unpack("<I", raw)[0], int(ins.address))
        if page is None or not ins.operands or ins.operands[0].type != ARM64_OP_REG:
            continue
        base = ins.operands[0].reg
        for follow_index in range(index + 1, min(len(insns), index + 1 + LITERAL_WINDOW)):
            follow = insns[follow_index]
            if len(follow.operands) < 2 or follow.operands[1].type != ARM64_OP_MEM:
                continue
            mem = follow.operands[1].mem
            if mem.base != base:
                continue
            literal_address = slot_to_literal.get(page + int(mem.disp))
            if literal_address is None:
                continue
            values = sorted(literal_values.get(literal_address, ()))
            if values:
                literal_refs.append(
                    {
                        "load_rva": int(follow.address),
                        "values": values,
                    }
                )
            break

    unique_literals: dict[tuple[int, tuple[str, ...]], dict[str, Any]] = {}
    for row in literal_refs:
        unique_literals[(row["load_rva"], tuple(row["values"]))] = row

    calls: list[dict[str, Any]] = []
    named_direct_call_count = 0
    for index, ins in enumerate(insns):
        call = direct_call(ins, by_rva)
        if call is None or not call[1]:
            continue
        named_direct_call_count += 1
        if not selected_call(call[1]):
            continue
        if len(calls) >= MAX_SELECTED_CALLS:
            raise RuntimeError(f"selected call surface too large in {method.name}")
        calls.append(
            {
                "rva": int(ins.address),
                "target_rva": call[0],
                "targets": call[1],
                "context": instruction_context(insns, index, by_rva),
            }
        )

    return {
        "name": method.name,
        "rva": method.address,
        "end_rva": end,
        "size": end - method.address,
        "signature": method.signature,
        "instruction_count": len(insns),
        "named_direct_call_count": named_direct_call_count,
        "referenced_string_literals": sorted(unique_literals.values(), key=lambda row: row["load_rva"]),
        "selected_direct_calls": calls,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    by_rva, starts, targets = load_methods(args.script_json)
    literal_values, literal_addresses = load_string_literals(args.stringliteral_json)
    view = BinaryView(args.lib)
    try:
        slot_to_literal = view.relocation_slots(literal_addresses)
        reports = [
            analyze_method(
                targets[suffix],
                starts=starts,
                by_rva=by_rva,
                view=view,
                literal_values=literal_values,
                slot_to_literal=slot_to_literal,
            )
            for suffix in TARGET_SUFFIXES
            if suffix in targets
        ]
    finally:
        view.close()

    report = {
        "schema": 1,
        "target": "member-unit-edit-native-semantics",
        "methods": reports,
        "limits": {
            "bounded_methods_only": True,
            "direct_calls_only": True,
            "indirect_dispatch_recovered": False,
            "runtime_acceptance": False,
            "ui_visible_success": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
