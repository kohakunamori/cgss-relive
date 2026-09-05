#!/usr/bin/env python3
"""Recover bounded final-11.6.3 response semantics for MemberProtectCardTask.Parse.

The report is deliberately narrow and sanitized. It exports:
- managed string literals referenced inside the exact Parse method;
- nearby managed call targets for each literal;
- tiny instruction contexts around calls to owned-card lookup, protection accessors,
  ObscuredBool conversions and JsonData helpers.

No raw bytes, dump.cs, script.json, stringliteral.json or bulk disassembly are emitted.
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

TARGET_METHOD = "Stage.MemberProtectCardTask$$Parse"
MAX_FUNCTION_SIZE = 0x5000
LITERAL_WINDOW = 10
CONTEXT_RADIUS = 7
MAX_LITERAL_LENGTH = 160


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


def load_methods(path: Path) -> tuple[dict[int, list[Method]], list[int], Method]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    by_rva: dict[int, list[Method]] = defaultdict(list)
    starts: set[int] = set()
    target: Method | None = None
    for row in raw.get("ScriptMethod", []):
        address = as_int(row.get("Address", 0))
        name = str(row.get("Name") or "")
        if address <= 0 or not name:
            continue
        method = Method(address, name, row.get("Signature"))
        by_rva[address].append(method)
        starts.add(address)
        if name == TARGET_METHOD:
            target = method
    for value in raw.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    if target is None:
        raise RuntimeError(f"target method not found: {TARGET_METHOD}")
    return dict(by_rva), sorted(starts), target


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


def direct_call_name(ins: Any, by_rva: dict[int, list[Method]]) -> tuple[int, list[str]] | None:
    if ins.id != ARM64_INS_BL or not ins.operands or ins.operands[0].type != ARM64_OP_IMM:
        return None
    target = int(ins.operands[0].imm)
    return target, [row.name for row in by_rva.get(target, [])]


def sanitize_instruction(ins: Any, by_rva: dict[int, list[Method]]) -> str:
    call = direct_call_name(ins, by_rva)
    if call is not None and call[1]:
        return f"0x{ins.address:X}: bl {' | '.join(call[1])}"
    return f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}"


def context(insns: list[Any], index: int, by_rva: dict[int, list[Method]]) -> list[str]:
    lo = max(0, index - CONTEXT_RADIUS)
    hi = min(len(insns), index + CONTEXT_RADIUS + 1)
    return [sanitize_instruction(item, by_rva) for item in insns[lo:hi]]


def interesting_call(names: list[str]) -> bool:
    joined = " ".join(names)
    terms = (
        "WorkCardData$$GetCardDataWithSerial",
        "WorkCardData.CardData$$get_isProtect",
        "WorkCardData.CardData$$set_isProtect",
        "WorkCardData.CardData$$SetResponseProtect",
        "ObscuredBool$$op_Implicit",
        "LitJson.JsonData$$get_Item",
        "LitJson.JsonData$$get_Count",
        "LitJson.JsonData$$get_Keys",
        "LitJson.JsonData$$ToInt",
        "LitJson.JsonData$$op_Explicit",
    )
    return any(term in joined for term in terms)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    by_rva, starts, target = load_methods(args.script_json)
    end = function_end(starts, target.address)
    literal_values, literal_addresses = load_string_literals(args.stringliteral_json)
    view = BinaryView(args.lib)
    try:
        slot_to_literal_address = view.relocation_slots(literal_addresses)
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        insns = list(md.disasm(view.read(target.address, end - target.address), target.address))

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
            for follow in insns[index + 1 : index + 1 + LITERAL_WINDOW]:
                if len(follow.operands) < 2 or follow.operands[1].type != ARM64_OP_MEM:
                    continue
                mem = follow.operands[1].mem
                if mem.base != base:
                    continue
                slot = page + int(mem.disp)
                literal_address = slot_to_literal_address.get(slot)
                if literal_address is None:
                    continue
                values = sorted(literal_values.get(literal_address, ()))
                if not values:
                    continue
                nearby_calls: list[dict[str, Any]] = []
                follow_index = insns.index(follow)
                for later in insns[follow_index + 1 : follow_index + 18]:
                    call = direct_call_name(later, by_rva)
                    if call is None:
                        continue
                    nearby_calls.append(
                        {"rva": int(later.address), "target_rva": call[0], "targets": call[1]}
                    )
                literal_refs.append(
                    {
                        "adrp_rva": int(ins.address),
                        "load_rva": int(follow.address),
                        "values": values,
                        "nearby_calls": nearby_calls,
                    }
                )
                break

        important_calls: list[dict[str, Any]] = []
        for index, ins in enumerate(insns):
            call = direct_call_name(ins, by_rva)
            if call is None or not interesting_call(call[1]):
                continue
            important_calls.append(
                {
                    "rva": int(ins.address),
                    "target_rva": call[0],
                    "targets": call[1],
                    "context": context(insns, index, by_rva),
                }
            )
    finally:
        view.close()

    # De-duplicate literal references by exact load site + values.
    unique: dict[tuple[int, tuple[str, ...]], dict[str, Any]] = {}
    for row in literal_refs:
        unique[(row["load_rva"], tuple(row["values"]))] = row
    literal_refs = sorted(unique.values(), key=lambda row: row["load_rva"])

    report = {
        "schema": 1,
        "target_method": target.name,
        "target_rva": target.address,
        "target_end_rva": end,
        "target_signature": target.signature,
        "referenced_string_literals": literal_refs,
        "important_call_contexts": important_calls,
        "limits": {
            "bounded_single_method": True,
            "direct_calls_only": True,
            "indirect_dispatch_recovered": False,
            "runtime_acceptance": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "target_method": target.name,
        "target_rva": target.address,
        "strings": [row["values"] for row in literal_refs],
        "important_calls": [
            {"rva": row["rva"], "targets": row["targets"], "context": row["context"]}
            for row in important_calls
        ],
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
