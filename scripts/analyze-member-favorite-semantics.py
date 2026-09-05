#!/usr/bin/env python3
"""Bounded exact-final native pass for A:22 MemberFavoriteEdit.

The target route and managed request DTO are already closed by the first-stage
favorite discovery pass. This pass exports only sanitized derived evidence for:

* MemberFavoriteEditTask.SetParameter();
* MemberFavoriteEditTask.Parse();
* direct native callers of SetParameter, with tiny local contexts.

It records named direct calls and managed string literals inside the two task
methods. The caller xref scan is target-specific and does not export bulk
callgraphs, disassembly, raw bytes or the specimen.
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
from capstone.arm64 import ARM64_INS_ADRP, ARM64_INS_B, ARM64_INS_BL, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile

TARGET_SUFFIXES = (
    "MemberFavoriteEditTask$$SetParameter",
    "MemberFavoriteEditTask$$Parse",
)
MAX_FUNCTION_SIZE = 0x4000
MAX_LITERAL_LENGTH = 160
LITERAL_WINDOW = 10
CONTEXT_RADIUS = 7
MAX_SELECTED_CALLS = 200
MAX_XREFS = 32
MAX_TINY_FULL_INSTRUCTIONS = 12
INTEREST_TERMS = (
    "Favorite",
    "WorkCardData",
    "WorkFavoriteData",
    "JsonData",
    "BaseTask$$Parse",
    "Array",
    "List",
    "Dictionary",
    "ToArray",
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
        self.loads: list[tuple[int, int, int, int, bool]] = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            flags = int(segment["p_flags"])
            self.loads.append(
                (
                    int(segment["p_vaddr"]),
                    int(segment["p_memsz"]),
                    int(segment["p_offset"]),
                    int(segment["p_filesz"]),
                    bool(flags & 1),
                )
            )

    def close(self) -> None:
        self.stream.close()

    def read(self, address: int, size: int) -> bytes:
        for vaddr, memsz, offset, filesz, _ in self.loads:
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

    def direct_bl_xrefs(self, target: int) -> list[int]:
        """Find ARM64 BL instructions whose exact immediate target is ``target``."""

        hits: list[int] = []
        for vaddr, _memsz, offset, filesz, executable in self.loads:
            if not executable or filesz < 4:
                continue
            self.stream.seek(offset)
            blob = self.stream.read(filesz)
            limit = len(blob) - (len(blob) % 4)
            for off in range(0, limit, 4):
                word = struct.unpack_from("<I", blob, off)[0]
                if word & 0xFC000000 != 0x94000000:
                    continue
                imm26 = word & 0x03FFFFFF
                if imm26 & 0x02000000:
                    imm26 -= 0x04000000
                pc = vaddr + off
                if pc + (imm26 << 2) == target:
                    hits.append(pc)
                    if len(hits) > MAX_XREFS:
                        raise RuntimeError("MemberFavoriteEdit SetParameter xref surface unexpectedly large")
        return hits


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
                    raise RuntimeError(f"ambiguous favorite target suffix {suffix!r}")
                targets[suffix] = method
    for value in raw.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    for suffix in TARGET_SUFFIXES:
        if suffix not in targets:
            raise RuntimeError(f"required favorite method not found: *{suffix}")
    return dict(by_rva), sorted(starts), targets


def function_end(starts: list[int], start: int) -> int:
    index = bisect.bisect_right(starts, start)
    if index >= len(starts):
        return start + MAX_FUNCTION_SIZE
    return min(starts[index], start + MAX_FUNCTION_SIZE)


def containing_method(starts: list[int], by_rva: dict[int, list[Method]], address: int) -> tuple[int, list[str]] | None:
    index = bisect.bisect_right(starts, address) - 1
    while index >= 0:
        start = starts[index]
        names = [row.name for row in by_rva.get(start, ())]
        if names:
            return start, names
        index -= 1
    return None


def load_string_literals(path: Path) -> tuple[dict[int, set[str]], set[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = raw.values() if isinstance(raw, dict) else raw
    by_address: dict[int, set[str]] = defaultdict(set)
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get("value", item.get("Value", item.get("string", item.get("String"))))
        address = item.get("address", item.get("Address"))
        if not isinstance(value, str) or address is None or not value or len(value) > MAX_LITERAL_LENGTH:
            continue
        by_address[as_int(address)].add(value)
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


def direct_branch(ins: Any, by_rva: dict[int, list[Method]], include_tail: bool = False):
    allowed = (ARM64_INS_BL, ARM64_INS_B) if include_tail else (ARM64_INS_BL,)
    if ins.id not in allowed or not ins.operands or ins.operands[0].type != ARM64_OP_IMM:
        return None
    target = int(ins.operands[0].imm)
    return target, [row.name for row in by_rva.get(target, ())]


def sanitize_instruction(ins: Any, by_rva: dict[int, list[Method]]) -> str:
    branch = direct_branch(ins, by_rva, include_tail=True)
    if branch is not None and branch[1]:
        mnemonic = "bl" if ins.id == ARM64_INS_BL else "b"
        return f"0x{ins.address:X}: {mnemonic} {' | '.join(branch[1])}"
    return f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}"


def disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def context(view: BinaryView, site: int, by_rva: dict[int, list[Method]]) -> list[str]:
    start = max(0, site - CONTEXT_RADIUS * 4)
    count = (CONTEXT_RADIUS * 2 + 1) * 4
    return [sanitize_instruction(ins, by_rva) for ins in disassembler().disasm(view.read(start, count), start)]


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
    insns = list(disassembler().disasm(view.read(method.address, end - method.address), method.address))

    literal_refs: dict[tuple[int, tuple[str, ...]], dict[str, Any]] = {}
    for index, ins in enumerate(insns):
        if ins.id != ARM64_INS_ADRP:
            continue
        raw = view.read(int(ins.address), 4)
        if len(raw) != 4 or not ins.operands or ins.operands[0].type != ARM64_OP_REG:
            continue
        page = adrp_page(struct.unpack("<I", raw)[0], int(ins.address))
        if page is None:
            continue
        base = ins.operands[0].reg
        for follow in insns[index + 1 : index + 1 + LITERAL_WINDOW]:
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
                row = {"load_rva": int(follow.address), "values": values}
                literal_refs[(row["load_rva"], tuple(values))] = row
            break

    selected_calls: list[dict[str, Any]] = []
    named_direct_call_count = 0
    for index, ins in enumerate(insns):
        branch = direct_branch(ins, by_rva)
        if branch is None or not branch[1]:
            continue
        named_direct_call_count += 1
        joined = " ".join(branch[1])
        if not any(term in joined for term in INTEREST_TERMS):
            continue
        if len(selected_calls) >= MAX_SELECTED_CALLS:
            raise RuntimeError(f"favorite selected-call surface too large in {method.name}")
        lo = max(0, index - CONTEXT_RADIUS)
        hi = min(len(insns), index + CONTEXT_RADIUS + 1)
        selected_calls.append(
            {
                "rva": int(ins.address),
                "target_rva": branch[0],
                "targets": branch[1],
                "context": [sanitize_instruction(row, by_rva) for row in insns[lo:hi]],
            }
        )

    tiny = [sanitize_instruction(ins, by_rva) for ins in insns] if len(insns) <= MAX_TINY_FULL_INSTRUCTIONS else []
    return {
        "name": method.name,
        "rva": method.address,
        "end_rva": end,
        "size": end - method.address,
        "signature": method.signature,
        "instruction_count": len(insns),
        "named_direct_call_count": named_direct_call_count,
        "tiny_full_instruction_listing": tiny,
        "referenced_string_literals": sorted(literal_refs.values(), key=lambda row: row["load_rva"]),
        "selected_direct_calls": selected_calls,
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
        methods = [
            analyze_method(
                targets[suffix],
                starts=starts,
                by_rva=by_rva,
                view=view,
                literal_values=literal_values,
                slot_to_literal=slot_to_literal,
            )
            for suffix in TARGET_SUFFIXES
        ]
        set_parameter = targets[TARGET_SUFFIXES[0]]
        xrefs: list[dict[str, Any]] = []
        for site in view.direct_bl_xrefs(set_parameter.address):
            owner = containing_method(starts, by_rva, site)
            xrefs.append(
                {
                    "site": site,
                    "caller_start": None if owner is None else owner[0],
                    "callers": [] if owner is None else owner[1],
                    "context": context(view, site, by_rva),
                }
            )
    finally:
        view.close()

    report = {
        "schema": 1,
        "target": "member-favorite-edit-native-semantics",
        "methods": methods,
        "set_parameter_direct_xrefs": xrefs,
        "limits": {
            "only_A22_task_methods": True,
            "xref_target_specific": True,
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
