#!/usr/bin/env python3
"""Bounded exact-final native pass for A:47 StoryStart.

The report is deliberately sanitized. It exports only StoryStart task methods,
compact StoryTempData type outlines, managed literals and named direct calls.
Raw specimen bytes and bulk dump.cs/disassembly are never written.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_ADRP, ARM64_INS_B, ARM64_INS_BL, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile

TASK_PREFIX = "Stage.StoryStartTask$$"
TARGET_METHOD_SUFFIXES = ("$$SetParameter", "$$Parse")
TYPE_TERMS = ("StoryStartTask", "StoryTempData")
MAX_FUNCTION_SIZE = 0x5000
MAX_LITERAL_LENGTH = 160
LITERAL_WINDOW = 10
CONTEXT_RADIUS = 6
MAX_NAMED_CALLS = 320
MAX_TYPE_OUTLINE_LINES = 240
INTEREST_TERMS = (
    "Story", "PData", "Present", "JsonData", "NetworkUtil", "BaseTask$$Parse",
    "Array", "List", "Dictionary", "ToInt", "ToString", "op_Explicit", "op_Implicit",
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
            self.loads.append((
                int(segment["p_vaddr"]), int(segment["p_memsz"]),
                int(segment["p_offset"]), int(segment["p_filesz"]), bool(flags & 1),
            ))

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


def as_int(value: Any) -> int:
    return value if isinstance(value, int) else int(str(value), 0)


def load_methods(path: Path) -> tuple[dict[int, list[Method]], list[int], list[Method]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    by_rva: dict[int, list[Method]] = defaultdict(list)
    starts: set[int] = set()
    targets: list[Method] = []
    for row in raw.get("ScriptMethod", []):
        address = as_int(row.get("Address", 0))
        name = str(row.get("Name") or "")
        if address <= 0 or not name:
            continue
        method = Method(address, name, row.get("Signature"))
        by_rva[address].append(method)
        starts.add(address)
        if name.startswith(TASK_PREFIX) and any(name.endswith(s) for s in TARGET_METHOD_SUFFIXES):
            targets.append(method)
    for value in raw.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    if not any(m.name.endswith("$$Parse") for m in targets):
        raise RuntimeError("required StoryStartTask$$Parse method not found")
    return dict(by_rva), sorted(starts), sorted(targets, key=lambda m: (m.address, m.name))


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


def disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def direct_branch(ins: Any, by_rva: dict[int, list[Method]]) -> tuple[int, list[str]] | None:
    if ins.id not in (ARM64_INS_BL, ARM64_INS_B) or not ins.operands or ins.operands[0].type != ARM64_OP_IMM:
        return None
    target = int(ins.operands[0].imm)
    return target, [row.name for row in by_rva.get(target, ())]


def sanitize_instruction(ins: Any, by_rva: dict[int, list[Method]]) -> str:
    branch = direct_branch(ins, by_rva)
    if branch is not None and branch[1]:
        mnemonic = "bl" if ins.id == ARM64_INS_BL else "b"
        return f"0x{ins.address:X}: {mnemonic} {' | '.join(branch[1])}"
    return f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}"


def referenced_literals(insns: list[Any], *, view: BinaryView, literal_values: dict[int, set[str]], slot_to_literal: dict[int, int]) -> list[dict[str, Any]]:
    found: dict[tuple[int, tuple[str, ...]], dict[str, Any]] = {}
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
        for follow in insns[index + 1:index + 1 + LITERAL_WINDOW]:
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
                found[(row["load_rva"], tuple(values))] = row
            break
    return sorted(found.values(), key=lambda row: row["load_rva"])


def analyze_method(method: Method, *, starts: list[int], by_rva: dict[int, list[Method]], view: BinaryView, literal_values: dict[int, set[str]], slot_to_literal: dict[int, int]) -> dict[str, Any]:
    end = function_end(starts, method.address)
    insns = list(disassembler().disasm(view.read(method.address, end - method.address), method.address))
    named_calls: list[dict[str, Any]] = []
    selected_calls: list[dict[str, Any]] = []
    for index, ins in enumerate(insns):
        branch = direct_branch(ins, by_rva)
        if branch is None or not branch[1]:
            continue
        if len(named_calls) >= MAX_NAMED_CALLS:
            raise RuntimeError(f"StoryStart named-call surface unexpectedly large in {method.name}")
        lo = max(0, index - CONTEXT_RADIUS)
        hi = min(len(insns), index + CONTEXT_RADIUS + 1)
        row = {
            "rva": int(ins.address),
            "branch_kind": "BL" if ins.id == ARM64_INS_BL else "B",
            "target_rva": branch[0],
            "targets": branch[1],
            "context": [sanitize_instruction(x, by_rva) for x in insns[lo:hi]],
        }
        named_calls.append(row)
        joined = " ".join(branch[1])
        if any(term in joined for term in INTEREST_TERMS):
            selected_calls.append(row)
    return {
        "name": method.name,
        "rva": method.address,
        "end_rva": end,
        "size": end - method.address,
        "signature": method.signature,
        "instruction_count": len(insns),
        "referenced_string_literals": referenced_literals(insns, view=view, literal_values=literal_values, slot_to_literal=slot_to_literal),
        "named_direct_calls": named_calls,
        "selected_direct_calls": selected_calls,
    }


def type_blocks(text: str) -> list[tuple[str, str, list[str]]]:
    lines = text.splitlines()
    namespace = ""
    blocks: list[tuple[str, str, list[str]]] = []
    type_re = re.compile(r"^(?:public|internal|private|protected|static|sealed|abstract|partial|\s)*\s*(?:class|struct)\s+")
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("// Namespace:"):
            namespace = stripped.split(":", 1)[1].strip()
            i += 1
            continue
        if not type_re.match(stripped):
            i += 1
            continue
        declaration = stripped
        block = [lines[i]]
        depth = lines[i].count("{") - lines[i].count("}")
        j = i + 1
        while j < len(lines):
            block.append(lines[j])
            depth += lines[j].count("{") - lines[j].count("}")
            if depth == 0 and any("{" in x for x in block):
                break
            j += 1
        blocks.append((namespace, declaration, block))
        i = max(j + 1, i + 1)
    return blocks


def compact_type_outlines(dump_cs: Path) -> list[dict[str, Any]]:
    text = dump_cs.read_text(encoding="utf-8", errors="replace")
    result: list[dict[str, Any]] = []
    for namespace, declaration, block in type_blocks(text):
        if not any(term in f"{namespace} {declaration}" for term in TYPE_TERMS):
            continue
        outline: list[str] = []
        for raw in block:
            line = raw.strip()
            if not line or line in {"{", "}"}:
                continue
            keep = line == declaration.strip()
            keep = keep or line.startswith("// RVA:") or line.startswith("// Fields") or line.startswith("// Methods")
            keep = keep or bool(re.search(r";\s*//\s*0x[0-9A-Fa-f]+", line))
            keep = keep or ("(" in line and (line.endswith("{ }") or line.endswith(";")))
            keep = keep or any(term in line for term in ("PData", "indexString", "30minute", "Present"))
            if keep:
                outline.append(line)
            if len(outline) > MAX_TYPE_OUTLINE_LINES:
                raise RuntimeError(f"type outline unexpectedly large for {declaration}")
        result.append({"namespace": namespace, "declaration": declaration, "outline": outline})
    if not any("StoryStartTask" in row["declaration"] for row in result):
        raise RuntimeError("StoryStartTask dump.cs outline not found")
    if not any("StoryTempData" in row["declaration"] for row in result):
        raise RuntimeError("StoryTempData dump.cs outline not found")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    by_rva, starts, targets = load_methods(args.script_json)
    literal_values, literal_addresses = load_string_literals(args.stringliteral_json)
    view = BinaryView(args.lib)
    try:
        slots = view.relocation_slots(literal_addresses)
        methods = [analyze_method(m, starts=starts, by_rva=by_rva, view=view, literal_values=literal_values, slot_to_literal=slots) for m in targets]
    finally:
        view.close()

    report = {
        "schema": 1,
        "target": "A47-story-start-native-semantics",
        "route": "/story/start",
        "endpoint": {"group": "A", "key": 47, "enum": "StoryStart"},
        "methods": methods,
        "type_outlines": compact_type_outlines(args.dump_cs),
        "limits": {
            "only_story_start_task_methods": True,
            "bounded_named_direct_calls": MAX_NAMED_CALLS,
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
