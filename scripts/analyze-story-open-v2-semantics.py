#!/usr/bin/env python3
"""Bounded exact-final native pass for A:48 StoryReleaseEventStory / story/open_v2.

This report is intentionally narrow and sanitized. It exports only the task's
SetParameter/Parse methods, compact request-param type outlines, managed string
literals, named direct calls, and a tiny full instruction listing when a target
method is small enough. Raw specimen bytes and bulk Il2CppDumper output never leave
the workflow.
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

TASK_PREFIX = "Stage.StoryReleaseEventStoryTask$$"
TARGET_SUFFIXES = ("$$SetParameter", "$$Parse")
MAX_FUNCTION_SIZE = 0x6000
MAX_LITERAL_LENGTH = 160
LITERAL_WINDOW = 10
CONTEXT_RADIUS = 7
MAX_NAMED_CALLS = 360
MAX_TINY_INSTRUCTIONS = 120
MAX_OUTLINE_LINES = 160
INTEREST_TERMS = (
    "Story", "WorkStoryData", "JsonData", "BaseTask$$Parse", "NetworkUtil",
    "OpenStory", "OpenPrologue", "Present", "Item", "ToInt", "get_Keys",
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
        if name.startswith(TASK_PREFIX) and any(name.endswith(suffix) for suffix in TARGET_SUFFIXES):
            targets.append(method)
    for value in raw.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    for suffix in TARGET_SUFFIXES:
        if not any(method.name.endswith(suffix) for method in targets):
            raise RuntimeError(f"required StoryReleaseEventStoryTask{suffix} method not found")
    return dict(by_rva), sorted(starts), sorted(targets, key=lambda row: (row.address, row.name))


def function_end(starts: list[int], start: int) -> int:
    index = bisect.bisect_right(starts, start)
    if index >= len(starts):
        return start + MAX_FUNCTION_SIZE
    return min(starts[index], start + MAX_FUNCTION_SIZE)


def load_string_literals(path: Path) -> tuple[dict[int, set[str]], set[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = raw.values() if isinstance(raw, dict) else raw
    values: dict[int, set[str]] = defaultdict(set)
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get("value", item.get("Value", item.get("string", item.get("String"))))
        address = item.get("address", item.get("Address"))
        if isinstance(value, str) and value and len(value) <= MAX_LITERAL_LENGTH and address is not None:
            values[as_int(address)].add(value)
    return dict(values), set(values)


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
            raise RuntimeError(f"named-call surface unexpectedly large in {method.name}")
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
        if any(term in " ".join(branch[1]) for term in INTEREST_TERMS):
            selected_calls.append(row)
    tiny = [sanitize_instruction(ins, by_rva) for ins in insns] if len(insns) <= MAX_TINY_INSTRUCTIONS else []
    return {
        "name": method.name,
        "rva": method.address,
        "end_rva": end,
        "size": end - method.address,
        "signature": method.signature,
        "instruction_count": len(insns),
        "tiny_full_instruction_listing": tiny,
        "referenced_string_literals": referenced_literals(insns, view=view, literal_values=literal_values, slot_to_literal=slot_to_literal),
        "named_direct_calls": named_calls,
        "selected_direct_calls": selected_calls,
    }


def compact_param_outlines(dump_cs: Path) -> list[dict[str, Any]]:
    lines = dump_cs.read_text(encoding="utf-8", errors="replace").splitlines()
    namespace = ""
    result: list[dict[str, Any]] = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        if stripped.startswith("// Namespace:"):
            namespace = stripped.split(":", 1)[1].strip()
            i += 1
            continue
        if "StoryReleaseEventStoryTask" not in stripped or not re.search(r"\b(class|struct)\b", stripped):
            i += 1
            continue
        declaration = stripped
        block = [lines[i]]
        depth = lines[i].count("{") - lines[i].count("}")
        j = i + 1
        while j < len(lines):
            block.append(lines[j])
            depth += lines[j].count("{") - lines[j].count("}")
            if depth == 0 and any("{" in row for row in block):
                break
            j += 1
        outline: list[str] = []
        for raw in block:
            line = raw.strip()
            if not line or line in {"{", "}"}:
                continue
            if (
                line == declaration
                or line.startswith("// Fields")
                or line.startswith("// Methods")
                or line.startswith("// RVA:")
                or bool(re.search(r";\s*//\s*0x[0-9A-Fa-f]+", line))
                or "SetParameter(" in line
                or "Parse(" in line
            ):
                outline.append(line)
            if len(outline) > MAX_OUTLINE_LINES:
                raise RuntimeError(f"task outline unexpectedly large for {declaration}")
        result.append({"namespace": namespace, "declaration": declaration, "outline": outline})
        i = max(j + 1, i + 1)
    if not result:
        raise RuntimeError("StoryReleaseEventStoryTask type outline not found")
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
        methods = [
            analyze_method(
                method,
                starts=starts,
                by_rva=by_rva,
                view=view,
                literal_values=literal_values,
                slot_to_literal=slots,
            )
            for method in targets
        ]
    finally:
        view.close()

    report = {
        "schema": 1,
        "target": "A48-story-open-v2-native-semantics",
        "route": "/story/open_v2",
        "endpoint": {"group": "A", "key": 48, "enum": "StoryReleaseEventStory"},
        "methods": methods,
        "type_outlines": compact_param_outlines(args.dump_cs),
        "limits": {
            "only_story_release_event_story_task_methods": True,
            "tiny_listing_instruction_cap": MAX_TINY_INSTRUCTIONS,
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
