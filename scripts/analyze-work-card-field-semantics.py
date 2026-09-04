#!/usr/bin/env python3
"""Targeted final-client semantic pass for WorkCardData card fields.

The goal is deliberately narrow: identify exact CardData fields/methods related to
``step``, ``love`` and ``protect`` and map direct native callers of those accessors.
The output is sanitized metadata only; no bulk dump.cs or disassembly is emitted.
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
from capstone.arm64 import ARM64_OP_MEM
from elftools.elf.elffile import ELFFile

SCHEMA = 1
TARGET_OWNER = "Stage.WorkCardData.CardData"
TARGET_TERMS = ("step", "love", "protect")
RELATED_TERMS = ("step", "love", "protect", "lock", "favorite", "affection", "bond")
PF_X = 0x1
BRANCH_MASK = 0xFC000000
BL_OPCODE = 0x94000000
B_OPCODE = 0x14000000
MAX_METHOD_SIZE = 0x1000

_TYPE_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)?\s*"
    r"(?:(?:sealed|abstract|static|partial)\s+)*"
    r"(?:class|struct)\s+([^\s:{]+)"
)
_RVA_RE = re.compile(r"//\s*RVA:\s*0x([0-9A-Fa-f]+)")
_OFFSET_RE = re.compile(r"//\s*0x([0-9A-Fa-f]+)\s*$")
_FIELD_NAME_RE = re.compile(r"([A-Za-z_<>][A-Za-z0-9_<>]*)\s*;\s*(?://|$)")
_METHOD_NAME_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: str | None


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def load_script(path: Path) -> tuple[list[Method], dict[int, list[Method]], list[int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    methods: list[Method] = []
    by_start: dict[int, list[Method]] = defaultdict(list)
    boundaries: set[int] = set()
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        name = str(item.get("Name") or "")
        if address <= 0 or not name:
            continue
        method = Method(address, name, item.get("Signature"))
        methods.append(method)
        by_start[address].append(method)
        boundaries.add(address)
    for value in data.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            boundaries.add(address)
    methods.sort(key=lambda row: (row.address, row.name, row.signature or ""))
    return methods, dict(by_start), sorted(boundaries)


def type_header(line: str) -> str | None:
    match = _TYPE_RE.match(line)
    return None if match is None else match.group(1)


def type_blocks(lines: list[str]) -> list[tuple[int, int, str]]:
    starts: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        name = type_header(line)
        if name is not None:
            starts.append((index, name))
    result: list[tuple[int, int, str]] = []
    for pos, (start, name) in enumerate(starts):
        end = starts[pos + 1][0] if pos + 1 < len(starts) else len(lines)
        result.append((start, end, name))
    return result


def rvas_in_block(lines: list[str], start: int, end: int) -> set[int]:
    values: set[int] = set()
    for line in lines[start:end]:
        match = _RVA_RE.search(line)
        if match:
            values.add(int(match.group(1), 16))
    return values


def select_card_data_block(
    lines: list[str], by_start: dict[int, list[Method]]
) -> tuple[int, int, str]:
    candidates: list[tuple[int, int, str]] = []
    for block in type_blocks(lines):
        start, end, name = block
        if name.rsplit(".", 1)[-1] != "CardData":
            continue
        for rva in rvas_in_block(lines, start, end):
            if any(method.name.startswith(TARGET_OWNER + "$$") for method in by_start.get(rva, [])):
                candidates.append(block)
                break
    if len(candidates) != 1:
        raise RuntimeError(f"expected one {TARGET_OWNER} dump.cs block, found {len(candidates)}")
    return candidates[0]


def parse_target_fields(lines: list[str], start: int, end: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for index in range(start + 1, end):
        line = lines[index]
        offset = _OFFSET_RE.search(line)
        field = _FIELD_NAME_RE.search(line)
        if not offset or not field:
            continue
        name = field.group(1).strip("<>")
        lowered = name.lower()
        matched = [term for term in TARGET_TERMS if term in lowered]
        if not matched:
            continue
        declaration = line.split("//", 1)[0].strip()
        rows.append(
            {
                "name": name,
                "offset": int(offset.group(1), 16),
                "declaration": declaration,
                "matched_terms": matched,
                "dump_line": index + 1,
            }
        )
    rows.sort(key=lambda row: (row["offset"], row["name"]))
    return rows


def parse_block_methods(
    lines: list[str], start: int, end: int, by_start: dict[int, list[Method]]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index in range(start + 1, end - 1):
        match = _RVA_RE.search(lines[index])
        if not match:
            continue
        rva = int(match.group(1), 16)
        signature = lines[index + 1].strip()
        managed = [m for m in by_start.get(rva, []) if m.name.startswith(TARGET_OWNER + "$$")]
        if not managed:
            continue
        short = managed[0].name.split("$$", 1)[1]
        lowered = (short + " " + signature).lower()
        terms = [term for term in RELATED_TERMS if term in lowered]
        if not terms:
            continue
        result.append(
            {
                "rva": rva,
                "full_name": managed[0].name,
                "method": short,
                "signature": signature,
                "matched_terms": terms,
                "dump_line": index + 2,
            }
        )
    result.sort(key=lambda row: (row["rva"], row["full_name"]))
    return result


def find_add_card_methods(methods: list[Method]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for method in methods:
        if method.name.startswith("Stage.WorkCardData$$AddCardData"):
            rows.append({"rva": method.address, "full_name": method.name, "signature": method.signature})
    return rows


def signed_imm26(word: int) -> int:
    imm26 = word & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return imm26 << 2


def containing_methods(address: int, boundaries: list[int], by_start: dict[int, list[Method]]) -> list[Method]:
    index = bisect.bisect_right(boundaries, address) - 1
    if index < 0:
        return []
    return by_start.get(boundaries[index], [])


def scan_direct_xrefs(
    lib_path: Path,
    targets: dict[int, list[dict[str, Any]]],
    boundaries: list[int],
    by_start: dict[int, list[Method]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with lib_path.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & PF_X):
                continue
            vaddr = int(segment["p_vaddr"])
            stream.seek(int(segment["p_offset"]))
            data = stream.read(int(segment["p_filesz"]))
            data = data[: len(data) - len(data) % 4]
            for index, (word,) in enumerate(struct.iter_unpack("<I", data)):
                opcode = word & BRANCH_MASK
                if opcode not in (BL_OPCODE, B_OPCODE):
                    continue
                site = vaddr + index * 4
                target = site + signed_imm26(word)
                if target not in targets:
                    continue
                callers = containing_methods(site, boundaries, by_start)
                rows.append(
                    {
                        "callsite_rva": site,
                        "target_rva": target,
                        "edge_kind": "BL" if opcode == BL_OPCODE else "B-tail",
                        "target_methods": [row["full_name"] for row in targets[target]],
                        "callers": [method.name for method in callers],
                    }
                )
    rows.sort(key=lambda row: (row["target_rva"], row["callsite_rva"]))
    return rows


def method_field_accesses(
    lib_path: Path,
    methods: list[dict[str, Any]],
    fields: list[dict[str, Any]],
    boundaries: list[int],
) -> list[dict[str, Any]]:
    wanted_offsets = {int(row["offset"]): row["name"] for row in fields}
    if not wanted_offsets:
        return []
    dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    dis.detail = True
    result: list[dict[str, Any]] = []
    with lib_path.open("rb") as stream:
        elf = ELFFile(stream)
        segments = []
        for segment in elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                segments.append(
                    (
                        int(segment["p_vaddr"]), int(segment["p_memsz"]),
                        int(segment["p_offset"]), int(segment["p_filesz"]),
                    )
                )

        def read(address: int, size: int) -> bytes:
            for vaddr, memsz, fileoff, filesz in segments:
                if vaddr <= address < vaddr + memsz:
                    relative = address - vaddr
                    if relative >= filesz:
                        return b""
                    stream.seek(fileoff + relative)
                    return stream.read(min(size, filesz - relative))
            return b""

        for method in methods:
            start = int(method["rva"])
            idx = bisect.bisect_right(boundaries, start)
            if idx >= len(boundaries):
                continue
            end = boundaries[idx]
            if end <= start or end - start > MAX_METHOD_SIZE:
                continue
            hits: list[dict[str, Any]] = []
            for insn in dis.disasm(read(start, end - start), start):
                for operand in insn.operands:
                    if operand.type != ARM64_OP_MEM:
                        continue
                    disp = int(operand.mem.disp)
                    if disp not in wanted_offsets:
                        continue
                    hits.append(
                        {
                            "rva": int(insn.address),
                            "mnemonic": insn.mnemonic,
                            "field_offset": disp,
                            "field_name": wanted_offsets[disp],
                        }
                    )
            result.append(
                {
                    "method": method["full_name"],
                    "method_rva": start,
                    "target_field_accesses": hits,
                }
            )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lines = args.dump_cs.read_text(encoding="utf-8", errors="replace").splitlines()
    methods, by_start, boundaries = load_script(args.script_json)
    start, end, declaration = select_card_data_block(lines, by_start)
    fields = parse_target_fields(lines, start, end)
    target_methods = parse_block_methods(lines, start, end, by_start)
    add_card_methods = find_add_card_methods(methods)

    by_target: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in target_methods:
        by_target[int(row["rva"])].append(row)

    xrefs = scan_direct_xrefs(args.lib, dict(by_target), boundaries, by_start)
    accesses = method_field_accesses(args.lib, target_methods, fields, boundaries)

    consumers_by_target: dict[str, set[str]] = defaultdict(set)
    for row in xrefs:
        for target in row["target_methods"]:
            for caller in row["callers"]:
                consumers_by_target[target].add(caller)

    report = {
        "schema": SCHEMA,
        "target_owner": TARGET_OWNER,
        "type_declaration": declaration,
        "target_fields": fields,
        "target_methods": target_methods,
        "add_card_data_methods": add_card_methods,
        "direct_xrefs": xrefs,
        "method_field_accesses": accesses,
        "direct_consumers": {
            key: sorted(value) for key, value in sorted(consumers_by_target.items())
        },
        "evidence_policy": {
            "field_layout": "exact-dump-metadata",
            "method_identity": "exact-il2cppdumper-script-method",
            "direct_consumer": "direct-arm64-bl-or-b-tail-only",
            "business_semantics_inferred": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(json.dumps({
        "target_field_count": len(fields),
        "target_method_count": len(target_methods),
        "add_card_data_method_count": len(add_card_methods),
        "direct_xref_count": len(xrefs),
        "fields": [row["name"] for row in fields],
        "methods": [row["full_name"] for row in target_methods],
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
