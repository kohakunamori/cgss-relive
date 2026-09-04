#!/usr/bin/env python3
"""Trace executable consumers of selected final A-group endpoint route literals.

This is the residual C1 pass for endpoints whose concrete NetworkTask key was not
recovered from constructor/type-field evidence.  It deliberately accepts an
explicit key set, joins the authoritative `(key, route, literal_index)` map to
`stringliteral.json`, follows ELF RELA slots and exact ADRP+LDR executable loads,
and maps each load back to managed ScriptMethods.

Only bounded derived xref metadata is emitted.  Raw specimen/decompiler material
remains ephemeral in CI.
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
from elftools.elf.elffile import ELFFile

SCHEMA = 1
MAX_WINDOW = 8
MAX_REFS = 4096
MAX_FUNCTION_SIZE = 0x20000


@dataclass(frozen=True)
class Method:
    address: int
    name: str


class View:
    def __init__(self, path: Path):
        self.f = path.open("rb")
        self.elf = ELFFile(self.f)
        self.loads = []
        self.execs = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            row = (
                int(segment["p_vaddr"]), int(segment["p_memsz"]),
                int(segment["p_offset"]), int(segment["p_filesz"]),
            )
            self.loads.append(row)
            if int(segment["p_flags"]) & 1 and row[3]:
                self.execs.append((row[0], row[2], row[3]))

    def close(self):
        self.f.close()

    def read(self, address: int, size: int) -> bytes:
        for vaddr, memsz, offset, filesz in self.loads:
            if vaddr <= address < vaddr + memsz:
                rel = address - vaddr
                if rel >= filesz:
                    return b""
                size = min(size, filesz - rel)
                self.f.seek(offset + rel)
                return self.f.read(size)
        return b""

    def reloc_by_addend(self, addresses: set[int]):
        out = []
        for section in self.elf.iter_sections():
            if not hasattr(section, "iter_relocations"):
                continue
            for rel in section.iter_relocations():
                if not rel.is_RELA():
                    continue
                addend = int(rel["r_addend"])
                if addend in addresses:
                    out.append({
                        "section": section.name,
                        "slot": int(rel["r_offset"]),
                        "addend": addend,
                        "type": int(rel["r_info_type"]),
                    })
        return out

    def adrp_candidates(self, pages: set[int]):
        out = []
        for vaddr, offset, filesz in self.execs:
            self.f.seek(offset)
            data = self.f.read(filesz)
            limit = len(data) - len(data) % 4
            for pos in range(0, limit, 4):
                word = struct.unpack_from("<I", data, pos)[0]
                if word & 0x9F000000 != 0x90000000:
                    continue
                immlo = (word >> 29) & 3
                immhi = (word >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                pc = vaddr + pos
                page = (pc & ~0xFFF) + (imm << 12)
                if page in pages:
                    out.append((pc, page))
        return out


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def load_methods(path: Path):
    raw = json.loads(path.read_text(encoding="utf-8"))
    methods = []
    starts = set()
    signatures = {}
    for item in raw.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        name = str(item.get("Name", ""))
        methods.append(Method(address, name))
        starts.add(address)
        signatures[(address, name)] = item.get("Signature")
    for item in raw.get("Addresses", []):
        address = as_int(item)
        if address > 0:
            starts.add(address)
    methods.sort(key=lambda m: (m.address, m.name))
    return methods, sorted(starts), signatures


def function_end(starts: list[int], address: int) -> int:
    index = bisect.bisect_right(starts, address)
    end = starts[index] if index < len(starts) else address + MAX_FUNCTION_SIZE
    return min(end, address + MAX_FUNCTION_SIZE)


def containing(methods: list[Method], starts: list[int], rva: int):
    addresses = [m.address for m in methods]
    index = bisect.bisect_right(addresses, rva) - 1
    if index < 0:
        return []
    start = methods[index].address
    if not start <= rva < function_end(starts, start):
        return []
    left = bisect.bisect_left(addresses, start)
    right = bisect.bisect_right(addresses, start)
    return methods[left:right]


def load_rows(path: Path, keys: set[int]):
    raw = json.loads(path.read_text(encoding="utf-8"))
    by_key = {int(row[1]): row for row in raw["A"]}
    missing = sorted(keys - set(by_key))
    if missing:
        raise RuntimeError(f"A keys missing from authoritative map: {missing}")
    return [
        {"enum": str(by_key[key][0]), "key": key, "route": str(by_key[key][2]), "literal_index": int(by_key[key][3])}
        for key in sorted(keys)
    ]


def load_literals(path: Path, indices: set[int]):
    raw = json.loads(path.read_text(encoding="utf-8"))
    out = {}
    for index in indices:
        item = raw[index]
        value = item.get("value", item.get("Value", item.get("string", item.get("String"))))
        address = item.get("address", item.get("Address"))
        if not isinstance(value, str) or address is None:
            raise RuntimeError(f"literal {index} missing")
        out[index] = {"literal_index": index, "value": value, "address": as_int(address)}
    return out


def exact_slot_refs(view: View, slots: set[int]):
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    pages = {slot & ~0xFFF for slot in slots}
    out = []
    for adrp, page in view.adrp_candidates(pages):
        insns = list(md.disasm(view.read(adrp, 4 * MAX_WINDOW), adrp))
        if not insns:
            continue
        base = insns[0].op_str.split(",", 1)[0].strip().lower()
        for ins in insns[1:]:
            text = ins.op_str.replace(" ", "").lower()
            for slot in slots:
                if slot & ~0xFFF != page:
                    continue
                offset = slot & 0xFFF
                if text.startswith(base + ",") and f"[{base},#0x{offset:x}]" in text:
                    out.append({"adrp_rva": adrp, "load_rva": int(ins.address), "slot": slot})
                    break
            else:
                continue
            break
        if len(out) > MAX_REFS:
            raise RuntimeError("too many residual route refs")
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--api-map", type=Path, required=True)
    parser.add_argument("--keys", required=True, help="comma-separated A-group keys")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    keys = {int(part.strip(), 0) for part in args.keys.split(",") if part.strip()}
    rows = load_rows(args.api_map, keys)
    literals = load_literals(args.stringliteral_json, {row["literal_index"] for row in rows})
    address_to_rows = defaultdict(list)
    for row in rows:
        literal = literals[row["literal_index"]]
        if literal["value"] != row["route"]:
            raise RuntimeError(f"A route/literal mismatch: {row} vs {literal}")
        address_to_rows[literal["address"]].append(row)

    methods, starts, signatures = load_methods(args.script_json)
    view = View(args.lib)
    try:
        relocs = view.reloc_by_addend(set(address_to_rows))
        slot_to_addend = {row["slot"]: row["addend"] for row in relocs}
        refs = exact_slot_refs(view, set(slot_to_addend))
        mapped = []
        unmapped = []
        for ref in refs:
            owners = containing(methods, starts, ref["load_rva"])
            addend = slot_to_addend[ref["slot"]]
            routes = address_to_rows[addend]
            if not owners:
                unmapped.append({**ref, "routes": routes})
            for method in owners:
                mapped.append({
                    **ref,
                    "consumer": method.name,
                    "consumer_rva": method.address,
                    "signature": signatures.get((method.address, method.name)),
                    "routes": routes,
                })
    finally:
        view.close()

    by_key = {str(row["key"]): [] for row in rows}
    for item in mapped:
        for route in item["routes"]:
            by_key[str(route["key"])].append({
                "consumer": item["consumer"],
                "consumer_rva": item["consumer_rva"],
                "signature": item["signature"],
                "load_rva": item["load_rva"],
                "slot": item["slot"],
            })

    report = {
        "schema": SCHEMA,
        "group": "A",
        "keys": sorted(keys),
        "route_count": len(rows),
        "unique_literal_address_count": len(address_to_rows),
        "relocation_count": len(relocs),
        "exact_reference_count": len(refs),
        "mapped_references": mapped,
        "unmapped_references": unmapped,
        "by_key": by_key,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
