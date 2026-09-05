#!/usr/bin/env python3
"""Trace the final 11.6.3 MemberProtect card mutation flow.

Sanitized output only: selected managed method identities, direct ARM64 BL/B-tail
edges, and reverse direct xrefs to WorkCardData protection accessors.  This pass is
intended to determine whether ``member/protect_card`` means set, toggle, or merely
acknowledge a protection mutation without guessing from the route name.
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

from elftools.elf.elffile import ELFFile

PF_X = 1
BRANCH_MASK = 0xFC000000
BL_OPCODE = 0x94000000
B_OPCODE = 0x14000000
MAX_FUNCTION_SIZE = 0x5000


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: str | None


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def load_methods(path: Path) -> tuple[list[Method], dict[int, list[Method]], list[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    methods: list[Method] = []
    by_start: dict[int, list[Method]] = defaultdict(list)
    boundaries: set[int] = set()
    for row in raw.get("ScriptMethod", []):
        address = as_int(row.get("Address", 0))
        name = str(row.get("Name") or "")
        if address <= 0 or not name:
            continue
        method = Method(address, name, row.get("Signature"))
        methods.append(method)
        by_start[address].append(method)
        boundaries.add(address)
    for value in raw.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            boundaries.add(address)
    return methods, dict(by_start), sorted(boundaries)


def signed_imm26(word: int) -> int:
    imm26 = word & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return imm26 << 2


def selected_flow_method(name: str) -> bool:
    if "MemberProtectCardTask$$" in name:
        return True
    if "MemberCardListBase$$" in name and any(
        token in name for token in ("Protect", "ActionProtect", "StartMemberProtectTask")
    ):
        return True
    if "MemberCardListBase.<" in name and "Protect" in name and name.endswith("$$MoveNext"):
        return True
    if "MemberPopupIdolDetail" in name and "Protect" in name:
        return True
    if "GachaScIdolDetail" in name and "Protect" in name:
        return True
    return False


def protection_accessor(name: str) -> bool:
    return "WorkCardData.CardData$$" in name and any(
        token in name.lower() for token in ("protect", "isprotect")
    )


def function_end(start: int, boundaries: list[int]) -> int:
    index = bisect.bisect_right(boundaries, start)
    if index >= len(boundaries):
        return start
    return min(boundaries[index], start + MAX_FUNCTION_SIZE)


def containing_methods(address: int, boundaries: list[int], by_start: dict[int, list[Method]]) -> list[Method]:
    index = bisect.bisect_right(boundaries, address) - 1
    if index < 0:
        return []
    return by_start.get(boundaries[index], [])


def scan_edges(
    lib: Path,
    selected: list[Method],
    accessors: list[Method],
    by_start: dict[int, list[Method]],
    boundaries: list[int],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected_starts = {method.address: method for method in selected}
    accessor_starts = {method.address: method for method in accessors}
    flow_edges: list[dict[str, Any]] = []
    accessor_xrefs: list[dict[str, Any]] = []

    with lib.open("rb") as stream:
        elf = ELFFile(stream)
        segments: list[tuple[int, bytes]] = []
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & PF_X):
                continue
            vaddr = int(segment["p_vaddr"])
            stream.seek(int(segment["p_offset"]))
            data = stream.read(int(segment["p_filesz"]))
            data = data[: len(data) - len(data) % 4]
            segments.append((vaddr, data))

        # Scan selected method bodies for direct calls/tails.
        for method in selected:
            end = function_end(method.address, boundaries)
            if end <= method.address:
                continue
            for seg_vaddr, data in segments:
                seg_end = seg_vaddr + len(data)
                if not (seg_vaddr <= method.address < seg_end):
                    continue
                lo = method.address - seg_vaddr
                hi = min(end - seg_vaddr, len(data))
                chunk = data[lo : hi - ((hi - lo) % 4)]
                for index, (word,) in enumerate(struct.iter_unpack("<I", chunk)):
                    opcode = word & BRANCH_MASK
                    if opcode not in (BL_OPCODE, B_OPCODE):
                        continue
                    site = method.address + index * 4
                    target = site + signed_imm26(word)
                    target_methods = by_start.get(target, [])
                    if not target_methods:
                        continue
                    flow_edges.append(
                        {
                            "caller": method.name,
                            "callsite_rva": site,
                            "edge_kind": "BL" if opcode == BL_OPCODE else "B-tail",
                            "target_rva": target,
                            "targets": [row.name for row in target_methods],
                        }
                    )
                break

        # Whole executable reverse-xref scan to exact protection accessors.
        wanted = set(accessor_starts)
        for seg_vaddr, data in segments:
            for index, (word,) in enumerate(struct.iter_unpack("<I", data)):
                opcode = word & BRANCH_MASK
                if opcode not in (BL_OPCODE, B_OPCODE):
                    continue
                site = seg_vaddr + index * 4
                target = site + signed_imm26(word)
                if target not in wanted:
                    continue
                callers = containing_methods(site, boundaries, by_start)
                accessor_xrefs.append(
                    {
                        "callsite_rva": site,
                        "edge_kind": "BL" if opcode == BL_OPCODE else "B-tail",
                        "target": accessor_starts[target].name,
                        "callers": [row.name for row in callers],
                    }
                )

    flow_edges.sort(key=lambda row: (row["caller"], row["callsite_rva"]))
    accessor_xrefs.sort(key=lambda row: (row["target"], row["callsite_rva"]))
    return flow_edges, accessor_xrefs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    methods, by_start, boundaries = load_methods(args.script_json)
    selected = sorted((m for m in methods if selected_flow_method(m.name)), key=lambda m: (m.address, m.name))
    accessors = sorted((m for m in methods if protection_accessor(m.name)), key=lambda m: (m.address, m.name))
    flow_edges, accessor_xrefs = scan_edges(args.lib, selected, accessors, by_start, boundaries)

    report = {
        "schema": 1,
        "target": "member/protect_card",
        "selected_methods": [
            {"rva": m.address, "name": m.name, "signature": m.signature} for m in selected
        ],
        "protection_accessors": [
            {"rva": m.address, "name": m.name, "signature": m.signature} for m in accessors
        ],
        "flow_edges": flow_edges,
        "protection_accessor_direct_xrefs": accessor_xrefs,
        "limits": {
            "direct_branches_only": True,
            "indirect_dispatch_recovered": False,
            "runtime_acceptance": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    important = [
        row for row in flow_edges
        if any(
            token in " ".join(row["targets"])
            for token in ("WorkCardData", "NetworkTask", "BaseTask", "SetResponseProtect", "get_isProtect")
        )
    ]
    print(json.dumps({
        "selected_method_count": len(selected),
        "accessor_count": len(accessors),
        "important_flow_edges": important,
        "accessor_xrefs": accessor_xrefs,
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
