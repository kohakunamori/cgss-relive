#!/usr/bin/env python3
"""C11: trace C6 unbound base-parser response contracts to concrete endpoint tasks.

The 11.6.3 C6 DB currently has a small residual set of response contracts whose
owner is a reusable BaseTask/BaseResultTask rather than a concrete network task.
This analyzer does *not* propagate those fields by inheritance/name similarity.
Instead it scans the exact ARM64 image for direct branch immediates to each
unbound parser method RVA, maps each callsite to the exact Il2CppDumper managed
caller boundary, and only annotates a concrete endpoint candidate when the caller
owner itself has an existing exact C6 task binding.

This report is discovery evidence.  A later promotion step may require a narrower
caller-method policy (for example Parse/response-flow callers) after the real
artifact is inspected.  Indirect BLR/BR dispatch is intentionally not recovered.
"""
from __future__ import annotations

import argparse
import bisect
import json
import sqlite3
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

SCHEMA = 1
PF_X = 0x1
BRANCH_MASK = 0xFC000000
BL_OPCODE = 0x94000000
B_OPCODE = 0x14000000


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: str | None

    @property
    def owner(self) -> str | None:
        if "$$" not in self.name:
            return None
        return self.name.split("$$", 1)[0]

    @property
    def short_name(self) -> str | None:
        if "$$" not in self.name:
            return None
        return self.name.split("$$", 1)[1]


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def load_methods(path: Path) -> tuple[dict[int, list[Method]], list[int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    by_start: dict[int, list[Method]] = defaultdict(list)
    boundaries: set[int] = set()
    for row in data.get("ScriptMethod", []):
        address = as_int(row.get("Address", 0))
        name = str(row.get("Name") or "")
        if address <= 0 or not name:
            continue
        by_start[address].append(Method(address, name, row.get("Signature")))
        boundaries.add(address)
    for value in data.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            boundaries.add(address)
    for rows in by_start.values():
        rows.sort(key=lambda item: (item.name, item.signature or ""))
    return dict(by_start), sorted(boundaries)


def signed_imm26(word: int) -> int:
    imm26 = word & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return imm26 << 2


def scan_direct_xrefs(lib_path: Path, targets: set[int]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    hits: list[dict[str, Any]] = []
    executable_segments = 0
    executable_bytes = 0
    with lib_path.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & PF_X):
                continue
            executable_segments += 1
            vaddr = int(segment["p_vaddr"])
            stream.seek(int(segment["p_offset"]))
            data = stream.read(int(segment["p_filesz"]))
            usable = len(data) - len(data) % 4
            executable_bytes += usable
            for index, (word,) in enumerate(struct.iter_unpack("<I", data[:usable])):
                opcode = word & BRANCH_MASK
                if opcode not in (BL_OPCODE, B_OPCODE):
                    continue
                site = vaddr + index * 4
                target = site + signed_imm26(word)
                if target in targets:
                    hits.append({
                        "callsite_rva": site,
                        "target_rva": target,
                        "edge_kind": "BL" if opcode == BL_OPCODE else "B-tail",
                    })
    hits.sort(key=lambda row: (row["callsite_rva"], row["target_rva"], row["edge_kind"]))
    return hits, {
        "executable_segment_count": executable_segments,
        "executable_bytes_scanned": executable_bytes,
    }


def containing_methods(address: int, boundaries: list[int], by_start: dict[int, list[Method]]) -> tuple[int | None, list[Method]]:
    index = bisect.bisect_right(boundaries, address) - 1
    if index < 0:
        return None, []
    start = boundaries[index]
    return start, by_start.get(start, [])


def load_c6(path: Path) -> tuple[dict[int, dict[str, Any]], dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    db.row_factory = sqlite3.Row
    try:
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RuntimeError("C6 sqlite quick_check failed")
        method_contracts: dict[int, dict[str, Any]] = {}
        rows = db.execute(
            """
            SELECT id,task,method,method_rva,field,requiredness,value_types_json
            FROM response_fields
            WHERE endpoint_id IS NULL AND method_rva IS NOT NULL
            ORDER BY method_rva,id
            """
        ).fetchall()
        for row in rows:
            rva = int(row["method_rva"])
            entry = method_contracts.setdefault(rva, {
                "task": str(row["task"]),
                "method": str(row["method"]),
                "method_rva": rva,
                "fields": [],
            })
            if entry["task"] != str(row["task"]) or entry["method"] != str(row["method"]):
                raise RuntimeError(f"unbound method RVA shared by multiple C6 parser identities: {rva:#x}")
            entry["fields"].append({
                "field": str(row["field"]),
                "requiredness": str(row["requiredness"]) if row["requiredness"] is not None else None,
                "value_types": json.loads(row["value_types_json"] or "[]"),
            })

        task_bindings: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in db.execute(
            """
            SELECT tb.endpoint_id,tb.route,tb.enum,tb.task,tb.evidence,
                   e.status,e.group_name,e.api_key
            FROM task_bindings tb JOIN endpoints e ON e.id=tb.endpoint_id
            ORDER BY tb.task,tb.endpoint_id,tb.evidence
            """
        ):
            task_bindings[str(row["task"])].append({
                "endpoint_id": int(row["endpoint_id"]),
                "route": str(row["route"]),
                "enum": str(row["enum"]) if row["enum"] is not None else None,
                "task": str(row["task"]),
                "task_binding_evidence": str(row["evidence"]) if row["evidence"] is not None else None,
                "status": str(row["status"]) if row["status"] is not None else None,
                "group": str(row["group_name"]) if row["group_name"] is not None else None,
                "key": int(row["api_key"]) if row["api_key"] is not None else None,
            })
        endpoints = [dict(row) for row in db.execute("SELECT * FROM endpoints ORDER BY id")]
        return method_contracts, dict(task_bindings), endpoints
    finally:
        db.close()


def response_flow_kind(short_name: str | None) -> str:
    if not short_name:
        return "unknown"
    if short_name == "Parse" or short_name.startswith("Parse"):
        return "parse"
    if short_name.startswith(("OnSuccess", "OnSucceeded", "OnComplete", "OnCompleted", "Success")):
        return "response-callback"
    return "other"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--c6-sqlite", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    contracts, task_bindings, _ = load_c6(args.c6_sqlite)
    by_start, boundaries = load_methods(args.script_json)
    hits, scan_meta = scan_direct_xrefs(args.lib, set(contracts))

    xrefs: list[dict[str, Any]] = []
    exact_bound_bl: list[dict[str, Any]] = []
    for hit in hits:
        caller_start, callers = containing_methods(int(hit["callsite_rva"]), boundaries, by_start)
        contract = contracts[int(hit["target_rva"])]
        caller_rows = []
        for caller in callers:
            owner = caller.owner
            bindings = task_bindings.get(owner or "", [])
            row = {
                "caller_method": caller.name,
                "caller_rva": caller.address,
                "caller_signature": caller.signature,
                "caller_owner": owner,
                "caller_short_name": caller.short_name,
                "response_flow_kind": response_flow_kind(caller.short_name),
                "endpoint_candidates": bindings,
            }
            caller_rows.append(row)
            if hit["edge_kind"] == "BL" and len(callers) == 1 and bindings:
                exact_bound_bl.append({
                    "base_task": contract["task"],
                    "base_parser_method": contract["method"],
                    "base_parser_rva": contract["method_rva"],
                    "field_count": len(contract["fields"]),
                    "callsite_rva": int(hit["callsite_rva"]),
                    "edge_kind": "BL",
                    **row,
                    "evidence": (
                        "exact ARM64 BL to unbound base-parser RVA from uniquely mapped managed caller; "
                        "caller owner has existing C6 endpoint task binding"
                    ),
                })
        xrefs.append({
            **hit,
            "caller_boundary_rva": caller_start,
            "base_contract": contract,
            "caller_candidates": caller_rows,
            "caller_ambiguous": len(callers) != 1,
        })

    promoted_key_rows: dict[tuple[int, int, int], dict[str, Any]] = {}
    for row in exact_bound_bl:
        for endpoint in row["endpoint_candidates"]:
            key = (int(endpoint["endpoint_id"]), int(row["base_parser_rva"]), int(row["caller_rva"]))
            promoted_key_rows.setdefault(key, {
                "endpoint": endpoint,
                "base_task": row["base_task"],
                "base_parser_method": row["base_parser_method"],
                "base_parser_rva": row["base_parser_rva"],
                "fields": contracts[int(row["base_parser_rva"])]["fields"],
                "caller_owner": row["caller_owner"],
                "caller_method": row["caller_method"],
                "caller_rva": row["caller_rva"],
                "response_flow_kind": row["response_flow_kind"],
                "callsite_rvas": [],
                "evidence": row["evidence"],
            })["callsite_rvas"].append(int(row["callsite_rva"]))

    candidate_relations = []
    for key, row in sorted(promoted_key_rows.items()):
        row["callsite_rvas"] = sorted(set(row["callsite_rvas"]))
        candidate_relations.append(row)

    field_bindings = sum(len(row["fields"]) for row in candidate_relations)
    response_flow_counts = Counter(row["response_flow_kind"] for row in candidate_relations)
    base_tasks_reached = sorted({row["base_task"] for row in candidate_relations})
    endpoint_ids_reached = sorted({int(row["endpoint"]["endpoint_id"]) for row in candidate_relations})
    method_hit_counts = Counter(int(row["target_rva"]) for row in hits)
    methods_without_direct_xref = sorted(
        {
            f"{contract['method']}@0x{rva:x}"
            for rva, contract in contracts.items()
            if method_hit_counts[rva] == 0
        }
    )

    report = {
        "schema": SCHEMA,
        "scope": (
            "C11 discovery: exact direct native xrefs from concrete C6-bound task owners to residual "
            "unbound base parser methods; not yet automatic contract propagation"
        ),
        "source_unbound_contract_count": sum(len(row["fields"]) for row in contracts.values()),
        "source_unbound_method_count": len(contracts),
        "source_unbound_base_task_count": len({row["task"] for row in contracts.values()}),
        "scan": scan_meta,
        "direct_xref_count": len(hits),
        "exact_bound_bl_xref_count": len(exact_bound_bl),
        "candidate_relation_count": len(candidate_relations),
        "candidate_field_binding_count": field_bindings,
        "candidate_endpoint_count": len(endpoint_ids_reached),
        "candidate_base_tasks": base_tasks_reached,
        "candidate_endpoint_ids": endpoint_ids_reached,
        "response_flow_kind_counts": dict(sorted(response_flow_counts.items())),
        "methods_without_direct_xref": methods_without_direct_xref,
        "candidate_relations": candidate_relations,
        "xrefs": xrefs,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = [
            "# C11 residual base-parser caller analysis", "",
            "Exact direct ARM64 xrefs only. No inheritance/name-only propagation is performed.", "",
            f"- residual C6 field contracts: **{report['source_unbound_contract_count']}**",
            f"- residual parser methods: **{report['source_unbound_method_count']}**",
            f"- direct xrefs: **{report['direct_xref_count']}**",
            f"- uniquely mapped BL xrefs from C6-bound task owners: **{report['exact_bound_bl_xref_count']}**",
            f"- candidate endpoint/base-parser relations: **{report['candidate_relation_count']}**",
            f"- candidate field bindings before response-flow refinement: **{report['candidate_field_binding_count']}**",
            f"- candidate endpoints: **{report['candidate_endpoint_count']}**", "",
            "## Caller response-flow kinds", "",
        ]
        lines += [f"- `{kind}`: **{count}**" for kind, count in report["response_flow_kind_counts"].items()]
        lines += ["", "## Base tasks reached", ""]
        lines += [f"- `{name}`" for name in report["candidate_base_tasks"]]
        lines += ["", "This artifact is discovery evidence; inspect real caller names before promoting bindings."]
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({k: report[k] for k in (
        "source_unbound_contract_count", "source_unbound_method_count", "source_unbound_base_task_count",
        "direct_xref_count", "exact_bound_bl_xref_count", "candidate_relation_count",
        "candidate_field_binding_count", "candidate_endpoint_count", "response_flow_kind_counts",
    )}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
