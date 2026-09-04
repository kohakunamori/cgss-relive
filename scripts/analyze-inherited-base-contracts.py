#!/usr/bin/env python3
"""C12: recover residual base ``Parse`` contracts via exact IL2CPP inheritance.

C11 direct-xref evidence cannot see a virtual method call when a concrete task
inherits a base ``Parse`` implementation without emitting a native callsite to
that method.  This analyzer uses Il2CppDumper ``dump.cs`` only as a type-metadata
source and ``script.json`` as the concrete managed-method inventory.

A residual base Parse contract is proposed for a C6-bound task only when:

1. dump.cs proves the task transitively derives from the base task;
2. the concrete task has no own ``$$Parse`` ScriptMethod entry;
3. the base Parse method is one of C11's methods with no direct native xref.

This is kept as an inheritance-overlay provenance class. Helpers such as
``EventInfoParse`` are never propagated by inheritance alone, and a derived task
with its own Parse is explicitly rejected rather than guessed to call base.Parse.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 1

NAMESPACE_RE = re.compile(r"^namespace\s+([A-Za-z0-9_.]+)\s*$")
TYPE_RE = re.compile(
    r"^(?:\[[^]]+\]\s*)*(?:(?:public|private|protected|internal|abstract|sealed|static|partial|new)\s+)*"
    r"(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*(?:`\d+)?)"
    r"(?:<[^>{}]+>)?\s*(?::\s*([^\{]+))?\s*$"
)


def normalize_type_token(value: str) -> str:
    value = value.strip()
    value = re.sub(r"<.*>", "", value)
    value = value.replace("global::", "")
    return value.strip()


def parse_inheritance(path: Path) -> dict[str, str | None]:
    """Extract best-effort full type -> direct base from Il2CppDumper dump.cs."""
    namespace = ""
    pending_namespace = False
    inheritance: dict[str, str | None] = {}
    for raw in path.read_text(encoding="utf-8", errors="strict").splitlines():
        line = raw.strip()
        match = NAMESPACE_RE.match(line)
        if match:
            namespace = match.group(1)
            pending_namespace = True
            continue
        if pending_namespace and line == "{":
            pending_namespace = False
            continue
        match = TYPE_RE.match(line)
        if not match:
            continue
        short_name = normalize_type_token(match.group(1))
        full_name = f"{namespace}.{short_name}" if namespace else short_name
        raw_bases = match.group(2)
        base: str | None = None
        if raw_bases:
            first = normalize_type_token(raw_bases.split(",", 1)[0])
            if first and "." not in first and namespace:
                first = f"{namespace}.{first}"
            base = first or None
        inheritance[full_name] = base
    return inheritance


def derives_from(type_name: str, base_name: str, inheritance: dict[str, str | None]) -> bool:
    seen: set[str] = set()
    current = type_name
    while current and current not in seen:
        seen.add(current)
        parent = inheritance.get(current)
        if parent == base_name:
            return True
        current = parent or ""
    return False


def load_script_owners(path: Path) -> dict[str, set[str]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, set[str]] = defaultdict(set)
    for row in doc.get("ScriptMethod", []):
        name = str(row.get("Name") or "")
        if "$$" not in name:
            continue
        owner, method = name.split("$$", 1)
        out[owner].add(method)
    return dict(out)


def load_c6(path: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[tuple[str, str], dict[str, Any]]]:
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    db.row_factory = sqlite3.Row
    try:
        if db.execute("pragma quick_check").fetchone()[0] != "ok":
            raise RuntimeError("C6 quick_check failed")
        bindings: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in db.execute(
            """
            SELECT tb.endpoint_id,tb.route,tb.enum,tb.task,tb.evidence,
                   e.status,e.group_name,e.api_key
            FROM task_bindings tb JOIN endpoints e ON e.id=tb.endpoint_id
            ORDER BY tb.task,tb.endpoint_id,tb.evidence
            """
        ):
            bindings[str(row["task"])].append({
                "endpoint_id": int(row["endpoint_id"]),
                "route": str(row["route"]),
                "enum": str(row["enum"]) if row["enum"] is not None else None,
                "task": str(row["task"]),
                "task_binding_evidence": str(row["evidence"]) if row["evidence"] is not None else None,
                "status": str(row["status"]) if row["status"] is not None else None,
                "group": str(row["group_name"]) if row["group_name"] is not None else None,
                "key": int(row["api_key"]) if row["api_key"] is not None else None,
            })
        contracts: dict[tuple[str, str], dict[str, Any]] = {}
        for row in db.execute(
            """
            SELECT task,method,method_rva,field,requiredness,value_types_json
            FROM response_fields
            WHERE endpoint_id IS NULL AND method_rva IS NOT NULL
            ORDER BY task,method,field
            """
        ):
            task = str(row["task"])
            method = str(row["method"])
            key = (task, method)
            entry = contracts.setdefault(key, {
                "base_task": task,
                "base_parser_method": method,
                "base_parser_rva": int(row["method_rva"]),
                "fields": [],
            })
            if entry["base_parser_rva"] != int(row["method_rva"]):
                raise RuntimeError(f"method identity has multiple RVAs: {key}")
            entry["fields"].append({
                "field": str(row["field"]),
                "requiredness": str(row["requiredness"]) if row["requiredness"] is not None else None,
                "value_types": json.loads(row["value_types_json"] or "[]"),
            })
        return dict(bindings), contracts
    finally:
        db.close()


def load_c11_no_xref(path: Path) -> set[tuple[str, int]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema") != 1:
        raise RuntimeError(f"unsupported C11 schema: {doc.get('schema')!r}")
    result: set[tuple[str, int]] = set()
    for value in doc.get("methods_without_direct_xref", []):
        text = str(value)
        if "@0x" not in text:
            continue
        method, raw = text.rsplit("@0x", 1)
        result.add((method, int(raw, 16)))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--c6-sqlite", type=Path, required=True)
    parser.add_argument("--c11", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    inheritance = parse_inheritance(args.dump_cs)
    owner_methods = load_script_owners(args.script_json)
    task_bindings, contracts = load_c6(args.c6_sqlite)
    no_xref = load_c11_no_xref(args.c11)

    candidates: list[dict[str, Any]] = []
    overrides: list[dict[str, Any]] = []
    non_parse_residual: list[dict[str, Any]] = []
    considered_bases: set[str] = set()

    for (base_task, full_method), contract in sorted(contracts.items()):
        if "$$" not in full_method:
            continue
        owner, short_name = full_method.split("$$", 1)
        if owner != base_task:
            continue
        identity = (full_method, int(contract["base_parser_rva"]))
        if identity not in no_xref:
            continue
        considered_bases.add(base_task)
        if short_name != "Parse":
            non_parse_residual.append(contract)
            continue

        for concrete_task, endpoints in sorted(task_bindings.items()):
            if concrete_task == base_task or not derives_from(concrete_task, base_task, inheritance):
                continue
            own_methods = owner_methods.get(concrete_task, set())
            if "Parse" in own_methods:
                overrides.append({
                    "base_task": base_task,
                    "base_parser_method": full_method,
                    "base_parser_rva": int(contract["base_parser_rva"]),
                    "concrete_task": concrete_task,
                    "endpoint_candidates": endpoints,
                    "reason": "concrete derived task has its own ScriptMethod Parse; inherited base Parse not assumed",
                })
                continue
            for endpoint in endpoints:
                candidates.append({
                    "endpoint": endpoint,
                    "base_task": base_task,
                    "base_parser_method": full_method,
                    "base_parser_rva": int(contract["base_parser_rva"]),
                    "fields": contract["fields"],
                    "concrete_task": concrete_task,
                    "inheritance_chain_evidence": (
                        "Il2CppDumper dump.cs transitive type inheritance plus absence of concrete $$Parse ScriptMethod"
                    ),
                })

    # Deduplicate endpoints that have multiple C6 binding evidence rows for the same concrete task.
    grouped: dict[tuple[int, int, str], dict[str, Any]] = {}
    for row in candidates:
        endpoint = row["endpoint"]
        key = (
            int(endpoint["endpoint_id"]),
            int(row["base_parser_rva"]),
            str(row["concrete_task"]),
        )
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = row
        else:
            # Same endpoint/task may have multiple binding evidence strings; keep the stronger-looking
            # exact row only when all endpoint identity fields agree, otherwise fail closed.
            for field in ("route", "enum", "group", "key", "status", "task"):
                if existing["endpoint"].get(field) != endpoint.get(field):
                    raise RuntimeError(f"endpoint identity drift for inherited relation: {key}")
    candidates = [grouped[key] for key in sorted(grouped)]

    field_links = sum(len(row["fields"]) for row in candidates)
    endpoint_ids = sorted({int(row["endpoint"]["endpoint_id"]) for row in candidates})
    base_counts = Counter(str(row["base_task"]) for row in candidates)
    requiredness = Counter(
        str(field.get("requiredness") or "unknown")
        for row in candidates
        for field in row["fields"]
    )
    report = {
        "schema": SCHEMA,
        "scope": (
            "C12 inherited base Parse overlays: IL2CPP transitive inheritance + no concrete Parse override; "
            "separate provenance, no helper/inheritance guessing"
        ),
        "dump_type_count": len(inheritance),
        "c11_no_direct_xref_method_count": len(no_xref),
        "considered_base_task_count": len(considered_bases),
        "inherited_relation_count": len(candidates),
        "inherited_endpoint_count": len(endpoint_ids),
        "inherited_field_link_count": field_links,
        "base_task_relation_counts": dict(sorted(base_counts.items())),
        "inherited_requiredness_counts": dict(sorted(requiredness.items())),
        "override_rejection_count": len(overrides),
        "non_parse_residual_count": len(non_parse_residual),
        "inherited_relations": candidates,
        "override_rejections": overrides,
        "non_parse_residuals": non_parse_residual,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = [
            "# C12 inherited base Parse overlays", "",
            "Type-inheritance evidence only; concrete Parse overrides are rejected rather than guessed.", "",
            f"- parsed IL2CPP types: **{report['dump_type_count']}**",
            f"- C11 methods with no direct xref: **{report['c11_no_direct_xref_method_count']}**",
            f"- inherited endpoint/base-parser relations: **{report['inherited_relation_count']}**",
            f"- endpoints covered: **{report['inherited_endpoint_count']}**",
            f"- inherited field links: **{report['inherited_field_link_count']}**",
            f"- concrete Parse override rejections: **{report['override_rejection_count']}**",
            f"- non-Parse residual methods deliberately not propagated: **{report['non_parse_residual_count']}**", "",
            "## Base task relation counts", "",
        ]
        lines += [f"- `{name}`: **{count}**" for name, count in report["base_task_relation_counts"].items()]
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({k: report[k] for k in (
        "dump_type_count", "c11_no_direct_xref_method_count", "considered_base_task_count",
        "inherited_relation_count", "inherited_endpoint_count", "inherited_field_link_count",
        "base_task_relation_counts", "override_rejection_count", "non_parse_residual_count",
    )}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
