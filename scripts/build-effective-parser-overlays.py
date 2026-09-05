#!/usr/bin/env python3
"""C13: combine C11b and C12 endpoint base-parser overlays with provenance intact.

This is an *effective parser surface* supplement to C6/C9. It does not rewrite
``response_fields`` and it does not convert base-parser field names into response
values. Every overlay keeps one of two evidence classes:

- ``direct-BL``: exact ARM64 BL from a concrete C6-bound task parser to the base
  parser/helper, deduplicated by endpoint/base-parser identity (C11b);
- ``inherited-no-override``: exact IL2CPP type inheritance to a base ``Parse``
  with no concrete ``Parse`` ScriptMethod override (C12).

The two source sets are expected to be disjoint at base-parser RVA because C12 is
restricted to C11 methods with zero direct xrefs. Any unexpected overlap is kept
only when the endpoint/base parser identity and field surface agree exactly, and
both provenance records are retained.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 1


def load(path: Path, schema: int = 1) -> dict[str, Any]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema") != schema:
        raise RuntimeError(f"unsupported schema in {path}: {doc.get('schema')!r}")
    return doc


def endpoint_identity(endpoint: dict[str, Any]) -> tuple[Any, ...]:
    return (
        int(endpoint["endpoint_id"]),
        str(endpoint["route"]),
        endpoint.get("enum"),
        endpoint.get("group"),
        endpoint.get("key"),
        endpoint.get("status"),
        endpoint.get("task"),
    )


def canonical_fields(fields: list[dict[str, Any]]) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                str(field["field"]),
                field.get("requiredness"),
                tuple(sorted(str(x) for x in field.get("value_types", []))),
            )
            for field in fields
        )
    )


def add_overlay(
    grouped: dict[tuple[int, int], dict[str, Any]],
    *,
    endpoint: dict[str, Any],
    base_task: str,
    base_parser_method: str,
    base_parser_rva: int,
    fields: list[dict[str, Any]],
    provenance: dict[str, Any],
) -> None:
    key = (int(endpoint["endpoint_id"]), int(base_parser_rva))
    row = grouped.get(key)
    if row is None:
        grouped[key] = {
            "endpoint": endpoint,
            "base_task": base_task,
            "base_parser_method": base_parser_method,
            "base_parser_rva": int(base_parser_rva),
            "fields": fields,
            "provenance": [provenance],
        }
        return
    if endpoint_identity(row["endpoint"]) != endpoint_identity(endpoint):
        raise RuntimeError(f"C13 endpoint identity drift for overlay key {key}")
    if row["base_task"] != base_task or row["base_parser_method"] != base_parser_method:
        raise RuntimeError(f"C13 base parser identity drift for overlay key {key}")
    if canonical_fields(row["fields"]) != canonical_fields(fields):
        raise RuntimeError(f"C13 field surface drift for overlay key {key}")
    row["provenance"].append(provenance)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--c11b", type=Path, required=True)
    parser.add_argument("--c12", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    c11b = load(args.c11b)
    c12 = load(args.c12)
    grouped: dict[tuple[int, int], dict[str, Any]] = {}

    for source in c11b.get("overlays", []):
        add_overlay(
            grouped,
            endpoint=dict(source["endpoint"]),
            base_task=str(source["base_task"]),
            base_parser_method=str(source["base_parser_method"]),
            base_parser_rva=int(source["base_parser_rva"]),
            fields=list(source["fields"]),
            provenance={
                "kind": "direct-BL",
                "callers": source.get("callers", []),
                "evidence": source.get("evidence"),
            },
        )

    for source in c12.get("inherited_relations", []):
        add_overlay(
            grouped,
            endpoint=dict(source["endpoint"]),
            base_task=str(source["base_task"]),
            base_parser_method=str(source["base_parser_method"]),
            base_parser_rva=int(source["base_parser_rva"]),
            fields=list(source["fields"]),
            provenance={
                "kind": "inherited-no-override",
                "concrete_task": source.get("concrete_task"),
                "evidence": source.get("inheritance_chain_evidence"),
            },
        )

    overlays = [grouped[key] for key in sorted(grouped)]
    endpoint_ids = sorted({int(row["endpoint"]["endpoint_id"]) for row in overlays})
    provenance_counts = Counter(
        str(provenance["kind"])
        for row in overlays
        for provenance in row["provenance"]
    )
    relation_provenance_counts = Counter(
        "+".join(sorted({str(p["kind"]) for p in row["provenance"]}))
        for row in overlays
    )
    base_counts = Counter(str(row["base_task"]) for row in overlays)
    field_links = sum(len(row["fields"]) for row in overlays)
    requiredness = Counter(
        str(field.get("requiredness") or "unknown")
        for row in overlays
        for field in row["fields"]
    )
    endpoint_overlay_counts = Counter(int(row["endpoint"]["endpoint_id"]) for row in overlays)
    common_envelope = [
        row for row in overlays
        if row["base_task"] == "Stage.BaseTask" and row["base_parser_method"] == "Stage.BaseTask$$Parse"
    ]
    report = {
        "schema": SCHEMA,
        "scope": (
            "C13 effective endpoint base-parser overlays; provenance-preserving supplement to C6/C9, "
            "not concrete response_fields and not response-body generation"
        ),
        "source_c11b_overlay_relation_count": int(c11b.get("overlay_relation_count", 0)),
        "source_c12_inherited_relation_count": int(c12.get("inherited_relation_count", 0)),
        "overlay_relation_count": len(overlays),
        "overlay_endpoint_count": len(endpoint_ids),
        "overlay_field_link_count": field_links,
        "base_task_relation_counts": dict(sorted(base_counts.items())),
        "provenance_record_counts": dict(sorted(provenance_counts.items())),
        "relation_provenance_counts": dict(sorted(relation_provenance_counts.items())),
        "overlay_requiredness_counts": dict(sorted(requiredness.items())),
        "endpoints_with_multiple_base_parsers": sum(count > 1 for count in endpoint_overlay_counts.values()),
        "common_envelope_overlay_endpoint_count": len({int(row["endpoint"]["endpoint_id"]) for row in common_envelope}),
        "residual_unmapped_methods": [
            {
                "base_task": str(row["base_task"]),
                "base_parser_method": str(row["base_parser_method"]),
                "base_parser_rva": int(row["base_parser_rva"]),
                "fields": row["fields"],
                "reason": "no direct xref and not eligible for inherited Parse propagation",
            }
            for row in c12.get("non_parse_residuals", [])
        ],
        "overlays": overlays,
    }
    report["residual_unmapped_method_count"] = len(report["residual_unmapped_methods"])

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = [
            "# C13 effective base-parser overlays", "",
            "Provenance-preserving supplement to C6/C9; no field is converted into a fabricated response value.", "",
            f"- direct C11b relations: **{report['source_c11b_overlay_relation_count']}**",
            f"- inherited C12 relations: **{report['source_c12_inherited_relation_count']}**",
            f"- combined endpoint/base-parser relations: **{report['overlay_relation_count']}**",
            f"- endpoints covered: **{report['overlay_endpoint_count']}**",
            f"- field links: **{report['overlay_field_link_count']}**",
            f"- endpoints with common `Stage.BaseTask.Parse` envelope overlay: **{report['common_envelope_overlay_endpoint_count']}**",
            f"- residual unmapped base methods: **{report['residual_unmapped_method_count']}**", "",
            "## Evidence classes", "",
        ]
        lines += [f"- `{kind}` records: **{count}**" for kind, count in report["provenance_record_counts"].items()]
        lines += ["", "## Base parser families", ""]
        lines += [f"- `{name}`: **{count}** relations" for name, count in report["base_task_relation_counts"].items()]
        lines += ["", "## Residual unmapped methods", ""]
        if report["residual_unmapped_methods"]:
            lines += [f"- `{row['base_parser_method']}`" for row in report["residual_unmapped_methods"]]
        else:
            lines.append("- none")
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({k: report[k] for k in (
        "source_c11b_overlay_relation_count", "source_c12_inherited_relation_count",
        "overlay_relation_count", "overlay_endpoint_count", "overlay_field_link_count",
        "provenance_record_counts", "base_task_relation_counts",
        "common_envelope_overlay_endpoint_count", "residual_unmapped_method_count",
    )}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
