#!/usr/bin/env python3
"""C11b: refine C11 direct-caller evidence into endpoint base-parser overlays.

The output deliberately does not rewrite C6 ``response_fields``.  A field read by
``Stage.BaseTask.Parse`` or another reusable base parser is a different provenance
class from a field read by the concrete endpoint task itself.  This overlay keeps
that distinction while giving later runtime/model generation a deterministic
endpoint -> invoked base parser -> field surface.

Promotion requires:
- C11 exact direct ARM64 BL evidence;
- a uniquely mapped managed caller whose owner already has a C6 endpoint binding;
- a caller method whose managed name contains ``Parse``.

Multiple concrete Parse callers from the same endpoint to the same base parser are
deduplicated into one overlay relation while all caller/callsite evidence is kept.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 1


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def endpoint_identity(endpoint: dict[str, Any]) -> tuple[Any, ...]:
    return (
        int(endpoint["endpoint_id"]),
        str(endpoint["route"]),
        endpoint.get("enum"),
        endpoint.get("group"),
        endpoint.get("key"),
        endpoint.get("status"),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--c11", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    source = load(args.c11)
    if source.get("schema") != 1:
        raise RuntimeError(f"unsupported C11 schema: {source.get('schema')!r}")

    grouped: dict[tuple[int, int], dict[str, Any]] = {}
    rejected: list[dict[str, Any]] = []
    for relation in source.get("candidate_relations", []):
        caller_method = str(relation.get("caller_method") or "")
        short_name = caller_method.split("$$", 1)[1] if "$$" in caller_method else caller_method
        if relation.get("edge_kind") not in (None, "BL"):
            rejected.append({"reason": "not-direct-BL", "relation": relation})
            continue
        if "Parse" not in short_name:
            rejected.append({"reason": "caller-name-not-parser", "relation": relation})
            continue
        endpoint = dict(relation["endpoint"])
        key = (int(endpoint["endpoint_id"]), int(relation["base_parser_rva"]))
        row = grouped.setdefault(key, {
            "endpoint": endpoint,
            "base_task": str(relation["base_task"]),
            "base_parser_method": str(relation["base_parser_method"]),
            "base_parser_rva": int(relation["base_parser_rva"]),
            "fields": relation["fields"],
            "callers": {},
            "evidence": (
                "deduplicated endpoint/base-parser overlay backed by exact ARM64 BL from one or more "
                "managed Parse callers whose owner has an existing C6 endpoint binding"
            ),
        })
        if endpoint_identity(row["endpoint"]) != endpoint_identity(endpoint):
            raise RuntimeError(f"endpoint identity drift inside C11 overlay key: {key}")
        if row["base_task"] != relation["base_task"] or row["base_parser_method"] != relation["base_parser_method"]:
            raise RuntimeError(f"base parser identity drift inside C11 overlay key: {key}")
        if row["fields"] != relation["fields"]:
            raise RuntimeError(f"base parser field surface drift inside C11 overlay key: {key}")
        caller_key = (str(relation["caller_method"]), int(relation["caller_rva"]))
        caller = row["callers"].setdefault(caller_key, {
            "method": str(relation["caller_method"]),
            "rva": int(relation["caller_rva"]),
            "callsite_rvas": [],
        })
        caller["callsite_rvas"].extend(int(x) for x in relation.get("callsite_rvas", []))

    overlays: list[dict[str, Any]] = []
    for key in sorted(grouped):
        row = grouped[key]
        callers = []
        for caller_key in sorted(row["callers"]):
            caller = row["callers"][caller_key]
            caller["callsite_rvas"] = sorted(set(caller["callsite_rvas"]))
            callers.append(caller)
        overlays.append({
            "endpoint": row["endpoint"],
            "base_task": row["base_task"],
            "base_parser_method": row["base_parser_method"],
            "base_parser_rva": row["base_parser_rva"],
            "fields": row["fields"],
            "callers": callers,
            "evidence": row["evidence"],
        })

    endpoints = {int(row["endpoint"]["endpoint_id"]) for row in overlays}
    base_tasks = sorted({str(row["base_task"]) for row in overlays})
    field_link_count = sum(len(row["fields"]) for row in overlays)
    caller_count = sum(len(row["callers"]) for row in overlays)
    requiredness = Counter(
        str(field.get("requiredness") or "unknown")
        for row in overlays
        for field in row["fields"]
    )
    endpoint_overlay_counts = Counter(int(row["endpoint"]["endpoint_id"]) for row in overlays)

    report = {
        "schema": SCHEMA,
        "scope": (
            "C11b exact base-parser overlays; separate provenance from concrete C6 response_fields; "
            "not automatic response-body generation"
        ),
        "source_c11_candidate_relation_count": int(source.get("candidate_relation_count", 0)),
        "overlay_relation_count": len(overlays),
        "overlay_endpoint_count": len(endpoints),
        "overlay_field_link_count": field_link_count,
        "overlay_managed_caller_count": caller_count,
        "overlay_base_task_count": len(base_tasks),
        "overlay_base_tasks": base_tasks,
        "overlay_requiredness_counts": dict(sorted(requiredness.items())),
        "endpoints_with_multiple_base_parsers": sum(count > 1 for count in endpoint_overlay_counts.values()),
        "rejected_relation_count": len(rejected),
        "rejected_relations": rejected,
        "overlays": overlays,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = [
            "# C11b exact base-parser overlays", "",
            "Direct-BL parser-call evidence, kept separate from concrete C6 response fields.", "",
            f"- source C11 candidate relations: **{report['source_c11_candidate_relation_count']}**",
            f"- deduplicated endpoint/base-parser overlays: **{report['overlay_relation_count']}**",
            f"- endpoints covered: **{report['overlay_endpoint_count']}**",
            f"- base parser field links: **{report['overlay_field_link_count']}**",
            f"- managed caller identities retained: **{report['overlay_managed_caller_count']}**",
            f"- base task families: **{report['overlay_base_task_count']}**",
            f"- rejected C11 candidate relations: **{report['rejected_relation_count']}**", "",
            "## Base task families", "",
        ]
        lines += [f"- `{name}`" for name in base_tasks]
        lines += ["", "## Requiredness over overlay field links", ""]
        lines += [f"- `{kind}`: **{count}**" for kind, count in report["overlay_requiredness_counts"].items()]
        lines += [
            "",
            "These fields remain an overlay provenance class; do not merge them into concrete endpoint parser fields without preserving that distinction.",
        ]
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({k: report[k] for k in (
        "source_c11_candidate_relation_count", "overlay_relation_count", "overlay_endpoint_count",
        "overlay_field_link_count", "overlay_managed_caller_count", "overlay_base_task_count",
        "overlay_requiredness_counts", "endpoints_with_multiple_base_parsers", "rejected_relation_count",
    )}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
