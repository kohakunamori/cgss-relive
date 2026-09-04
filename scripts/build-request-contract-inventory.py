#!/usr/bin/env python3
"""Build the C2 request-side contract inventory from sanitized C0/C1 evidence.

This is intentionally a *candidate* inventory, not a required-field schema.  It
selects only C0 methods classified request-side, preserves their signatures/RVAs,
collects field/header/path literals referenced by those methods, and joins them to
C1 endpoint/task bindings.  A later native data-flow pass will distinguish required,
conditional and defaulted request fields.

No naming-only C1 candidate is treated as an endpoint binding here.
"""
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 1


def unique_literals(methods: list[dict[str, Any]], kind: str) -> list[str]:
    return sorted({
        str(item["value"])
        for method in methods
        for item in method.get("contract_literals", [])
        if item.get("kind") == kind
    })


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--endpoint-contracts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    endpoints = json.loads(args.endpoint_contracts.read_text(encoding="utf-8"))

    tasks: dict[str, dict[str, Any]] = {}
    for task in inventory.get("tasks", []):
        request_methods = [m for m in task.get("role_methods", []) if m.get("role") == "request"]
        if not request_methods:
            continue
        tasks[str(task["type"])] = {
            "task": str(task["type"]),
            "base": task.get("base"),
            "request_methods": [
                {
                    "name": str(method["name"]),
                    "member": str(method["member"]),
                    "rva": int(method["rva"]),
                    "signature": method.get("signature"),
                    "field_key_candidates": sorted({
                        str(item["value"])
                        for item in method.get("contract_literals", [])
                        if item.get("kind") == "field_key"
                    }),
                    "header_candidates": sorted({
                        str(item["value"])
                        for item in method.get("contract_literals", [])
                        if item.get("kind") == "header"
                    }),
                    "api_path_literals": sorted({
                        str(item["value"])
                        for item in method.get("contract_literals", [])
                        if item.get("kind") == "api_path"
                    }),
                }
                for method in request_methods
            ],
            "field_key_candidates": unique_literals(request_methods, "field_key"),
            "header_candidates": unique_literals(request_methods, "header"),
            "api_path_literals": unique_literals(request_methods, "api_path"),
        }

    endpoint_rows = []
    bound_tasks = set()
    for endpoint in endpoints.get("endpoints", []):
        if endpoint.get("status") != "proven-static":
            continue
        request_tasks = []
        for binding in endpoint.get("task_bindings", []):
            task_name = str(binding["task"])
            if task_name not in tasks:
                continue
            bound_tasks.add(task_name)
            request_tasks.append({
                **tasks[task_name],
                "binding_evidence": str(binding.get("evidence", "")),
            })
        endpoint_rows.append({
            "group": str(endpoint["group"]),
            "key": int(endpoint["key"]),
            "enum": str(endpoint["enum"]),
            "route": str(endpoint["route"]),
            "request_tasks": request_tasks,
            "has_request_surface": bool(request_tasks),
        })

    field_frequency: dict[str, int] = defaultdict(int)
    for task in tasks.values():
        for field in task["field_key_candidates"]:
            field_frequency[field] += 1

    report = {
        "schema": SCHEMA,
        "scope": "C2 broad request-side candidate inventory; fields are not yet classified required/conditional/default",
        "request_task_count": len(tasks),
        "request_method_count": sum(len(task["request_methods"]) for task in tasks.values()),
        "request_tasks_bound_to_proven_endpoints": len(bound_tasks),
        "proven_endpoint_count": len(endpoint_rows),
        "proven_endpoints_with_request_surface": sum(row["has_request_surface"] for row in endpoint_rows),
        "unique_field_key_candidate_count": len(field_frequency),
        "field_key_frequency": dict(sorted(field_frequency.items(), key=lambda item: (-item[1], item[0]))),
        "tasks": sorted(tasks.values(), key=lambda row: row["task"]),
        "endpoints": endpoint_rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = [
            "# C2 request-side contract inventory",
            "",
            "This is a broad static candidate inventory. Fields are **not** yet marked required/conditional/default.",
            "",
            f"- request tasks: **{report['request_task_count']}**",
            f"- request-role methods: **{report['request_method_count']}**",
            f"- request tasks bound to proven endpoints: **{report['request_tasks_bound_to_proven_endpoints']}**",
            f"- proven endpoints represented: **{report['proven_endpoint_count']}**",
            f"- proven endpoints with request-side methods: **{report['proven_endpoints_with_request_surface']}**",
            f"- unique request field-key candidates: **{report['unique_field_key_candidate_count']}**",
            "",
            "## Highest-field-count request tasks",
            "",
        ]
        ranked = sorted(tasks.values(), key=lambda row: (len(row["field_key_candidates"]), len(row["request_methods"])), reverse=True)
        for task in ranked[:100]:
            fields = ", ".join(f"`{x}`" for x in task["field_key_candidates"][:16]) or "(no field literal recovered)"
            lines.append(f"- `{task['task']}` — {fields}")
        lines += [
            "",
            "Next C2 pass: native data-flow around request parameter insertion calls to classify field presence semantics.",
            "",
        ]
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
