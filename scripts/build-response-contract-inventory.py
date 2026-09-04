#!/usr/bin/env python3
"""Build the C3 response-side contract inventory from sanitized C0/C1 evidence.

This pass selects only response-role methods (`Parse`, `SetResponseData`,
`CheckResult`, etc.), preserves their RVAs/signatures and candidate field literals,
and joins them to C1 proven endpoint/task bindings.  It is deliberately conservative:
field literals are *candidate reads*, not yet hard-read/optional classifications.

A later native helper-call/data-flow pass will classify primitive expectations,
conditional reads, arrays/nested maps and shared parser helpers.
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
        response_methods = [m for m in task.get("role_methods", []) if m.get("role") == "response"]
        if not response_methods:
            continue
        tasks[str(task["type"])] = {
            "task": str(task["type"]),
            "base": task.get("base"),
            "response_methods": [
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
                for method in response_methods
            ],
            "field_key_candidates": unique_literals(response_methods, "field_key"),
            "header_candidates": unique_literals(response_methods, "header"),
            "api_path_literals": unique_literals(response_methods, "api_path"),
        }

    endpoint_rows = []
    bound_tasks = set()
    for endpoint in endpoints.get("endpoints", []):
        if endpoint.get("status") != "proven-static":
            continue
        response_tasks = []
        for binding in endpoint.get("task_bindings", []):
            task_name = str(binding["task"])
            if task_name not in tasks:
                continue
            bound_tasks.add(task_name)
            response_tasks.append({
                **tasks[task_name],
                "binding_evidence": str(binding.get("evidence", "")),
            })
        endpoint_rows.append({
            "group": str(endpoint["group"]),
            "key": int(endpoint["key"]),
            "enum": str(endpoint["enum"]),
            "route": str(endpoint["route"]),
            "response_tasks": response_tasks,
            "has_response_surface": bool(response_tasks),
        })

    field_frequency: dict[str, int] = defaultdict(int)
    for task in tasks.values():
        for field in task["field_key_candidates"]:
            field_frequency[field] += 1

    report = {
        "schema": SCHEMA,
        "scope": "C3 broad response-side candidate inventory; fields are not yet classified hard-read/optional/conditional",
        "response_task_count": len(tasks),
        "response_method_count": sum(len(task["response_methods"]) for task in tasks.values()),
        "response_tasks_bound_to_proven_endpoints": len(bound_tasks),
        "proven_endpoint_count": len(endpoint_rows),
        "proven_endpoints_with_response_surface": sum(row["has_response_surface"] for row in endpoint_rows),
        "unique_field_key_candidate_count": len(field_frequency),
        "field_key_frequency": dict(sorted(field_frequency.items(), key=lambda item: (-item[1], item[0]))),
        "tasks": sorted(tasks.values(), key=lambda row: row["task"]),
        "endpoints": endpoint_rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = [
            "# C3 response-side contract inventory",
            "",
            "This is a broad static candidate inventory. Fields are **not** yet hard-read/optional/conditional classifications.",
            "",
            f"- response tasks: **{report['response_task_count']}**",
            f"- response-role methods: **{report['response_method_count']}**",
            f"- response tasks bound to proven endpoints: **{report['response_tasks_bound_to_proven_endpoints']}**",
            f"- proven endpoints represented: **{report['proven_endpoint_count']}**",
            f"- proven endpoints with response-side methods: **{report['proven_endpoints_with_response_surface']}**",
            f"- unique response field-key candidates: **{report['unique_field_key_candidate_count']}**",
            "",
            "## Highest-field-count response tasks",
            "",
        ]
        ranked = sorted(tasks.values(), key=lambda row: (len(row["field_key_candidates"]), len(row["response_methods"])), reverse=True)
        for task in ranked[:100]:
            fields = ", ".join(f"`{x}`" for x in task["field_key_candidates"][:16]) or "(no field literal recovered)"
            lines.append(f"- `{task['task']}` — {fields}")
        lines += [
            "",
            "Next C3 pass: recover parser helper calls and branch context to classify hard/optional/conditional reads.",
            "",
        ]
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
