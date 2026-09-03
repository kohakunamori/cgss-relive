#!/usr/bin/env python3
"""Build an evidence-graded final-client endpoint/task contract table.

Inputs are sanitized derived reports only.  The builder deliberately distinguishes
static proof from naming candidates:

* ``proven-static``: a concrete NetworkTask writes an ApiType key directly into the
  typed ``NetworkTask.type`` backing field, or an explicitly proven conversion
  bridge receives that key;
* ``candidate-name``: normalized enum/task names match but no key-flow proof exists;
* ``unresolved``: neither form of evidence exists yet.

Intermediate/default base-task writes and ConvertType pre-initialization writes are
not promoted to endpoint bindings.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 1
CONVERT_TARGET = "Stage.ArcadePhaseBaseTask$$ConvertType"
_SUFFIXES = ("NetworkTask", "Task", "Api", "Request", "Response")


def normalize(value: str) -> str:
    value = value.rsplit(".", 1)[-1]
    changed = True
    while changed:
        changed = False
        for suffix in _SUFFIXES:
            if value.endswith(suffix):
                value = value[: -len(suffix)]
                changed = True
                break
    return re.sub(r"[^a-z0-9]", "", value.lower())


def load_map(path: Path) -> dict[str, list[dict[str, Any]]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, list[dict[str, Any]]] = {}
    for group in ("A", "B"):
        entries = raw.get(group)
        if not isinstance(entries, list):
            raise RuntimeError(f"missing ApiType group {group}")
        rows = []
        for entry in entries:
            if not isinstance(entry, list) or len(entry) != 4:
                raise RuntimeError(f"invalid {group} row: {entry!r}")
            name, key, route, literal_index = entry
            rows.append(
                {
                    "group": group,
                    "key": int(key),
                    "enum": str(name),
                    "route": str(route),
                    "literal_index": int(literal_index),
                }
            )
        result[group] = rows
    return result


def task_has_convert_bridge(task: dict[str, Any]) -> bool:
    for method in task.get("field_touching_methods", []):
        for call in method.get("calls", []):
            if call.get("target_name") == CONVERT_TARGET:
                return True
    return False


def direct_bindings(field_report: dict[str, Any]) -> tuple[dict[int, list[dict[str, Any]]], set[str]]:
    bindings: dict[int, list[dict[str, Any]]] = defaultdict(list)
    converted_tasks: set[str] = set()
    for task in field_report.get("tasks", []):
        task_name = str(task["task"])
        converted = task_has_convert_bridge(task)
        if converted:
            converted_tasks.add(task_name)
        values = [int(value) for value in task.get("constant_write_values", [])]

        # ConvertType callers first write a default ApiType.Load (11) and then
        # overwrite the typed field with the conversion result. That 11 is not an
        # endpoint binding for the Arcade task.
        if converted:
            values = [value for value in values if value != 11]

        # Abstract/base helper classes can initialize defaults but are not concrete
        # server operations. Keep them out of route bindings.
        short = task_name.rsplit(".", 1)[-1]
        if short in {"BaseTask", "ArcadePhaseBaseTask"} or short.endswith("TaskBase"):
            continue

        for key in sorted(set(values)):
            if not 0 <= key <= 515:
                continue
            bindings[key].append(
                {
                    "task": task_name,
                    "evidence": "direct-networktask-type-write",
                }
            )
    return bindings, converted_tasks


def add_arcade_bindings(
    bindings: dict[int, list[dict[str, Any]]],
    arcade_report: dict[str, Any],
) -> None:
    for row in arcade_report.get("constructors", []):
        task = str(row["task"])
        key = int(row["convert_input_key"])
        expected = int(row["expected_api_key"])
        if key != expected:
            raise RuntimeError(f"Arcade bridge mismatch for {task}: {key} != {expected}")
        bindings[key].append(
            {
                "task": task,
                "evidence": "convert-type-input-to-networktask-type",
                "convert_call_rva": int(row["convert_call_rva"]),
            }
        )


def name_candidates(tasks: list[str], enum_name: str) -> list[str]:
    target = normalize(enum_name)
    return sorted(task for task in tasks if normalize(task) == target)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-map", type=Path, required=True)
    parser.add_argument("--field-report", type=Path, required=True)
    parser.add_argument("--arcade-report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    api_map = load_map(args.api_map)
    field_report = json.loads(args.field_report.read_text(encoding="utf-8"))
    arcade_report = json.loads(args.arcade_report.read_text(encoding="utf-8"))
    if not field_report.get("network_task", {}).get("typed_api_field"):
        raise RuntimeError("NetworkTask.type field has not been statically proven")
    if arcade_report.get("schema") not in {2, 3}:
        raise RuntimeError("Arcade ConvertType proof report schema mismatch")

    direct, converted_tasks = direct_bindings(field_report)
    add_arcade_bindings(direct, arcade_report)
    tasks = [str(row["task"]) for row in field_report.get("tasks", [])]

    endpoints = []
    summary = {
        "A": {"total": 0, "proven_static": 0, "candidate_name": 0, "unresolved": 0},
        "B": {"total": 0, "proven_static": 0, "candidate_name": 0, "unresolved": 0},
    }
    for group in ("A", "B"):
        for endpoint in api_map[group]:
            bindings = direct.get(endpoint["key"], []) if group == "A" else []
            # Deduplicate same task/evidence generated by multiple observations.
            unique = []
            seen = set()
            for binding in bindings:
                marker = (binding["task"], binding["evidence"])
                if marker in seen:
                    continue
                seen.add(marker)
                unique.append(binding)

            candidates = []
            if not unique:
                candidates = name_candidates(tasks, endpoint["enum"])
                # If the only name match is a ConvertType caller, its key-flow must
                # be proven by the bridge report rather than by the name fallback.
                candidates = [task for task in candidates if task not in converted_tasks]

            if unique:
                status = "proven-static"
            elif candidates:
                status = "candidate-name"
            else:
                status = "unresolved"

            row = dict(endpoint)
            row.update(
                {
                    "status": status,
                    "task_bindings": unique,
                    "name_candidates": candidates,
                }
            )
            endpoints.append(row)
            summary[group]["total"] += 1
            summary[group][status.replace("-", "_")] += 1

    report = {
        "schema": SCHEMA,
        "scope": "final 11.6.3 endpoint-to-task binding with evidence grades",
        "summary": summary,
        "endpoints": endpoints,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if args.markdown_output:
        lines = [
            "# Final 11.6.3 endpoint/task contract status",
            "",
            "`proven-static` requires key-flow evidence into the typed `NetworkTask.type` field.",
            "Naming alone is never promoted to proof.",
            "",
        ]
        for group in ("A", "B"):
            s = summary[group]
            lines += [
                f"## Group {group}",
                "",
                f"- total: **{s['total']}**",
                f"- proven-static: **{s['proven_static']}**",
                f"- candidate-name: **{s['candidate_name']}**",
                f"- unresolved: **{s['unresolved']}**",
                "",
            ]
        lines += ["## Remaining non-proven endpoints", ""]
        for row in endpoints:
            if row["status"] == "proven-static":
                continue
            suffix = ""
            if row["name_candidates"]:
                suffix = " -> " + ", ".join(f"`{x}`" for x in row["name_candidates"])
            lines.append(
                f"- `{row['group']}:{row['key']}` `{row['enum']}` `{row['route']}`: **{row['status']}**{suffix}"
            )
        lines.append("")
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
