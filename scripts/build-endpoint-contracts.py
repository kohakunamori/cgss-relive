#!/usr/bin/env python3
"""Build an evidence-graded final-client endpoint/task contract table.

`proven-static` requires concrete key flow into the typed `Cute.NetworkTask.type`
field. Accepted evidence includes direct field writes, the proven Arcade ConvertType
input/output chain, or caller-side object provenance into `NetworkTask.set_type`.
Naming alone remains candidate evidence only.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 3
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
        result[group] = [
            {"group": group, "key": int(row[1]), "enum": str(row[0]), "route": str(row[2]), "literal_index": int(row[3])}
            for row in entries
            if isinstance(row, list) and len(row) == 4
        ]
        if len(result[group]) != len(entries):
            raise RuntimeError(f"invalid ApiType group {group}")
    return result


def task_has_convert_bridge(task: dict[str, Any]) -> bool:
    return any(call.get("target_name") == CONVERT_TARGET for method in task.get("field_touching_methods", []) for call in method.get("calls", []))


def zero_register_writes(task: dict[str, Any]) -> bool:
    return any(
        access.get("kind") == "write" and str(access.get("register", "")).lower() in {"wzr", "xzr"}
        for method in task.get("field_touching_methods", [])
        for access in method.get("api_field_accesses", [])
    )


def direct_bindings(field_report: dict[str, Any]) -> tuple[dict[int, list[dict[str, Any]]], set[str]]:
    bindings: dict[int, list[dict[str, Any]]] = defaultdict(list)
    converted_tasks: set[str] = set()
    for task in field_report.get("tasks", []):
        task_name = str(task["task"])
        converted = task_has_convert_bridge(task)
        if converted:
            converted_tasks.add(task_name)
        values = [int(value) for value in task.get("constant_write_values", [])]
        if zero_register_writes(task):
            values.append(0)
        if converted:
            values = [value for value in values if value != 11]
        short = task_name.rsplit(".", 1)[-1]
        if short in {"BaseTask", "ArcadePhaseBaseTask"} or short.endswith("TaskBase"):
            continue
        for key in sorted(set(values)):
            if 0 <= key <= 515:
                evidence = "direct-networktask-type-zero-register-write" if key == 0 and zero_register_writes(task) else "direct-networktask-type-write"
                bindings[key].append({"task": task_name, "evidence": evidence})
    return bindings, converted_tasks


def add_arcade_bindings(bindings: dict[int, list[dict[str, Any]]], arcade_report: dict[str, Any]) -> dict[int, str]:
    task_by_input: dict[int, str] = {}
    for row in arcade_report.get("constructors", []):
        key = int(row["convert_input_key"])
        expected = int(row["expected_api_key"])
        if key != expected:
            raise RuntimeError(f"Arcade bridge mismatch for {row['task']}: {key} != {expected}")
        task = str(row["task"])
        task_by_input[key] = task
        bindings[key].append({"task": task, "evidence": "convert-type-input-to-networktask-type", "convert_call_rva": int(row["convert_call_rva"])})
    return task_by_input


def add_arcade_garden_bindings(bindings: dict[int, list[dict[str, Any]]], api_map: dict[str, list[dict[str, Any]]], task_by_input: dict[int, str], proof: dict[str, Any]) -> None:
    if proof.get("schema") != 1 or proof.get("prefix", {}).get("value") != "Garden":
        raise RuntimeError("Arcade Garden conversion proof mismatch")
    if int(proof.get("convert_method", {}).get("rva", 0)) != 0x4769CC0:
        raise RuntimeError("Arcade ConvertType RVA mismatch")
    required = {"System.Enum$$GetName", "System.String$$Concat", "StageMinigame.ArcadeUtil$$ConvertEnumFromName<Int32Enum>"}
    if not required.issubset(set(proof.get("convert_method", {}).get("algorithm", []))):
        raise RuntimeError("Arcade conversion algorithm evidence incomplete")
    a_by_key = {row["key"]: row for row in api_map["A"]}
    for row in proof.get("mappings", []):
        input_key = int(row["input_key"])
        output_key = int(row["output_key"])
        if input_key not in task_by_input:
            raise RuntimeError(f"Garden conversion input task missing: {input_key}")
        if a_by_key[input_key]["enum"] != row["input_enum"] or a_by_key[output_key]["enum"] != row["output_enum"]:
            raise RuntimeError(f"Garden conversion enum mismatch: {row!r}")
        if row["output_enum"] != "Garden" + row["input_enum"]:
            raise RuntimeError(f"Garden enum-name transformation mismatch: {row!r}")
        bindings[output_key].append({
            "task": task_by_input[input_key],
            "evidence": "garden-room-enum-name-conversion-to-networktask-type",
            "input_key": input_key,
            "prefix": "Garden",
        })


def add_set_type_bindings(bindings: dict[int, list[dict[str, Any]]], report: dict[str, Any]) -> None:
    if report.get("schema") not in {1, 2}:
        raise RuntimeError("set_type callsite report schema mismatch")
    for row in report.get("observations", []):
        key = int(row["key"])
        if 0 <= key <= 515:
            bindings[key].append({
                "task": str(row["task"]), "evidence": "caller-object-provenance-to-networktask-set-type",
                "caller": str(row["caller"]), "caller_rva": int(row["caller_rva"]), "set_type_call_rva": int(row["set_type_call_rva"]),
            })


def name_candidates(tasks: list[str], enum_name: str) -> list[str]:
    target = normalize(enum_name)
    return sorted(task for task in tasks if normalize(task) == target)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--api-map", type=Path, required=True)
    p.add_argument("--field-report", type=Path, required=True)
    p.add_argument("--arcade-report", type=Path, required=True)
    p.add_argument("--arcade-garden-report", type=Path)
    p.add_argument("--set-type-report", type=Path)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--markdown-output", type=Path)
    args = p.parse_args()

    api_map = load_map(args.api_map)
    field_report = json.loads(args.field_report.read_text(encoding="utf-8"))
    arcade_report = json.loads(args.arcade_report.read_text(encoding="utf-8"))
    if not field_report.get("network_task", {}).get("typed_api_field"):
        raise RuntimeError("NetworkTask.type field has not been statically proven")
    if arcade_report.get("schema") not in {2, 3}:
        raise RuntimeError("Arcade ConvertType proof report schema mismatch")

    bindings, converted_tasks = direct_bindings(field_report)
    task_by_input = add_arcade_bindings(bindings, arcade_report)
    if args.arcade_garden_report:
        add_arcade_garden_bindings(bindings, api_map, task_by_input, json.loads(args.arcade_garden_report.read_text(encoding="utf-8")))
    if args.set_type_report:
        add_set_type_bindings(bindings, json.loads(args.set_type_report.read_text(encoding="utf-8")))
    tasks = [str(row["task"]) for row in field_report.get("tasks", [])]

    endpoints = []
    summary = {"A": {"total": 0, "proven_static": 0, "candidate_name": 0, "unresolved": 0}, "B": {"total": 0, "proven_static": 0, "candidate_name": 0, "unresolved": 0}}
    for group in ("A", "B"):
        for endpoint in api_map[group]:
            raw_bindings = bindings.get(endpoint["key"], []) if group == "A" else []
            unique = []
            seen = set()
            for binding in raw_bindings:
                marker = (binding["task"], binding["evidence"], binding.get("caller_rva"), binding.get("set_type_call_rva"), binding.get("input_key"))
                if marker not in seen:
                    seen.add(marker)
                    unique.append(binding)
            candidates = [] if unique else [task for task in name_candidates(tasks, endpoint["enum"]) if task not in converted_tasks]
            status = "proven-static" if unique else ("candidate-name" if candidates else "unresolved")
            row = dict(endpoint)
            row.update({"status": status, "task_bindings": unique, "name_candidates": candidates})
            endpoints.append(row)
            summary[group]["total"] += 1
            summary[group][status.replace("-", "_")] += 1

    report = {"schema": SCHEMA, "scope": "final 11.6.3 endpoint-to-task binding with evidence grades", "summary": summary, "endpoints": endpoints}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = ["# Final 11.6.3 endpoint/task contract status", "", "`proven-static` requires concrete key-flow evidence; naming alone is never proof.", ""]
        for group in ("A", "B"):
            s = summary[group]
            lines += [f"## Group {group}", "", f"- total: **{s['total']}**", f"- proven-static: **{s['proven_static']}**", f"- candidate-name: **{s['candidate_name']}**", f"- unresolved: **{s['unresolved']}**", ""]
        lines += ["## Remaining non-proven endpoints", ""]
        for row in endpoints:
            if row["status"] != "proven-static":
                suffix = " -> " + ", ".join(f"`{x}`" for x in row["name_candidates"]) if row["name_candidates"] else ""
                lines.append(f"- `{row['group']}:{row['key']}` `{row['enum']}` `{row['route']}`: **{row['status']}**{suffix}")
        lines.append("")
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
