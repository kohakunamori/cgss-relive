#!/usr/bin/env python3
"""C35 v3: recover exact task-owned response DTO metadata from DummyDll.

The v2 experiment proved that DummyDll TypeDef RIDs and dump.cs TypeDefIndex values
are not related by one global offset in the final client.  Therefore no identity
or field surface is inferred by layout/index coincidence here.

Il2CppDumper's final-client DummyDll preserves one coherent ECMA-335 metadata
surface: exact NestedClass ownership, field names/signatures/visibility, type
Serializable flags and custom attributes.  C35 v3 consumes that surface directly
and cross-checks every task-owned nested type reference already present in frozen
C33 task field signatures.

This is static metadata evidence only.  It does not infer JSON values, empty-value
safety, untouched-client acceptance or UI success.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = 3
TARGET_TASKS = (
    "Stage.BusSetFavoriteTask",
    "Stage.ConcertMVFinishMVLoadingTask",
    "Stage.ConcertMVPollingTask",
    "Stage.ConcertMVStartTask",
)


class C35Error(ValueError):
    pass


def load_dummy_types(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema") != 2:
        raise C35Error("dummy type map must contain schema=2")
    rows = raw.get("types")
    if not isinstance(rows, list):
        raise C35Error("dummy type map types must be a list")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise C35Error("malformed dummy type row")
        name = row.get("type")
        short = row.get("short_name")
        enclosing = row.get("enclosing_type")
        fields = row.get("fields")
        if not isinstance(name, str) or not name or name in seen:
            raise C35Error(f"invalid/duplicate dummy type name: {name!r}")
        if not isinstance(short, str) or not short:
            raise C35Error(f"invalid dummy short name for {name}")
        if enclosing is not None and not isinstance(enclosing, str):
            raise C35Error(f"invalid enclosing type for {name}")
        if not isinstance(fields, list):
            raise C35Error(f"invalid field list for {name}")
        clean_fields: list[dict[str, Any]] = []
        for field in fields:
            if not isinstance(field, dict):
                raise C35Error(f"malformed field for {name}")
            field_name = field.get("name")
            field_type = field.get("field_type")
            visibility = field.get("visibility")
            attrs = field.get("custom_attributes")
            if not all(isinstance(v, str) and v for v in (field_name, field_type, visibility)):
                raise C35Error(f"malformed field identity for {name}")
            if not isinstance(attrs, list) or any(not isinstance(v, str) for v in attrs):
                raise C35Error(f"malformed field attributes for {name}.{field_name}")
            is_static = field.get("is_static")
            if not isinstance(is_static, bool):
                raise C35Error(f"malformed static flag for {name}.{field_name}")
            # Unity's basic field rule is public instance field or [SerializeField]
            # instance field.  This remains a candidate flag: type support and
            # JsonUtility-specific exclusions are validated in the next stage.
            has_serialize_field = any(
                attr == "UnityEngine.SerializeField" or attr.endswith(".SerializeField")
                for attr in attrs
            )
            clean_fields.append({
                "metadata_rid": field.get("metadata_rid"),
                "name": field_name,
                "field_type": field_type,
                "visibility": visibility,
                "is_static": is_static,
                "is_init_only": bool(field.get("is_init_only", False)),
                "custom_attributes": sorted(set(attrs)),
                "unity_serialized_field_candidate": (
                    not is_static and (visibility == "public" or has_serialize_field)
                ),
            })
        type_attrs = row.get("custom_attributes")
        if not isinstance(type_attrs, list) or any(not isinstance(v, str) for v in type_attrs):
            raise C35Error(f"malformed type attributes for {name}")
        serializable = row.get("serializable_flag")
        if not isinstance(serializable, bool):
            raise C35Error(f"malformed Serializable flag for {name}")
        seen.add(name)
        out.append({
            "metadata_rid": row.get("metadata_rid"),
            "type": name.replace("+", "."),
            "short_name": short,
            "namespace": row.get("namespace"),
            "enclosing_type": enclosing.replace("+", ".") if enclosing else None,
            "serializable_flag": serializable,
            "custom_attributes": sorted(set(type_attrs)),
            "field_count": len(clean_fields),
            "fields": clean_fields,
        })
    return out


def load_c33_task_nested_refs(path: Path) -> dict[str, list[str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema") != 1 or raw.get("target_task_count") != 4:
        raise C35Error("unexpected C33 report")
    tasks = raw.get("tasks")
    if not isinstance(tasks, list):
        raise C35Error("C33 tasks must be a list")
    by_task = {str(row.get("task")): row for row in tasks if isinstance(row, dict)}
    result: dict[str, list[str]] = {}
    for task in TARGET_TASKS:
        row = by_task.get(task)
        if row is None or not isinstance(row.get("fields"), list):
            raise C35Error(f"C33 task missing/malformed: {task}")
        task_short = task.rsplit(".", 1)[-1]
        pat = re.compile(rf"\b{re.escape(task_short)}\.([A-Za-z_][A-Za-z0-9_]*(?:`\d+)?)\b")
        refs: set[str] = set()
        for field in row["fields"]:
            if not isinstance(field, dict) or not isinstance(field.get("field_type"), str):
                continue
            for match in pat.finditer(field["field_type"]):
                refs.add(f"Stage.{task_short}.{match.group(1)}")
        result[task] = sorted(refs)
    return result


def build(dummy_map_path: Path, c33_path: Path) -> dict[str, Any]:
    dummy_rows = load_dummy_types(dummy_map_path)
    by_name = {row["type"]: row for row in dummy_rows}
    c33_refs = load_c33_task_nested_refs(c33_path)

    missing_tasks = [task for task in TARGET_TASKS if task not in by_name]
    if missing_tasks:
        raise C35Error(f"target tasks absent from DummyDll: {missing_tasks}")

    tasks: list[dict[str, Any]] = []
    response_candidates: list[dict[str, Any]] = []
    resolved_names: set[str] = set()
    for task in TARGET_TASKS:
        nested = [row for row in dummy_rows if row["type"].startswith(task + ".")]
        nested.sort(key=lambda row: (row["type"].count("."), row["type"]))
        for entry in nested:
            resolved_names.add(entry["type"])
            short = str(entry["short_name"]).lower()
            if any(token in short for token in ("response", "result", "data")):
                response_candidates.append({
                    "task": task,
                    **entry,
                    "identity_evidence": "DummyDll-ECMA335-NestedClass",
                })
        tasks.append({
            "task": task,
            "task_metadata_rid": by_name[task]["metadata_rid"],
            "nested_type_count": len(nested),
            "nested_types": nested,
            "c33_task_nested_refs": c33_refs[task],
        })

    expected_refs = sorted({ref for refs in c33_refs.values() for ref in refs})
    unresolved = sorted(ref for ref in expected_refs if ref not in resolved_names)
    response_candidates.sort(key=lambda row: (row["task"], row["type"]))
    return {
        "schema": SCHEMA,
        "scope": (
            "C35 v3 exact final-client task-owned nested DTO metadata from DummyDll ECMA-335 "
            "NestedClass and field metadata, cross-checked against frozen C33 task signatures"
        ),
        "target_task_count": len(TARGET_TASKS),
        "task_nested_type_counts": {row["task"]: row["nested_type_count"] for row in tasks},
        "tasks": tasks,
        "c33_task_nested_ref_count": len(expected_refs),
        "c33_task_nested_refs": expected_refs,
        "unresolved_c33_task_nested_ref_count": len(unresolved),
        "unresolved_c33_task_nested_refs": unresolved,
        "response_candidate_count": len(response_candidates),
        "response_candidates": response_candidates,
        "identity_proof": "DummyDll-ECMA335-NestedClass",
        "field_surface_proof": "DummyDll-ECMA335-FieldDefinition",
        "static_evidence_only": True,
        "untouched_client_acceptance": False,
        "ui_visible_success": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dummy-type-map", type=Path, required=True)
    p.add_argument("--c33", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        report = build(args.dummy_type_map, args.c33)
    except (OSError, json.JSONDecodeError, C35Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "task_nested_type_counts": report["task_nested_type_counts"],
        "c33_task_nested_ref_count": report["c33_task_nested_ref_count"],
        "unresolved_c33_task_nested_ref_count": report["unresolved_c33_task_nested_ref_count"],
        "response_candidate_count": report["response_candidate_count"],
        "response_candidates": report["response_candidates"],
    }, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
