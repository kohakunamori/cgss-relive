#!/usr/bin/env python3
"""C36: bind exact C35 task-owned JsonUtility DTO metadata to C14 routes.

This stage is deliberately value-agnostic. It proves route/task/endpoint identity and
recursively describes the task-owned serializable field graph. It does not invent
field values, prove empty/default DTO safety, or promote runtime templates.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = 1
TARGET_TASKS = (
    "Stage.BusSetFavoriteTask",
    "Stage.ConcertMVFinishMVLoadingTask",
    "Stage.ConcertMVPollingTask",
    "Stage.ConcertMVStartTask",
)


class C36Error(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise C36Error(f"expected JSON object: {path}")
    return raw


def normalize_type(name: str) -> str:
    return name.replace("+", ".")


def unwrap_container(field_type: str) -> tuple[str, str | None]:
    t = normalize_type(field_type.strip())
    if t.endswith("[]"):
        return "array", t[:-2]
    m = re.fullmatch(r"System\.Collections\.Generic\.List`1<(.+)>", t)
    if m:
        return "list", m.group(1).strip()
    return "scalar-or-object", t


def primitive_kind(t: str) -> str | None:
    t = normalize_type(t)
    mapping = {
        "bool": "boolean", "System.Boolean": "boolean",
        "byte": "integer", "sbyte": "integer", "short": "integer", "ushort": "integer",
        "int": "integer", "uint": "integer", "long": "integer", "ulong": "integer",
        "System.Byte": "integer", "System.SByte": "integer", "System.Int16": "integer",
        "System.UInt16": "integer", "System.Int32": "integer", "System.UInt32": "integer",
        "System.Int64": "integer", "System.UInt64": "integer",
        "float": "number", "double": "number", "System.Single": "number", "System.Double": "number",
        "string": "string", "System.String": "string",
    }
    return mapping.get(t)


def bind_routes(c14: dict[str, Any]) -> dict[str, dict[str, Any]]:
    routes = c14.get("routes")
    if not isinstance(routes, list):
        raise C36Error("C14 routes missing")
    hits: dict[str, list[dict[str, Any]]] = {task: [] for task in TARGET_TASKS}
    for route_row in routes:
        if not isinstance(route_row, dict) or route_row.get("ambiguous_path_identity") is not False:
            continue
        route = route_row.get("route")
        endpoints = route_row.get("endpoints")
        if not isinstance(route, str) or not isinstance(endpoints, list):
            continue
        for endpoint in endpoints:
            if not isinstance(endpoint, dict):
                continue
            eid = endpoint.get("endpoint_id")
            fields = endpoint.get("concrete_response_fields")
            if not isinstance(eid, int) or not isinstance(fields, list):
                continue
            for task in TARGET_TASKS:
                matching = [f for f in fields if isinstance(f, dict) and f.get("task") == task]
                if matching:
                    hits[task].append({
                        "route": route,
                        "endpoint_id": eid,
                        "api_key": endpoint.get("api_key"),
                        "enum": endpoint.get("enum"),
                        "status": endpoint.get("status"),
                        "parser_methods": sorted({str(f.get("method")) for f in matching if f.get("method")}),
                        "concrete_response_keys": sorted({str(f.get("field")) for f in matching if f.get("field")}),
                    })
    out: dict[str, dict[str, Any]] = {}
    for task, rows in hits.items():
        unique = {(row["route"], row["endpoint_id"]): row for row in rows}
        if len(unique) != 1:
            raise C36Error(
                f"expected exactly one unambiguous C14 route for {task}, got {sorted(unique)}"
            )
        out[task] = next(iter(unique.values()))
    return out


def get_task_rows(c35: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if c35.get("schema") != 3 or c35.get("identity_proof") != "DummyDll-ECMA335-NestedClass":
        raise C36Error("unexpected C35 report")
    rows = c35.get("tasks")
    if not isinstance(rows, list):
        raise C36Error("C35 tasks missing")
    by_task = {
        row.get("task"): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("task"), str)
    }
    missing = [task for task in TARGET_TASKS if task not in by_task]
    if missing:
        raise C36Error(f"C35 target tasks missing: {missing}")
    return {task: by_task[task] for task in TARGET_TASKS}


def serialized_fields(type_row: dict[str, Any]) -> list[dict[str, Any]]:
    fields = type_row.get("fields")
    if not isinstance(fields, list):
        raise C36Error(f"fields missing for {type_row.get('type')}")
    return [
        field for field in fields
        if isinstance(field, dict) and field.get("unity_serialized_field_candidate") is True
    ]


def build_type_graph(
    task_row: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, set[str]]]:
    nested = task_row.get("nested_types")
    if not isinstance(nested, list):
        raise C36Error(f"nested_types missing for {task_row.get('task')}")
    by_name: dict[str, dict[str, Any]] = {}
    for row in nested:
        if not isinstance(row, dict) or not isinstance(row.get("type"), str):
            raise C36Error("malformed nested type")
        by_name[normalize_type(row["type"])] = row
    edges: dict[str, set[str]] = {name: set() for name in by_name}
    for name, row in by_name.items():
        for field in serialized_fields(row):
            field_type = field.get("field_type")
            if not isinstance(field_type, str):
                continue
            _, element = unwrap_container(field_type)
            if element in by_name:
                edges[name].add(element)
    return by_name, edges


def choose_root(
    task: str,
    task_row: dict[str, Any],
    response_candidates: list[dict[str, Any]],
) -> tuple[str, str]:
    _, edges = build_type_graph(task_row)
    candidate_names = {
        normalize_type(row["type"])
        for row in response_candidates
        if row.get("task") == task and isinstance(row.get("type"), str)
    }
    if not candidate_names:
        raise C36Error(f"no C35 response candidates for {task}")
    referenced = {
        dst
        for src, destinations in edges.items()
        if src in candidate_names
        for dst in destinations
        if dst in candidate_names
    }
    roots = sorted(candidate_names - referenced)
    named = [
        name for name in roots
        if re.search(r"(?:^|\.)(?:Response|Result)[A-Za-z0-9_]*$", name)
    ]
    if len(named) == 1:
        return named[0], "unreferenced-task-owned-response-type"
    if len(roots) == 1:
        return roots[0], "single-unreferenced-response-candidate"
    raise C36Error(f"ambiguous response root for {task}: {roots}")


def _collect_nested_unresolved(field: dict[str, Any]) -> set[str]:
    result: set[str] = set()
    schema = field.get("schema")
    if isinstance(schema, dict):
        result.update(schema.get("unresolved_external_types", []))
    element = field.get("element")
    if isinstance(element, dict):
        result.update(element.get("unresolved_external_types", []))
        if element.get("kind") == "external-object-ref" and isinstance(element.get("clr_type"), str):
            result.add(element["clr_type"])
    if field.get("kind") == "external-object-ref" and isinstance(field.get("clr_type"), str):
        result.add(field["clr_type"])
    return result


def describe_type(
    name: str,
    by_name: dict[str, dict[str, Any]],
    stack: tuple[str, ...] = (),
) -> dict[str, Any]:
    if name in stack:
        return {"kind": "object-ref", "type": name, "recursive": True}
    row = by_name[name]
    output_fields: list[dict[str, Any]] = []
    for field in serialized_fields(row):
        field_name = field.get("name")
        field_type = field.get("field_type")
        if not isinstance(field_name, str) or not isinstance(field_type, str):
            raise C36Error(f"bad field in {name}")
        container, element = unwrap_container(field_type)
        primitive = primitive_kind(element or field_type)
        item: dict[str, Any] = {
            "json_key": field_name,
            "clr_type": normalize_type(field_type),
            "visibility": field.get("visibility"),
            "metadata_rid": field.get("metadata_rid"),
        }
        if container in ("array", "list"):
            item["kind"] = container
            if primitive:
                item["element"] = {"kind": primitive, "clr_type": normalize_type(element or "")}
            elif element in by_name:
                item["element"] = describe_type(element, by_name, stack + (name,))
            else:
                item["element"] = {
                    "kind": "external-object-ref",
                    "clr_type": normalize_type(element or ""),
                }
        elif primitive:
            item["kind"] = primitive
        elif element in by_name:
            item["kind"] = "object"
            item["schema"] = describe_type(element, by_name, stack + (name,))
        else:
            item["kind"] = "external-object-ref"
        output_fields.append(item)
    unresolved: set[str] = set()
    for field in output_fields:
        unresolved.update(_collect_nested_unresolved(field))
    return {
        "kind": "object",
        "type": name,
        "serializable_flag": bool(row.get("serializable_flag")),
        "field_count": len(output_fields),
        "fields": output_fields,
        "unresolved_external_types": sorted(unresolved),
    }


def build(c14: dict[str, Any], c35: dict[str, Any]) -> dict[str, Any]:
    route_bindings = bind_routes(c14)
    task_rows = get_task_rows(c35)
    candidates = c35.get("response_candidates")
    if not isinstance(candidates, list):
        raise C36Error("C35 response_candidates missing")
    routes: list[dict[str, Any]] = []
    for task in TARGET_TASKS:
        task_row = task_rows[task]
        root, root_evidence = choose_root(task, task_row, candidates)
        by_name, _ = build_type_graph(task_row)
        schema = describe_type(root, by_name)
        binding = route_bindings[task]
        routes.append({
            **binding,
            "task": task,
            "root_dto_type": root,
            "root_selection_evidence": root_evidence,
            "response_json_schema": schema,
            "schema_presence": "static-proven-task-owned-field-surface",
            "empty_value_status": "not-proven",
            "runtime_template_status": "not-promoted",
            "untouched_client_acceptance": False,
            "ui_visible_success": False,
        })
    routes.sort(key=lambda row: row["route"])
    return {
        "schema": SCHEMA,
        "scope": (
            "C36 route-bound recursive JsonUtility response DTO schema evidence from frozen "
            "C14 + C35; no response values inferred"
        ),
        "route_count": len(routes),
        "route_task_binding_proof": "C14-exact-concrete-response-parser-task",
        "dto_identity_proof": c35.get("identity_proof"),
        "dto_field_surface_proof": c35.get("field_surface_proof"),
        "route_endpoint_pairs": [[row["route"], row["endpoint_id"]] for row in routes],
        "routes": routes,
        "value_semantics_inferred": False,
        "runtime_templates_promoted": 0,
        "untouched_client_acceptance": False,
        "ui_visible_success": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c14", type=Path, required=True)
    parser.add_argument("--c35", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = build(load_json(args.c14), load_json(args.c35))
    except (OSError, json.JSONDecodeError, C36Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "route_count": report["route_count"],
        "routes": [
            {
                "route": row["route"],
                "endpoint_id": row["endpoint_id"],
                "task": row["task"],
                "root_dto_type": row["root_dto_type"],
                "root_field_count": row["response_json_schema"]["field_count"],
            }
            for row in report["routes"]
        ],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
