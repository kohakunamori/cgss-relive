#!/usr/bin/env python3
"""C35 v2: recover exact nested response DTO metadata for JsonUtility-backed tasks.

Il2CppDumper's dump.cs is not a reliable lexical representation of CLR nesting:
final-client nested TypeDefs may be emitted as flat declarations even though task
field signatures retain names such as ``ConcertMVStartTask.ResponseDataMain``.

This pass therefore joins three independent sanitized metadata surfaces:

* DummyDll ECMA-335 NestedClass relations establish exact enclosing-type identity;
* dump.cs TypeDefIndex records provide field names, field types and IL2CPP offsets;
* frozen C33 task field signatures prove which task-owned nested types are
  actually referenced by the JsonUtility-backed tasks.

DummyDll TypeDef RIDs and dump.cs TypeDefIndex values are calibrated from the four
known task types.  A single consistent delta is required before any nested type is
joined.  No response value is generated and no runtime/client acceptance is
claimed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = 2
TARGET_TASKS = (
    "Stage.BusSetFavoriteTask",
    "Stage.ConcertMVFinishMVLoadingTask",
    "Stage.ConcertMVPollingTask",
    "Stage.ConcertMVStartTask",
)
NAMESPACE_RE = re.compile(r"^//\s*Namespace:\s*(.*?)\s*$")
TYPE_RE = re.compile(
    r"^(?:\[[^]]+\]\s*)*(?:(?:public|private|protected|internal|abstract|sealed|static|partial|new)\s+)*"
    r"(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_]*(?:`\d+)?)"
    r"(?:<[^>{}]+>)?\s*(?::\s*(.+?))?\s*$"
)
TYPEDEF_INDEX_RE = re.compile(r"//\s*TypeDefIndex:\s*(\d+)")
FIELD_RE = re.compile(r"^(.*?)\s+([^\s;]+);\s*//\s*0x([0-9A-Fa-f]+)\s*$")
MODIFIERS = {
    "public", "private", "protected", "internal", "static", "readonly", "const",
    "volatile", "new", "unsafe", "fixed",
}


class C35Error(ValueError):
    pass


def _code_part(line: str) -> str:
    return line.split("//", 1)[0]


def _declaration(line: str) -> str:
    return _code_part(line).strip().rstrip("{").strip()


def parse_dump_types(path: Path) -> dict[int, dict[str, Any]]:
    """Parse dump.cs field surfaces keyed by the authoritative TypeDefIndex."""
    namespace = ""
    depth = 0
    stack: list[tuple[int, str, int]] = []  # (typedef index, lexical name, body depth)
    pending: tuple[int, str] | None = None
    types: dict[int, dict[str, Any]] = {}

    for raw in path.read_text(encoding="utf-8", errors="strict").splitlines():
        while stack and depth < stack[-1][2]:
            stack.pop()

        stripped = raw.strip()
        ns = NAMESPACE_RE.match(stripped)
        if ns:
            namespace = ns.group(1).strip()
            pending = None
            continue

        decl = _declaration(raw)
        tm = TYPE_RE.match(decl)
        ti = TYPEDEF_INDEX_RE.search(raw)
        if tm and ti:
            short = tm.group(1)
            typedef_index = int(ti.group(1))
            parent = stack[-1][1] if stack else None
            lexical_name = (
                f"{parent}.{short}" if parent
                else (f"{namespace}.{short}" if namespace else short)
            )
            if typedef_index in types:
                raise C35Error(f"duplicate dump TypeDefIndex: {typedef_index}")
            base_raw = tm.group(2)
            types[typedef_index] = {
                "type_def_index": typedef_index,
                "dump_declared_type": lexical_name,
                "short_name": short,
                "namespace": namespace,
                "base_raw": base_raw.strip() if base_raw else None,
                "fields": [],
            }
            pending = (typedef_index, lexical_name)

        if stack and ";" in stripped and "// 0x" in stripped:
            fm = FIELD_RE.match(stripped)
            if fm:
                prefix, name, off = fm.groups()
                tokens = prefix.split()
                is_static = "static" in tokens
                while tokens and tokens[0] in MODIFIERS:
                    tokens.pop(0)
                if tokens:
                    types[stack[-1][0]]["fields"].append({
                        "name": name,
                        "field_type": " ".join(tokens),
                        "offset": int(off, 16),
                        "is_static": is_static,
                    })

        code = _code_part(raw)
        opens = code.count("{")
        closes = code.count("}")
        before = depth
        depth += opens - closes
        if depth < 0:
            depth = 0

        if pending is not None and opens > 0:
            typedef_index, lexical_name = pending
            stack.append((typedef_index, lexical_name, before + 1))
            pending = None

        while stack and depth < stack[-1][2]:
            stack.pop()

    for entry in types.values():
        entry["fields"].sort(key=lambda row: (int(row["offset"]), row["name"]))
    return types


def load_dummy_type_map(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("schema") != 1:
        raise C35Error("dummy type map must contain schema=1")
    rows = raw.get("types")
    if not isinstance(rows, list):
        raise C35Error("dummy type map types must be a list")
    out: list[dict[str, Any]] = []
    seen_rids: set[int] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise C35Error("malformed dummy type row")
        rid = row.get("metadata_rid")
        name = row.get("type")
        short = row.get("short_name")
        enclosing = row.get("enclosing_type")
        if not isinstance(rid, int) or rid <= 0 or rid in seen_rids:
            raise C35Error(f"invalid/duplicate dummy TypeDef RID: {rid!r}")
        if not isinstance(name, str) or not name or not isinstance(short, str) or not short:
            raise C35Error("malformed dummy type identity")
        if enclosing is not None and not isinstance(enclosing, str):
            raise C35Error("malformed dummy enclosing type")
        seen_rids.add(rid)
        out.append({
            "metadata_rid": rid,
            "type": name.replace("+", "."),
            "short_name": short,
            "enclosing_type": enclosing.replace("+", ".") if enclosing else None,
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


def _unique_dummy_by_name(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["type"], []).append(row)
    duplicates = [name for name, values in grouped.items() if len(values) != 1]
    if duplicates:
        raise C35Error(f"duplicate dummy full type names: {duplicates[:8]}")
    return {name: values[0] for name, values in grouped.items()}


def build(dump_path: Path, dummy_map_path: Path, c33_path: Path) -> dict[str, Any]:
    dump_types = parse_dump_types(dump_path)
    dummy_rows = load_dummy_type_map(dummy_map_path)
    dummy_by_name = _unique_dummy_by_name(dummy_rows)
    c33_refs = load_c33_task_nested_refs(c33_path)

    # Calibrate DummyDll TypeDef RID -> Il2CppDumper TypeDefIndex on four exact
    # task identities.  The final image must yield one consistent translation.
    deltas: list[int] = []
    task_dump: dict[str, dict[str, Any]] = {}
    for task in TARGET_TASKS:
        dump_matches = [row for row in dump_types.values() if row["dump_declared_type"] == task]
        dummy = dummy_by_name.get(task)
        if len(dump_matches) != 1 or dummy is None:
            raise C35Error(
                f"could not calibrate task {task}: dump={len(dump_matches)}, dummy={dummy is not None}"
            )
        task_dump[task] = dump_matches[0]
        deltas.append(int(dump_matches[0]["type_def_index"]) - int(dummy["metadata_rid"]))
    if len(set(deltas)) != 1:
        raise C35Error(f"inconsistent DummyDll/dump TypeDef translation: {deltas}")
    typedef_delta = deltas[0]

    rows: list[dict[str, Any]] = []
    response_candidates: list[dict[str, Any]] = []
    resolved_names: set[str] = set()
    for task in TARGET_TASKS:
        nested_dummy = [
            row for row in dummy_rows
            if row["type"].startswith(task + ".")
        ]
        nested: list[dict[str, Any]] = []
        for drow in sorted(nested_dummy, key=lambda row: (row["type"].count("."), row["type"])):
            dump_index = int(drow["metadata_rid"]) + typedef_delta
            surface = dump_types.get(dump_index)
            if surface is None:
                raise C35Error(
                    f"nested dummy type has no dump TypeDefIndex match: {drow['type']} -> {dump_index}"
                )
            if surface["short_name"] != drow["short_name"]:
                raise C35Error(
                    f"nested TypeDef short-name mismatch at {dump_index}: "
                    f"{surface['short_name']} != {drow['short_name']}"
                )
            entry = {
                "type": drow["type"],
                "short_name": drow["short_name"],
                "enclosing_type": drow["enclosing_type"],
                "type_def_index": dump_index,
                "dump_declared_type": surface["dump_declared_type"],
                "base_raw": surface["base_raw"],
                "field_count": len(surface["fields"]),
                "fields": surface["fields"],
                "identity_evidence": "DummyDll-NestedClass+calibrated-TypeDefIndex",
            }
            nested.append(entry)
            resolved_names.add(drow["type"])
            short_lower = str(drow["short_name"]).lower()
            if any(token in short_lower for token in ("response", "result", "data")):
                response_candidates.append({"task": task, **entry})
        rows.append({
            "task": task,
            "task_type_def_index": task_dump[task]["type_def_index"],
            "nested_type_count": len(nested),
            "nested_types": nested,
            "c33_task_nested_refs": c33_refs[task],
        })

    expected_refs = sorted({ref for refs in c33_refs.values() for ref in refs})
    unresolved_refs = sorted(ref for ref in expected_refs if ref not in resolved_names)
    response_candidates.sort(key=lambda row: (row["task"], row["type"]))
    return {
        "schema": SCHEMA,
        "scope": (
            "C35 v2 exact final-client task-owned nested DTO metadata joined from DummyDll "
            "NestedClass relations, calibrated dump.cs TypeDefIndex field surfaces, and C33 task references"
        ),
        "target_task_count": len(TARGET_TASKS),
        "dummy_typedef_to_dump_index_delta": typedef_delta,
        "task_nested_type_counts": {row["task"]: row["nested_type_count"] for row in rows},
        "tasks": rows,
        "c33_task_nested_ref_count": len(expected_refs),
        "c33_task_nested_refs": expected_refs,
        "unresolved_c33_task_nested_ref_count": len(unresolved_refs),
        "unresolved_c33_task_nested_refs": unresolved_refs,
        "response_candidate_count": len(response_candidates),
        "response_candidates": response_candidates,
        "identity_proof": "DummyDll-NestedClass+four-task-TypeDefIndex-calibration",
        "static_evidence_only": True,
        "untouched_client_acceptance": False,
        "ui_visible_success": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dump-cs", type=Path, required=True)
    p.add_argument("--dummy-type-map", type=Path, required=True)
    p.add_argument("--c33", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        report = build(args.dump_cs, args.dummy_type_map, args.c33)
    except (OSError, json.JSONDecodeError, C35Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "dummy_typedef_to_dump_index_delta": report["dummy_typedef_to_dump_index_delta"],
        "task_nested_type_counts": report["task_nested_type_counts"],
        "c33_task_nested_ref_count": report["c33_task_nested_ref_count"],
        "unresolved_c33_task_nested_ref_count": report["unresolved_c33_task_nested_ref_count"],
        "response_candidate_count": report["response_candidate_count"],
        "response_candidates": report["response_candidates"],
    }, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
