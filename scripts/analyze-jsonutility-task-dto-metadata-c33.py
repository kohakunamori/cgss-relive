#!/usr/bin/env python3
"""C33: recover dump.cs field/type metadata for the four JsonUtility response tasks.

C29-C32 establish that four low-complexity endpoints serialize response `data`
and deserialize it via UnityEngine.JsonUtility.FromJson<object>.  C31 additionally
proves the `/bus/favorite` result escapes through a non-stack store at offset
0x50.  This pass uses final-client Il2CppDumper `dump.cs` strictly as metadata to
map task field offsets/types and expose one-hop referenced DTO field surfaces.

No method bodies, native bytes, or official response values are emitted.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 1
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
FIELD_RE = re.compile(r"^(.*?)\s+([^\s;]+);\s*//\s*0x([0-9A-Fa-f]+)\s*$")
MODIFIERS = {
    "public", "private", "protected", "internal", "static", "readonly", "const",
    "volatile", "new", "unsafe", "fixed",
}


class C33Error(ValueError):
    pass


def _strip_comment(line: str) -> str:
    return line.split("//", 1)[0].strip() if "//" in line else line.strip()


def parse_dump(path: Path) -> dict[str, dict[str, Any]]:
    namespace = ""
    current: str | None = None
    types: dict[str, dict[str, Any]] = {}
    for raw in path.read_text(encoding="utf-8", errors="strict").splitlines():
        line = raw.strip()
        ns = NAMESPACE_RE.match(line)
        if ns:
            namespace = ns.group(1).strip()
            current = None
            continue
        declaration = _strip_comment(line).rstrip("{").strip()
        tm = TYPE_RE.match(declaration)
        if tm:
            short = tm.group(1)
            current = f"{namespace}.{short}" if namespace else short
            types.setdefault(current, {"type": current, "fields": []})
            continue
        if current is None or ";" not in line or "// 0x" not in line:
            continue
        fm = FIELD_RE.match(line)
        if not fm:
            continue
        prefix, name, off = fm.groups()
        tokens = prefix.split()
        static = "static" in tokens
        while tokens and tokens[0] in MODIFIERS:
            tokens.pop(0)
        if not tokens:
            continue
        field_type = " ".join(tokens)
        types[current]["fields"].append({
            "name": name,
            "field_type": field_type,
            "offset": int(off, 16),
            "is_static": static,
        })
    for entry in types.values():
        entry["fields"].sort(key=lambda row: (row["offset"], row["name"]))
    return types


def candidate_type_names(field_type: str, all_types: dict[str, dict[str, Any]]) -> list[str]:
    cleaned = re.sub(r"[\[\]*&?]", " ", field_type)
    cleaned = re.sub(r"<|>|,", " ", cleaned)
    tokens = [token.strip() for token in cleaned.split() if token.strip()]
    out: set[str] = set()
    for token in tokens:
        if token in all_types:
            out.add(token)
            continue
        short = token.rsplit(".", 1)[-1]
        for full in all_types:
            if full.rsplit(".", 1)[-1] == short:
                out.add(full)
    return sorted(out)


def load_c31_store_offsets(path: Path) -> dict[str, list[int]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema") != 1 or doc.get("route_count") != 3:
        raise C33Error("unexpected C31 report")
    result: dict[str, list[int]] = defaultdict(list)
    for row in doc.get("routes", []):
        task = row.get("task")
        if not isinstance(task, str):
            continue
        for sink in row.get("semantic_sinks", []):
            if isinstance(sink, dict) and sink.get("kind") == "nonstack-store" and isinstance(sink.get("offset"), int):
                result[task].append(int(sink["offset"]))
    return {task: sorted(set(values)) for task, values in result.items()}


def build(dump_cs: Path, c31: Path) -> dict[str, Any]:
    types = parse_dump(dump_cs)
    stores = load_c31_store_offsets(c31)
    missing = [task for task in TARGET_TASKS if task not in types]
    if missing:
        raise C33Error(f"target task types missing from dump.cs: {missing}")

    task_rows: list[dict[str, Any]] = []
    referenced: set[str] = set()
    store_matches: list[dict[str, Any]] = []
    for task in TARGET_TASKS:
        fields = types[task]["fields"]
        for field in fields:
            referenced.update(candidate_type_names(field["field_type"], types))
        offsets = stores.get(task, [])
        matches = [field for field in fields if field["offset"] in offsets and not field["is_static"]]
        for off in offsets:
            store_matches.append({
                "task": task,
                "store_offset": off,
                "field_matches": [field for field in fields if field["offset"] == off and not field["is_static"]],
            })
        task_rows.append({
            "task": task,
            "field_count": len(fields),
            "fields": fields,
            "c31_nonstack_store_offsets": offsets,
            "c31_store_field_matches": matches,
        })

    # One-hop type surfaces give exact serializable DTO member names/types without
    # dumping unrelated client metadata.
    referenced_rows = []
    for type_name in sorted(referenced):
        if type_name in TARGET_TASKS:
            continue
        fields = types[type_name]["fields"]
        if not fields:
            continue
        referenced_rows.append({
            "type": type_name,
            "field_count": len(fields),
            "fields": fields,
        })

    return {
        "schema": SCHEMA,
        "scope": "C33 sanitized final-client task field offsets and one-hop referenced DTO metadata",
        "target_task_count": len(TARGET_TASKS),
        "tasks": task_rows,
        "store_offset_matches": store_matches,
        "referenced_type_surface_count": len(referenced_rows),
        "referenced_type_surfaces": referenced_rows,
        "untouched_client_acceptance": False,
        "ui_visible_success": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dump-cs", type=Path, required=True)
    p.add_argument("--c31", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        report = build(args.dump_cs, args.c31)
    except (OSError, json.JSONDecodeError, C33Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps({
        "target_task_count": report["target_task_count"],
        "store_offset_matches": report["store_offset_matches"],
        "referenced_type_surface_count": report["referenced_type_surface_count"],
        "tasks": [{"task": r["task"], "field_count": r["field_count"]} for r in report["tasks"]],
    }, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__": raise SystemExit(main())
