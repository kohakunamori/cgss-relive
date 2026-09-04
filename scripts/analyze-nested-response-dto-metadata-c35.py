#!/usr/bin/env python3
"""C35: recover nested response DTO metadata for JsonUtility-backed tasks.

C33's flat dump.cs parser deliberately ignored nesting and therefore surfaced
callback signatures such as ``ConcertMVStartTask.ResponseDataMain`` without the
actual nested type definition.  This pass tracks C# brace/type scope in the exact
final-client dump metadata and exports every nested class/struct under the four
JsonUtility-backed tasks, including field names, field types and instance
offsets.

This is metadata only: no native bytes, method bodies or official server values
are emitted.
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


class C35Error(ValueError):
    pass


def _code_part(line: str) -> str:
    return line.split("//", 1)[0]


def _declaration(line: str) -> str:
    return _code_part(line).strip().rstrip("{").strip()


def parse_nested_types(path: Path) -> dict[str, dict[str, Any]]:
    namespace = ""
    depth = 0
    stack: list[tuple[str, int]] = []  # (full type name, body brace depth)
    pending: tuple[str, str | None] | None = None
    types: dict[str, dict[str, Any]] = {}

    for raw in path.read_text(encoding="utf-8", errors="strict").splitlines():
        # Close scopes that ended on the previous line.
        while stack and depth < stack[-1][1]:
            stack.pop()

        stripped = raw.strip()
        ns = NAMESPACE_RE.match(stripped)
        if ns:
            namespace = ns.group(1).strip()
            pending = None
            continue

        decl = _declaration(raw)
        tm = TYPE_RE.match(decl)
        if tm:
            short = tm.group(1)
            parent = stack[-1][0] if stack else None
            full = f"{parent}.{short}" if parent else (f"{namespace}.{short}" if namespace else short)
            base_raw = tm.group(2)
            types.setdefault(full, {
                "type": full,
                "short_name": short,
                "parent_type": parent,
                "base_raw": base_raw.strip() if base_raw else None,
                "fields": [],
            })
            pending = (full, parent)

        # Fields belong to the currently-open type, never to a merely pending
        # declaration whose opening brace has not been seen yet.
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
            full, _parent = pending
            # The declaration's body occupies the first newly opened brace level.
            body_depth = before + 1
            stack.append((full, body_depth))
            pending = None

        while stack and depth < stack[-1][1]:
            stack.pop()

    for entry in types.values():
        entry["fields"].sort(key=lambda row: (int(row["offset"]), row["name"]))
    return types


def build(path: Path) -> dict[str, Any]:
    types = parse_nested_types(path)
    missing = [task for task in TARGET_TASKS if task not in types]
    if missing:
        raise C35Error(f"target tasks missing: {missing}")

    rows: list[dict[str, Any]] = []
    response_candidates: list[dict[str, Any]] = []
    for task in TARGET_TASKS:
        prefix = task + "."
        nested = [entry for name, entry in types.items() if name.startswith(prefix)]
        nested.sort(key=lambda entry: entry["type"])
        rows.append({
            "task": task,
            "nested_type_count": len(nested),
            "nested_types": nested,
        })
        for entry in nested:
            short = str(entry["short_name"])
            if "response" in short.lower() or "result" in short.lower() or "data" in short.lower():
                response_candidates.append({
                    "task": task,
                    "type": entry["type"],
                    "short_name": short,
                    "field_count": len(entry["fields"]),
                    "fields": entry["fields"],
                })

    response_candidates.sort(key=lambda row: (row["task"], row["type"]))
    return {
        "schema": SCHEMA,
        "scope": "C35 final-client nested response DTO metadata for four JsonUtility-backed tasks",
        "target_task_count": len(TARGET_TASKS),
        "task_nested_type_counts": {row["task"]: row["nested_type_count"] for row in rows},
        "tasks": rows,
        "response_candidate_count": len(response_candidates),
        "response_candidates": response_candidates,
        "untouched_client_acceptance": False,
        "ui_visible_success": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dump-cs", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        report = build(args.dump_cs)
    except (OSError, json.JSONDecodeError, C35Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps({
        "task_nested_type_counts": report["task_nested_type_counts"],
        "response_candidate_count": report["response_candidate_count"],
        "response_candidates": report["response_candidates"],
    }, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
