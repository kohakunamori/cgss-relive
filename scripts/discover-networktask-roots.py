#!/usr/bin/env python3
"""Discover all final-client NetworkTask roots and ApiType-backed task families.

C0 initially centered on Cute.NetworkTask because that is the normal A-group stack.
The final client also contains a separate Common.ApiType surface used by the B-group
VR/login endpoints.  This pass avoids guessing its root name: it scans the exact
managed type graph for NetworkTask-like roots and ApiType-backed fields, then reports
bounded descendant/method counts for follow-up proof passes.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 1
MAX_TYPES = 100000
MAX_BLOCK_LINES = 4096

_NAMESPACE_RE = re.compile(r"^\s*//\s*Namespace:\s*(.*)\s*$")
_TYPE_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)?\s*"
    r"(?:(?:sealed|abstract|static|partial|readonly)\s+)*"
    r"(?:class|struct)\s+([^\s:{]+)"
)
_FIELD_OFFSET_RE = re.compile(r"//\s*0x([0-9A-Fa-f]+)\s*$")


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def parse_types(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    namespace = ""
    result = []
    i = 0
    while i < len(lines):
        ns = _NAMESPACE_RE.match(lines[i])
        if ns:
            namespace = ns.group(1).strip()
            i += 1
            continue
        match = _TYPE_RE.match(lines[i])
        if not match:
            i += 1
            continue
        name = match.group(1)
        full_name = f"{namespace}.{name}" if namespace else name
        tail = lines[i][match.end():]
        base = None
        if ":" in tail:
            raw = tail.split(":", 1)[1].split("//", 1)[0].split("{", 1)[0].strip()
            if raw:
                base = raw.split(",", 1)[0].strip()
        fields = []
        cursor = i + 1
        depth = 0
        opened = False
        for _ in range(MAX_BLOCK_LINES):
            if cursor >= len(lines):
                break
            line = lines[cursor]
            depth += line.count("{")
            if "{" in line:
                opened = True
            off = _FIELD_OFFSET_RE.search(line)
            if off and ";" in line and "(" not in line:
                decl = line[: off.start()].strip().rstrip(";").strip()
                if decl:
                    fields.append(
                        {
                            "offset": int(off.group(1), 16),
                            "declaration": decl[:300],
                        }
                    )
            depth -= line.count("}")
            if opened and depth <= 0 and line.strip() == "}":
                break
            cursor += 1
        result.append(
            {
                "name": name,
                "full_name": full_name,
                "namespace": namespace,
                "base": base,
                "line": i + 1,
                "fields": fields,
            }
        )
        if len(result) > MAX_TYPES:
            raise RuntimeError("unexpected type count")
        i = max(i + 1, cursor + 1)
    return result


def build_descendants(types: list[dict[str, Any]]) -> dict[str, list[str]]:
    by_full = {item["full_name"]: item for item in types}
    by_short: dict[str, list[str]] = defaultdict(list)
    for item in types:
        by_short[item["name"]].append(item["full_name"])

    def resolve_base(item: dict[str, Any]) -> str | None:
        base = item.get("base")
        if not base:
            return None
        base = str(base).split("<", 1)[0].strip()
        if base in by_full:
            return base
        if "." not in base:
            same_ns = f"{item['namespace']}.{base}" if item["namespace"] else base
            if same_ns in by_full:
                return same_ns
            matches = by_short.get(base, [])
            if len(matches) == 1:
                return matches[0]
        return None

    children: dict[str, list[str]] = defaultdict(list)
    for item in types:
        base = resolve_base(item)
        if base:
            children[base].append(item["full_name"])

    result: dict[str, list[str]] = {}
    for root in by_full:
        seen = set()
        stack = list(children.get(root, []))
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(children.get(current, []))
        result[root] = sorted(seen)
    return result


def load_method_counts(path: Path) -> dict[str, int]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    counts: dict[str, int] = defaultdict(int)
    for item in raw.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        name = str(item.get("Name", ""))
        if address <= 0 or "$$" not in name:
            continue
        counts[name.split("$$", 1)[0]] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    types = parse_types(args.dump_cs)
    descendants = build_descendants(types)
    method_counts = load_method_counts(args.script_json)

    candidates = []
    for item in types:
        api_fields = [
            field for field in item["fields"]
            if "apitype" in field["declaration"].lower()
            and "type" in field["declaration"].lower()
        ]
        networkish = "networktask" in item["name"].lower()
        if not networkish and not api_fields:
            continue
        child_names = descendants.get(item["full_name"], [])
        candidates.append(
            {
                "type": item["full_name"],
                "base": item["base"],
                "line": item["line"],
                "networktask_name": networkish,
                "api_type_fields": api_fields,
                "direct_method_count": method_counts.get(item["full_name"], method_counts.get(item["name"], 0)),
                "descendant_count": len(child_names),
                "descendant_sample": child_names[:80],
            }
        )

    candidates.sort(
        key=lambda row: (
            -int(bool(row["api_type_fields"])),
            -row["descendant_count"],
            row["type"],
        )
    )
    report = {
        "schema": SCHEMA,
        "type_count": len(types),
        "candidate_count": len(candidates),
        "candidates": candidates,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
