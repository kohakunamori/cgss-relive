#!/usr/bin/env python3
"""Validate a reconstructed CGSS 11.6.3 ApiType endpoint map.

Expected input shape is the delivered ``final_map.json`` object with groups A/B,
where every entry is ``[enum_name, key, relative_path, literal_index]``.
The validator never fills missing keys or guesses endpoints.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
from typing import Any

EXPECTED_A_KEYS = set(range(516))
EXPECTED_B_KEYS = {0, 1, 2, *range(8, 27)}


def _parse_entry(group: str, raw: Any) -> tuple[str, int, str, int]:
    if not isinstance(raw, list) or len(raw) != 4:
        raise ValueError(f"invalid {group} entry: {raw!r}")
    name, key, path, literal_index = raw
    if not isinstance(name, str) or not name:
        raise ValueError(f"invalid {group} enum name: {raw!r}")
    if not isinstance(key, int):
        raise ValueError(f"invalid {group} key: {raw!r}")
    if not isinstance(path, str) or not path or path.startswith("/"):
        raise ValueError(f"invalid {group} relative path: {raw!r}")
    if not isinstance(literal_index, int) or literal_index < 0:
        raise ValueError(f"invalid {group} literal index: {raw!r}")
    return name, key, path, literal_index


def validate_map(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {"A", "B"}:
        raise ValueError("map root must contain exactly groups A and B")

    parsed: dict[str, list[tuple[str, int, str, int]]] = {}
    for group in ("A", "B"):
        entries = raw[group]
        if not isinstance(entries, list):
            raise ValueError(f"group {group} must be a list")
        parsed[group] = [_parse_entry(group, entry) for entry in entries]

    a_keys = [entry[1] for entry in parsed["A"]]
    b_keys = [entry[1] for entry in parsed["B"]]
    if len(a_keys) != len(set(a_keys)):
        raise ValueError("group A contains duplicate keys")
    if len(b_keys) != len(set(b_keys)):
        raise ValueError("group B contains duplicate keys")
    if set(a_keys) != EXPECTED_A_KEYS:
        missing = sorted(EXPECTED_A_KEYS - set(a_keys))
        extra = sorted(set(a_keys) - EXPECTED_A_KEYS)
        raise ValueError(f"group A key coverage mismatch: missing={missing}, extra={extra}")
    if set(b_keys) != EXPECTED_B_KEYS:
        missing = sorted(EXPECTED_B_KEYS - set(b_keys))
        extra = sorted(set(b_keys) - EXPECTED_B_KEYS)
        raise ValueError(f"group B key coverage mismatch: missing={missing}, extra={extra}")

    by_path: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    prefix_counts: collections.Counter[str] = collections.Counter()
    for group, entries in parsed.items():
        for name, key, path, literal_index in entries:
            by_path[path].append(
                {"group": group, "name": name, "key": key, "literal_index": literal_index}
            )
            prefix_counts[path.split("/", 1)[0]] += 1

    aliases = {path: entries for path, entries in by_path.items() if len(entries) > 1}
    load_entries = [
        {"name": name, "key": key, "path": path, "literal_index": literal_index}
        for name, key, path, literal_index in parsed["A"]
        if path.startswith("load/")
    ]
    home_entries = [
        {"name": name, "key": key, "path": path, "literal_index": literal_index}
        for name, key, path, literal_index in parsed["A"]
        if path.startswith("home/")
    ]

    return {
        "groups": {"A": len(parsed["A"]), "B": len(parsed["B"])},
        "load_entries": load_entries,
        "home_entries": home_entries,
        "alias_paths": aliases,
        "prefix_counts": dict(sorted(prefix_counts.items(), key=lambda item: (-item[1], item[0]))),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the final CGSS 11.6.3 ApiType endpoint map")
    parser.add_argument("map", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    payload = args.map.read_bytes()
    raw = json.loads(payload.decode("utf-8"))
    report = validate_map(raw)
    report["input_sha256"] = hashlib.sha256(payload).hexdigest()
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
