#!/usr/bin/env python3
"""Emit only exact target records from Il2CppDumper stringliteral.json.

This is intentionally narrow clean-room tooling. It refuses fuzzy matching and
redacts unrelated string values from a matched record, retaining only the exact
target string plus scalar address/index metadata needed for a follow-up xref.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SAFE_KEY_HINTS = ("addr", "address", "offset", "index", "id", "rva", "value")


def contains_exact_target(value: Any, target: str) -> bool:
    if isinstance(value, str):
        return value == target
    if isinstance(value, list):
        return any(contains_exact_target(item, target) for item in value)
    if isinstance(value, dict):
        return any(contains_exact_target(item, target) for item in value.values())
    return False


def sanitize_scalar(key: str, value: Any, target: str) -> Any | None:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        if value == target:
            return value
        lower = key.lower()
        if any(hint in lower for hint in SAFE_KEY_HINTS):
            # Preserve only numeric/hex-looking metadata strings.
            text = value.strip()
            try:
                int(text, 0)
            except ValueError:
                return None
            return text
    return None


def sanitize_record(record: dict[str, Any], target: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in record.items():
        scalar = sanitize_scalar(str(key), value, target)
        if scalar is not None:
            out[str(key)] = scalar
    return out


def walk(value: Any, target: str, path: str = "$", matches: list[dict[str, Any]] | None = None):
    if matches is None:
        matches = []
    if isinstance(value, dict):
        if contains_exact_target(value, target):
            # Keep the smallest dict that directly contains the target scalar;
            # parent objects are skipped to avoid duplicate/broad exports.
            if any(isinstance(item, str) and item == target for item in value.values()):
                matches.append({"path": path, "record": sanitize_record(value, target)})
        for key, item in value.items():
            walk(item, target, f"{path}.{key}", matches)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            walk(item, target, f"{path}[{index}]", matches)
    return matches


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    data = json.loads(args.input.read_text(encoding="utf-8"))
    matches = walk(data, args.target)
    report = {
        "schema": 1,
        "target": args.target,
        "match_count": len(matches),
        "matches": matches,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
