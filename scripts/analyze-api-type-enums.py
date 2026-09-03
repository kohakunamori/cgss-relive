#!/usr/bin/env python3
"""Discover final-client ApiType enum and initializer surfaces.

The normal A group is represented by one exact 516-value enum.  The separate
VR/login B group is anchored primarily by `Common.ApiType::.cctor`; its enum shape
need not be identical to the 22 delivered dictionary entries, so B discovery is
reported as exact/superset evidence instead of blocking the normal API analysis.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = 2
A_KEYS = frozenset(range(516))
B_KEYS = frozenset({0, 1, 2, *range(8, 27)})
EXPECTED_A_CCTOR = 0x4271C3C
EXPECTED_B_CCTOR = 0x4DC8490
MAX_ENUMS = 20000
MAX_RELATED_METHODS = 256
MAX_PATH_LITERALS = 4096

_NAMESPACE_RE = re.compile(r"^\s*//\s*Namespace:\s*(.*)\s*$")
_ENUM_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)?\s*"
    r"(?:(?:sealed|abstract|static|partial|readonly)\s+)*enum\s+([^\s:{]+)"
)
_ENUM_CONST_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)\s+const\s+[^\s]+\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?(?:0x[0-9A-Fa-f]+|\d+))\s*;\s*$"
)
_ENUM_SIMPLE_RE = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(-?(?:0x[0-9A-Fa-f]+|\d+))\s*,?\s*$"
)
_API_PATH_RE = re.compile(r"^[a-z0-9_]+(?:/[a-z0-9_]+)+$")


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def parse_enums(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    namespace = ""
    enums: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        ns = _NAMESPACE_RE.match(lines[index])
        if ns:
            namespace = ns.group(1).strip()
            index += 1
            continue
        match = _ENUM_RE.match(lines[index])
        if not match:
            index += 1
            continue
        name = match.group(1)
        full_name = f"{namespace}.{name}" if namespace else name
        entries: list[list[Any]] = []
        cursor = index + 1
        for _ in range(8192):
            if cursor >= len(lines):
                break
            line = lines[cursor]
            value_match = _ENUM_CONST_RE.match(line) or _ENUM_SIMPLE_RE.match(line)
            if value_match:
                entries.append([value_match.group(1), int(value_match.group(2), 0)])
            if line.strip() == "}" and cursor > index + 1:
                break
            cursor += 1
        enums.append(
            {
                "name": name,
                "full_name": full_name,
                "namespace": namespace,
                "line": index + 1,
                "entries": entries,
            }
        )
        if len(enums) > MAX_ENUMS:
            raise RuntimeError(f"unexpected enum count > {MAX_ENUMS}")
        index = max(cursor + 1, index + 1)
    return enums


def enum_values(enum: dict[str, Any]) -> list[int]:
    return [int(entry[1]) for entry in enum["entries"]]


def select_exact(enums: list[dict[str, Any]], expected: frozenset[int]) -> list[dict[str, Any]]:
    result = []
    for enum in enums:
        values = enum_values(enum)
        if len(values) == len(expected) and len(values) == len(set(values)) and set(values) == expected:
            result.append(enum)
    return result


def select_small_superset(
    enums: list[dict[str, Any]], expected: frozenset[int], max_entries: int = 96
) -> list[dict[str, Any]]:
    result = []
    for enum in enums:
        values = enum_values(enum)
        if len(values) > max_entries or len(values) != len(set(values)):
            continue
        if expected.issubset(set(values)):
            result.append(enum)
    return result


def load_related_methods(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    result: list[dict[str, Any]] = []
    for item in raw.get("ScriptMethod", []):
        name = str(item.get("Name", ""))
        lowered = name.lower()
        if not any(token in lowered for token in ("apitype", "apilist", "api_type", "api_list")):
            continue
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        result.append(
            {"name": name, "rva": address, "signature": item.get("Signature")}
        )
        if len(result) > MAX_RELATED_METHODS:
            raise RuntimeError("unexpectedly many ApiType-related methods")
    return sorted(result, key=lambda item: (item["rva"], item["name"]))


def load_path_literals(path: Path) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise RuntimeError("unexpected stringliteral.json root")
    result: list[dict[str, Any]] = []
    for literal_index, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        value = item.get("value", item.get("Value", item.get("string", item.get("String"))))
        if not isinstance(value, str) or len(value) > 160 or not _API_PATH_RE.fullmatch(value):
            continue
        address_raw = item.get("address", item.get("Address"))
        result.append(
            {
                "literal_index": literal_index,
                "value": value,
                "address": as_int(address_raw) if address_raw is not None else None,
            }
        )
        if len(result) > MAX_PATH_LITERALS:
            raise RuntimeError("unexpected API-shaped literal count")
    return result


def compact_enum(enum: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": enum["name"],
        "full_name": enum["full_name"],
        "namespace": enum["namespace"],
        "line": enum["line"],
        "entry_count": len(enum["entries"]),
        "entries": enum["entries"],
    }


def find_method(methods: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    matches = [item for item in methods if item["name"] == name]
    return matches[0] if len(matches) == 1 else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    enums = parse_enums(args.dump_cs)
    a_candidates = select_exact(enums, A_KEYS)
    b_exact = select_exact(enums, B_KEYS)
    b_superset = select_small_superset(enums, B_KEYS)
    related_methods = load_related_methods(args.script_json)
    path_literals = load_path_literals(args.stringliteral_json)

    a_cctor = find_method(related_methods, "ApiType$$.cctor")
    b_cctor = find_method(related_methods, "Common.ApiType$$.cctor")

    report = {
        "schema": SCHEMA,
        "enum_count": len(enums),
        "a_expected_key_count": len(A_KEYS),
        "b_delivered_key_count": len(B_KEYS),
        "a_candidates": [compact_enum(item) for item in a_candidates],
        "b_exact_candidates": [compact_enum(item) for item in b_exact],
        "b_superset_candidates": [compact_enum(item) for item in b_superset],
        "a_cctor": a_cctor,
        "b_cctor": b_cctor,
        "related_methods": related_methods,
        "api_shaped_literal_count": len(path_literals),
        "api_shaped_literals": path_literals,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if len(a_candidates) != 1:
        raise RuntimeError(
            f"expected exactly one 516-key normal ApiType enum, got {len(a_candidates)} "
            f"from {len(enums)} enums"
        )
    if a_cctor is None or int(a_cctor["rva"]) != EXPECTED_A_CCTOR:
        raise RuntimeError(f"normal ApiType cctor mismatch: {a_cctor!r}")
    if b_cctor is None or int(b_cctor["rva"]) != EXPECTED_B_CCTOR:
        raise RuntimeError(f"VR ApiType cctor mismatch: {b_cctor!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
