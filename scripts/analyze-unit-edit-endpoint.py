#!/usr/bin/env python3
"""Targeted exact-final discovery for the UnitEdit mutation contract.

The report is intentionally sanitized. It emits only:
- exact final ApiType entries whose enum/path contains both ``unit`` and ``edit``;
- exact Il2CppDumper type blocks whose type name contains ``UnitEdit``;
- selected fields and method signatures/RVAs from those blocks;
- exact script.json methods owned by those already-selected UnitEdit types.

No raw binaries, dump.cs, script.json, or bulk decompilation are emitted.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

TYPE_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)?\s*"
    r"(?:(?:sealed|abstract|static|partial)\s+)*"
    r"(?:class|struct|enum)\s+([^\s:{]+)"
)
RVA_RE = re.compile(r"//\s*RVA:\s*0x([0-9A-Fa-f]+)")
FIELD_HINTS = (
    "unit", "serial", "dress", "costume", "member", "slot", "name", "id", "param"
)
MAX_BLOCK_LINES = 320
MAX_FIELDS = 80
MAX_METHODS = 100
MAX_SCRIPT_METHODS = 160


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    return 0


def endpoint_rows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for group in ("A", "B"):
        for raw in doc[group]:
            name, key, path, literal_index = raw
            text = f"{name} {path}".lower()
            if "unit" not in text or "edit" not in text:
                continue
            rows.append(
                {
                    "group": group,
                    "name": name,
                    "key": key,
                    "path": path,
                    "literal_index": literal_index,
                    "evidence": "exact-final-api-map",
                }
            )
    return rows


def type_blocks(lines: list[str]) -> list[dict[str, Any]]:
    headers: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines):
        match = TYPE_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if "unitedit" not in name.lower():
            continue
        headers.append((index, name, line.strip()))

    output: list[dict[str, Any]] = []
    for start, name, declaration in headers:
        end = min(len(lines), start + MAX_BLOCK_LINES)
        for cursor in range(start + 1, end):
            if TYPE_RE.match(lines[cursor]):
                end = cursor
                break

        fields: list[str] = []
        methods: list[dict[str, Any]] = []
        for index in range(start + 1, end):
            stripped = lines[index].strip()
            lower = stripped.lower()
            if (
                ";" in stripped
                and "(" not in stripped
                and any(hint in lower for hint in FIELD_HINTS)
                and len(fields) < MAX_FIELDS
            ):
                fields.append(stripped)

            rva_match = RVA_RE.search(lines[index])
            if rva_match and index + 1 < end and len(methods) < MAX_METHODS:
                signature = lines[index + 1].strip()
                if "(" in signature:
                    methods.append(
                        {
                            "rva": int(rva_match.group(1), 16),
                            "signature": signature,
                        }
                    )

        output.append(
            {
                "type": name,
                "declaration": declaration,
                "selected_fields": fields,
                "methods": methods,
            }
        )
    return output


def script_methods(path: Path, selected_types: tuple[str, ...]) -> list[dict[str, Any]]:
    """Return methods owned by exact selected types, not substring-matched closures."""

    doc = json.loads(path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    owner_tokens = tuple(f".{type_name}$$" for type_name in selected_types)
    bare_tokens = tuple(f"{type_name}$$" for type_name in selected_types)
    for raw in doc.get("ScriptMethod", []):
        name = str(raw.get("Name") or "")
        if not any(token in name for token in owner_tokens) and not name.startswith(bare_tokens):
            continue
        rows.append(
            {
                "name": name,
                "address": as_int(raw.get("Address", 0)),
                "signature": raw.get("Signature"),
            }
        )
    rows.sort(key=lambda row: (row["address"], row["name"]))
    if len(rows) > MAX_SCRIPT_METHODS:
        raise RuntimeError(
            f"exact UnitEdit type-owned method surface unexpectedly large: {len(rows)}"
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-map", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    api_map = json.loads(args.api_map.read_text(encoding="utf-8"))
    lines = args.dump_cs.read_text(encoding="utf-8", errors="replace").splitlines()
    endpoints = endpoint_rows(api_map)
    types = type_blocks(lines)
    methods = script_methods(args.script_json, tuple(row["type"] for row in types))

    report = {
        "schema": 2,
        "target": "unit-edit",
        "endpoint_count": len(endpoints),
        "type_count": len(types),
        "script_method_count": len(methods),
        "endpoints": endpoints,
        "types": types,
        "script_methods": methods,
        "evidence_boundary": {
            "api_map": "exact final 11.6.3 delivered map",
            "types": "exact final 11.6.3 Il2CppDumper metadata",
            "methods": "exact final 11.6.3 Il2CppDumper script metadata constrained by selected types",
            "runtime_acceptance": False,
            "ui_visible_success": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "endpoints": endpoints,
        "type_names": [row["type"] for row in types],
        "types": types,
        "script_methods": methods,
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
