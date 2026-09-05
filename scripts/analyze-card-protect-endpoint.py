#!/usr/bin/env python3
"""Targeted final-client discovery for card protection mutation contracts.

This pass intentionally emits only sanitized derived metadata:
- exact final ApiType entries whose enum/path contains ``protect``;
- exact Il2CppDumper type names containing ``protect``;
- selected field declarations and method signatures from those type blocks.

It does not emit dump.cs, raw metadata, binaries, or bulk decompilation.  The goal is
to establish whether final 11.6.3 exposes a dedicated protection endpoint and which
NetworkTask/parameter types own that contract before implementing a server command.
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
FIELD_HINTS = ("serial", "protect", "card", "favorite", "flag", "id")
MAX_BLOCK_LINES = 220
MAX_FIELDS = 32
MAX_METHODS = 64


def endpoint_rows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for group in ("A", "B"):
        for raw in doc[group]:
            name, key, path, literal_index = raw
            if "protect" not in str(name).lower() and "protect" not in str(path).lower():
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
        if "protect" not in name.lower():
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-map", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    api_map = json.loads(args.api_map.read_text(encoding="utf-8"))
    lines = args.dump_cs.read_text(encoding="utf-8", errors="replace").splitlines()
    endpoints = endpoint_rows(api_map)
    types = type_blocks(lines)

    report = {
        "schema": 1,
        "target": "card-protect",
        "endpoint_count": len(endpoints),
        "type_count": len(types),
        "endpoints": endpoints,
        "types": types,
        "evidence_boundary": {
            "api_map": "exact final 11.6.3 delivered map",
            "types": "exact final 11.6.3 Il2CppDumper metadata",
            "runtime_acceptance": False,
            "ui_visible_success": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "endpoint_count": len(endpoints),
        "endpoints": endpoints,
        "type_count": len(types),
        "type_names": [row["type"] for row in types],
    }, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
