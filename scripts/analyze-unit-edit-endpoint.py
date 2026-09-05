#!/usr/bin/env python3
"""Targeted exact-final discovery for the UnitEdit mutation contract.

The first-stage report deliberately stops at managed metadata. It emits only:
- exact final ApiType entries whose enum/path contains both ``unit`` and ``edit``;
- bounded UnitEdit-related type names from exact final ``dump.cs``;
- detailed fields/method signatures/RVAs only for likely task/param/data contract types.

A later native pass can take the few resulting RVAs as explicit inputs. No raw
binary, bulk script.json surface, dump.cs, or decompilation is emitted.
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
DETAIL_HINTS = ("task", "param", "request", "response", "data")
MAX_BLOCK_LINES = 320
MAX_CANDIDATE_TYPES = 120
MAX_DETAILED_TYPES = 30
MAX_FIELDS = 80
MAX_METHODS = 100


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


def discover_type_headers(lines: list[str]) -> list[tuple[int, str, str]]:
    headers: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines):
        match = TYPE_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if "unitedit" in name.lower():
            headers.append((index, name, line.strip()))
    if len(headers) > MAX_CANDIDATE_TYPES:
        raise RuntimeError(
            f"UnitEdit managed type surface unexpectedly large: {len(headers)}"
        )
    return headers


def is_contract_type(name: str) -> bool:
    lower = name.lower()
    return lower == "unitedit" or any(hint in lower for hint in DETAIL_HINTS)


def detailed_type_blocks(
    lines: list[str], headers: list[tuple[int, str, str]]
) -> list[dict[str, Any]]:
    selected = [header for header in headers if is_contract_type(header[1])]
    if len(selected) > MAX_DETAILED_TYPES:
        raise RuntimeError(
            f"UnitEdit contract-type surface unexpectedly large: {len(selected)}"
        )

    output: list[dict[str, Any]] = []
    all_type_starts = [index for index, _, _ in headers]
    for start, name, declaration in selected:
        end = min(len(lines), start + MAX_BLOCK_LINES)
        # Any next managed type declaration ends the current block, including one
        # that is unrelated to UnitEdit and therefore absent from ``headers``.
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
    headers = discover_type_headers(lines)
    types = detailed_type_blocks(lines, headers)

    report = {
        "schema": 3,
        "target": "unit-edit",
        "endpoint_count": len(endpoints),
        "candidate_type_count": len(headers),
        "detailed_type_count": len(types),
        "endpoints": endpoints,
        "candidate_type_names": [name for _, name, _ in headers],
        "types": types,
        "evidence_boundary": {
            "api_map": "exact final 11.6.3 delivered map",
            "types": "exact final 11.6.3 Il2CppDumper managed metadata",
            "native_flow": "not analyzed in this first-stage report",
            "runtime_acceptance": False,
            "ui_visible_success": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
