#!/usr/bin/env python3
"""Targeted exact-final discovery for card-favorite mutation contracts.

This first stage deliberately does not assume a production route/type name. It
emits only sanitized derived metadata:

* exact final ApiType rows whose name/path contains ``favorite``;
* exact final managed type names containing ``favorite``;
* bounded details for likely task/param/card/member types among those candidates.

The report is discovery evidence only. It does not claim that every favorite row
mutates CardOwnership.favorite, and it exports no raw specimen or bulk dump.
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
    "favorite", "serial", "card", "member", "idol", "flag", "unit", "id", "param"
)
DETAIL_HINTS = ("task", "param", "card", "member")
MAX_CANDIDATE_TYPES = 160
MAX_DETAILED_TYPES = 48
MAX_BLOCK_LINES = 320
MAX_FIELDS = 80
MAX_METHODS = 120


def endpoint_rows(doc: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for group in ("A", "B"):
        for raw in doc[group]:
            name, key, path, literal_index = raw
            text = f"{name} {path}".lower()
            if "favorite" not in text:
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


def discover_headers(lines: list[str]) -> list[tuple[int, str, str]]:
    headers: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines):
        match = TYPE_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if "favorite" in name.lower():
            headers.append((index, name, line.strip()))
    if len(headers) > MAX_CANDIDATE_TYPES:
        raise RuntimeError(f"favorite managed type surface unexpectedly large: {len(headers)}")
    return headers


def should_detail(name: str) -> bool:
    lower = name.lower()
    return any(hint in lower for hint in DETAIL_HINTS)


def detailed_blocks(
    lines: list[str], headers: list[tuple[int, str, str]]
) -> list[dict[str, Any]]:
    selected = [header for header in headers if should_detail(header[1])]
    if len(selected) > MAX_DETAILED_TYPES:
        raise RuntimeError(f"favorite detailed type surface unexpectedly large: {len(selected)}")

    output: list[dict[str, Any]] = []
    for start, name, declaration in selected:
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
    headers = discover_headers(lines)
    details = detailed_blocks(lines, headers)

    report = {
        "schema": 1,
        "target": "card-favorite-discovery",
        "endpoint_count": len(endpoints),
        "candidate_type_count": len(headers),
        "detailed_type_count": len(details),
        "endpoints": endpoints,
        "candidate_type_names": [name for _, name, _ in headers],
        "types": details,
        "evidence_boundary": {
            "api_map": "exact final 11.6.3 delivered map",
            "types": "exact final 11.6.3 Il2CppDumper managed metadata",
            "card_favorite_binding": "not established by discovery alone",
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
