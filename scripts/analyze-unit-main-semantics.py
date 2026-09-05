#!/usr/bin/env python3
"""Recover exact managed metadata relevant to UnitEdit ``main_unit_id``.

This bounded pass selects only managed type blocks that own one of the final-client
methods used by the A:19 caller/serializer:

- WorkUnitData.GetMainUnit
- UnitData.GetUnitSerial
- UnitData.GetCostumeId
- UnitData.GetCostume2dId
- UnitData.GetClosetId

It emits the owning type declaration/namespace, field declarations with their dump
layout comments, and the small method surface for those blocks.  No raw specimen or
bulk dump content is emitted.
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
    r"(?:class|struct)\s+([^\s:{]+)"
)
RVA_RE = re.compile(r"//\s*RVA:\s*0x([0-9A-Fa-f]+)")
TARGET_METHODS = (
    "GetMainUnit(",
    "GetUnitSerial(",
    "GetCostumeId(",
    "GetCostume2dId(",
    "GetClosetId(",
)
MAX_TYPES = 12
MAX_FIELDS = 120
MAX_METHODS = 160


def namespace_before(lines: list[str], start: int) -> str | None:
    for index in range(start - 1, max(-1, start - 40), -1):
        stripped = lines[index].strip()
        if stripped.startswith("// Namespace:"):
            return stripped.split(":", 1)[1].strip()
        if TYPE_RE.match(lines[index]):
            break
    return None


def type_blocks(lines: list[str]) -> list[tuple[int, int, str, str]]:
    headers: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines):
        match = TYPE_RE.match(line)
        if match:
            headers.append((index, match.group(1), line.strip()))
    blocks: list[tuple[int, int, str, str]] = []
    for position, (start, name, declaration) in enumerate(headers):
        end = headers[position + 1][0] if position + 1 < len(headers) else len(lines)
        blocks.append((start, end, name, declaration))
    return blocks


def selected_blocks(lines: list[str]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for start, end, name, declaration in type_blocks(lines):
        block = lines[start:end]
        text = "\n".join(block)
        matched = [method for method in TARGET_METHODS if method in text]
        if not matched:
            continue

        fields: list[str] = []
        methods: list[dict[str, Any]] = []
        for index in range(start + 1, end):
            stripped = lines[index].strip()
            if ";" in stripped and "(" not in stripped and len(fields) < MAX_FIELDS:
                fields.append(stripped)
            rva = RVA_RE.search(lines[index])
            if rva and index + 1 < end and len(methods) < MAX_METHODS:
                signature = lines[index + 1].strip()
                if "(" in signature:
                    methods.append({"rva": int(rva.group(1), 16), "signature": signature})

        output.append(
            {
                "namespace": namespace_before(lines, start),
                "type": name,
                "declaration": declaration,
                "matched_methods": matched,
                "fields": fields,
                "methods": methods,
            }
        )
    if len(output) > MAX_TYPES:
        raise RuntimeError(f"main-unit target type surface unexpectedly large: {len(output)}")
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lines = args.dump_cs.read_text(encoding="utf-8", errors="replace").splitlines()
    types = selected_blocks(lines)
    if not any("GetMainUnit(" in row["matched_methods"] for row in types):
        raise RuntimeError("exact WorkUnitData.GetMainUnit owner was not recovered")
    if not any("GetUnitSerial(" in row["matched_methods"] for row in types):
        raise RuntimeError("exact UnitData.GetUnitSerial owner was not recovered")

    report = {
        "schema": 1,
        "target": "unit-edit-main-unit",
        "types": types,
        "evidence_boundary": {
            "source": "exact final 11.6.3 Il2CppDumper managed metadata",
            "native_identity_semantics": "not inferred from field names alone",
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
