#!/usr/bin/env python3
"""Discover managed consumers of the final client's separate ``Common.ApiType``.

The B-group VR/login endpoint dictionary has its own ``Common.ApiType::.cctor`` but
there is no second class literally named ``Common.NetworkTask``.  Rather than guess
a root, this pass walks the exact Il2CppDumper ``dump.cs`` type blocks and records
bounded declarations/signatures that reference ``Common.ApiType`` or its nested
``Type`` enum.  It then joins those owners to ``script.json`` method RVAs so later
passes can target the actual consumer/factory stack.

Only declaration-level metadata is emitted; no method bodies or bulk dump text leave
the CI work directory.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 1
TARGETS = ("Common.ApiType.Type", "Common.ApiType")
MAX_BLOCK_LINES = 8192
MAX_MATCHES_PER_TYPE = 96
MAX_METHODS_PER_OWNER = 256

_NAMESPACE_RE = re.compile(r"^\s*//\s*Namespace:\s*(.*)\s*$")
_TYPE_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)?\s*"
    r"(?:(?:sealed|abstract|static|partial|readonly)\s+)*"
    r"(?:class|struct|enum|interface)\s+([^\s:{]+)"
)
_RVA_RE = re.compile(r"RVA:\s*0x([0-9A-Fa-f]+)")


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def clean_declaration(line: str) -> str:
    text = line.strip()
    # Keep declarations compact and deterministic. Attribute-only and pure address
    # comments are useful only when immediately paired with a matching declaration,
    # so they are handled separately by the caller.
    return text[:420]


def parse_type_blocks(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    namespace = ""
    result: list[dict[str, Any]] = []
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

        matches: list[dict[str, Any]] = []
        cursor = i + 1
        depth = 0
        opened = False
        pending_rva: int | None = None
        for _ in range(MAX_BLOCK_LINES):
            if cursor >= len(lines):
                break
            line = lines[cursor]
            stripped = line.strip()
            depth += line.count("{")
            if "{" in line:
                opened = True

            rva_match = _RVA_RE.search(line)
            if rva_match:
                pending_rva = int(rva_match.group(1), 16)

            if any(target in line for target in TARGETS):
                # Skip the target type's own nested/static declarations only when
                # they are not useful as a consumer.  Keep Common.ApiType itself in
                # a separate flag for provenance.
                kind = "declaration"
                if "(" in stripped and ")" in stripped:
                    kind = "method-signature"
                elif ";" in stripped:
                    kind = "field-or-property"
                matches.append(
                    {
                        "line": cursor + 1,
                        "kind": kind,
                        "text": clean_declaration(line),
                        "preceding_rva": pending_rva,
                    }
                )
                if len(matches) > MAX_MATCHES_PER_TYPE:
                    raise RuntimeError(f"too many Common.ApiType matches in {full_name}")
                pending_rva = None
            elif stripped and not stripped.startswith("//") and not stripped.startswith("["):
                # Do not accidentally attach an unrelated previous RVA comment to
                # a later declaration.
                if "(" in stripped or ";" in stripped:
                    pending_rva = None

            depth -= line.count("}")
            if opened and depth <= 0 and stripped == "}":
                break
            cursor += 1

        if matches or full_name == "Common.ApiType":
            result.append(
                {
                    "type": full_name,
                    "namespace": namespace,
                    "base": base,
                    "line": i + 1,
                    "is_common_apitype": full_name == "Common.ApiType",
                    "matches": matches,
                }
            )
        i = max(i + 1, cursor + 1)
    return result


def load_methods(path: Path) -> dict[str, list[dict[str, Any]]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in raw.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        name = str(item.get("Name", ""))
        if address <= 0 or "$$" not in name:
            continue
        owner, member = name.split("$$", 1)
        result[owner].append(
            {
                "name": name,
                "member": member,
                "rva": address,
                "signature": item.get("Signature"),
            }
        )
    for owner, rows in result.items():
        rows.sort(key=lambda row: (row["rva"], row["member"]))
        if len(rows) > MAX_METHODS_PER_OWNER:
            # A high-method-count consumer owner is still useful. Keep the report
            # bounded instead of failing the entire specimen run.
            result[owner] = rows[:MAX_METHODS_PER_OWNER]
    return result


def owner_methods(index: dict[str, list[dict[str, Any]]], owner: str) -> list[dict[str, Any]]:
    if owner in index:
        return index[owner]
    short = owner.rsplit(".", 1)[-1]
    candidates = [rows for key, rows in index.items() if key.rsplit(".", 1)[-1] == short]
    return candidates[0] if len(candidates) == 1 else []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    blocks = parse_type_blocks(args.dump_cs)
    method_index = load_methods(args.script_json)

    consumers = []
    for block in blocks:
        methods = owner_methods(method_index, block["type"])
        matched_rvas = {m["preceding_rva"] for m in block["matches"] if m["preceding_rva"]}
        matched_methods = [row for row in methods if row["rva"] in matched_rvas]
        # If Il2CppDumper declaration/RVA adjacency changed, preserve the owner
        # method inventory so the next pass still has a bounded target set.
        consumers.append(
            {
                **block,
                "script_method_count": len(methods),
                "matched_script_methods": matched_methods,
                "owner_method_sample": methods[:64],
            }
        )

    consumers.sort(
        key=lambda row: (
            row["is_common_apitype"],
            -len(row["matches"]),
            row["type"],
        )
    )
    report = {
        "schema": SCHEMA,
        "target": "Common.ApiType / Common.ApiType.Type",
        "consumer_type_count": sum(not row["is_common_apitype"] for row in consumers),
        "consumers": consumers,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if not any(row["is_common_apitype"] for row in consumers):
        raise RuntimeError("Common.ApiType type block not found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
