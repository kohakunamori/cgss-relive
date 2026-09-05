#!/usr/bin/env python3
"""C34: match the Concert polling FromJson object by exact field-offset fingerprint.

C32 proves the deserialized object is directly dereferenced at instance offsets
0x10, 0x18, 0x20, 0x28, 0x30 and 0x3c.  This pass searches final-client dump.cs
type metadata for classes/structs containing that complete non-static field
offset set.  Namespace/name context is reported only as metadata; candidacy is
based on the offset fingerprint itself.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
C33_PATH = ROOT / "scripts" / "analyze-jsonutility-task-dto-metadata-c33.py"
SPEC = importlib.util.spec_from_file_location("c33_metadata_for_c34", C33_PATH)
assert SPEC is not None and SPEC.loader is not None
C33 = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = C33
SPEC.loader.exec_module(C33)

SCHEMA = 1
TARGET_ROUTE = "/concert/mv_polling"
EXPECTED_ENDPOINT_ID = 306


class C34Error(ValueError):
    pass


def load_offsets(path: Path) -> list[int]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if doc.get("schema") != 1 or doc.get("route") != TARGET_ROUTE or doc.get("endpoint_id") != EXPECTED_ENDPOINT_ID:
        raise C34Error("unexpected C32 report")
    offsets = sorted({
        int(sink["offset"])
        for sink in doc.get("semantic_sinks", [])
        if isinstance(sink, dict)
        and sink.get("kind") == "dereference"
        and isinstance(sink.get("offset"), int)
    })
    expected = [16, 24, 32, 40, 48, 60]
    if offsets != expected:
        raise C34Error(f"unexpected polling DTO dereference fingerprint: {offsets}")
    return offsets


def build(dump_cs: Path, c32: Path) -> dict[str, Any]:
    required = load_offsets(c32)
    types = C33.parse_dump(dump_cs)
    candidates: list[dict[str, Any]] = []
    required_set = set(required)
    for type_name, entry in types.items():
        fields = [field for field in entry["fields"] if not field["is_static"]]
        offsets = {int(field["offset"]) for field in fields}
        if not required_set <= offsets:
            continue
        matched = [field for field in fields if int(field["offset"]) in required_set]
        extra = sorted(offsets - required_set)
        candidates.append({
            "type": type_name,
            "namespace": type_name.rsplit(".", 1)[0] if "." in type_name else "",
            "required_offset_match_count": len(matched),
            "exact_instance_offset_set_match": offsets == required_set,
            "instance_field_count": len(fields),
            "matched_fields": matched,
            "all_instance_fields": fields,
            "extra_instance_offsets": extra,
        })
    candidates.sort(key=lambda row: (
        not row["exact_instance_offset_set_match"],
        row["instance_field_count"],
        row["type"],
    ))
    return {
        "schema": SCHEMA,
        "scope": "C34 final-client dump.cs type candidates matching C32 polling DTO dereference offsets",
        "route": TARGET_ROUTE,
        "endpoint_id": EXPECTED_ENDPOINT_ID,
        "required_offsets": required,
        "candidate_type_count": len(candidates),
        "exact_offset_set_candidate_count": sum(1 for row in candidates if row["exact_instance_offset_set_match"]),
        "candidates": candidates,
        "selection_status": "offset-fingerprint-candidates-only",
        "untouched_client_acceptance": False,
        "ui_visible_success": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dump-cs", type=Path, required=True)
    p.add_argument("--c32", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        report = build(args.dump_cs, args.c32)
    except (OSError, json.JSONDecodeError, C34Error) as exc:
        print(f"error: {exc}", file=sys.stderr); return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps({
        "required_offsets": report["required_offsets"],
        "candidate_type_count": report["candidate_type_count"],
        "exact_offset_set_candidate_count": report["exact_offset_set_candidate_count"],
        "top_candidates": [
            {"type": r["type"], "exact": r["exact_instance_offset_set_match"], "fields": r["matched_fields"]}
            for r in report["candidates"][:20]
        ],
    }, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__": raise SystemExit(main())
