#!/usr/bin/env python3
"""C25: overlay bounded C24 recursive-helper shape evidence onto frozen C22.

C22 is intentionally immutable evidence.  C24 proved five additional routes are
objects by following the exact tainted ``data`` value through bounded direct
managed helpers.  C25 creates a new catalog rather than rewriting C22 in place.

Only ``helper-proven-object`` / ``helper-proven-array`` C24 results may replace an
older C22 shape.  Empty-value proof and untouched-client acceptance remain exactly
as conservative as C22: no response values are manufactured.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = 1
EXPECTED_ROUTE_COUNT = 76


class C25Error(ValueError):
    pass


def load(path: Path, label: str) -> dict[str, Any]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise C25Error(f"could not read {label}: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("schema") != 1:
        raise C25Error(f"{label} must contain schema=1")
    return doc


def index_routes(doc: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    rows = doc.get("routes")
    if not isinstance(rows, list):
        raise C25Error(f"{label} routes must be a list")
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("route"), str):
            raise C25Error(f"malformed {label} route row")
        route = row["route"]
        if route in out:
            raise C25Error(f"duplicate {label} route {route}")
        out[route] = row
    return out


def build(c22: dict[str, Any], c24: dict[str, Any]) -> dict[str, Any]:
    i22 = index_routes(c22, "C22")
    i24 = index_routes(c24, "C24")
    if len(i22) != EXPECTED_ROUTE_COUNT or c22.get("route_count") != EXPECTED_ROUTE_COUNT:
        raise C25Error(f"unexpected C22 route count: {len(i22)}")
    if c22.get("parser_local_empty_value_proven_route_count") != 0:
        raise C25Error("C22 unexpectedly contains empty-value proof")
    if c22.get("untouched_client_accepted_route_count") != 0:
        raise C25Error("C22 unexpectedly claims untouched-client acceptance")
    if c24.get("target_route_count") != len(i24):
        raise C25Error("C24 target count mismatch")
    if not set(i24) <= set(i22):
        raise C25Error("C24 contains route outside C22")

    rows: list[dict[str, Any]] = []
    overlay_routes: list[str] = []
    shape_counts: Counter[str] = Counter()
    source_counts: Counter[str] = Counter()
    empty_counts: Counter[str] = Counter()
    consumer_counts: Counter[str] = Counter()

    for route in sorted(i22):
        old = dict(i22[route])
        rec = i24.get(route)
        if rec is not None:
            refined = rec.get("recursive_shape_refinement")
            if refined == "helper-proven-object":
                old["effective_shape"] = "proven-object"
                old["effective_shape_source"] = "C24-recursive-helper-json-operations"
                old["c24_recursive_shape_refinement"] = refined
                old["c24_visited_helper_count"] = rec.get("visited_helper_count")
                overlay_routes.append(route)
            elif refined == "helper-proven-array":
                old["effective_shape"] = "proven-array"
                old["effective_shape_source"] = "C24-recursive-helper-json-operations"
                old["c24_recursive_shape_refinement"] = refined
                old["c24_visited_helper_count"] = rec.get("visited_helper_count")
                overlay_routes.append(route)
            elif refined not in {"helper-unresolved", "helper-opaque-json", "helper-countable-ambiguous"}:
                raise C25Error(f"unsupported C24 refinement for {route}: {refined!r}")

        # C24 is shape-only.  It must not silently promote empty values or client acceptance.
        if old.get("empty_value_status") != "not-proven":
            raise C25Error(f"unexpected empty-value promotion for {route}")
        if old.get("untouched_client_acceptance") is not False:
            raise C25Error(f"unexpected client acceptance claim for {route}")
        old["static_evidence_only"] = True
        old["next_action"] = (
            "device/runtime-observation-or-deeper-empty-value-proof"
            if old.get("effective_shape") in {
                "proven-object", "proven-array", "countable-collection-ambiguous"
            }
            else "reconstruct-business-value-semantics"
        )
        rows.append(old)
        shape_counts[str(old.get("effective_shape"))] += 1
        source_counts[str(old.get("effective_shape_source"))] += 1
        empty_counts[str(old.get("empty_value_status"))] += 1
        consumer_counts[str(old.get("consumer_resolution"))] += 1

    return {
        "schema": SCHEMA,
        "generation": "C25",
        "scope": (
            "C25 final-client low-complexity response evidence: frozen C22 plus bounded C24 "
            "recursive direct-helper shape overlays; empty values and untouched-client acceptance remain unproven"
        ),
        "source_c22_route_count": len(i22),
        "source_c24_route_count": len(i24),
        "c24_shape_overlay_route_count": len(overlay_routes),
        "c24_shape_overlay_routes": overlay_routes,
        "route_count": len(rows),
        "effective_shape_counts": dict(sorted(shape_counts.items())),
        "effective_shape_source_counts": dict(sorted(source_counts.items())),
        "empty_value_status_counts": dict(sorted(empty_counts.items())),
        "consumer_resolution_counts": dict(sorted(consumer_counts.items())),
        "parser_local_empty_value_proven_route_count": 0,
        "untouched_client_accepted_route_count": 0,
        "routes": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c22", type=Path, required=True)
    parser.add_argument("--c24", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = build(load(args.c22, "C22"), load(args.c24, "C24"))
    except C25Error as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "route_count": report["route_count"],
        "c24_shape_overlay_route_count": report["c24_shape_overlay_route_count"],
        "c24_shape_overlay_routes": report["c24_shape_overlay_routes"],
        "effective_shape_counts": report["effective_shape_counts"],
        "effective_shape_source_counts": report["effective_shape_source_counts"],
        "empty_value_status_counts": report["empty_value_status_counts"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
