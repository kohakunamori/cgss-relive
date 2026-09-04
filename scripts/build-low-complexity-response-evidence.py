#!/usr/bin/env python3
"""C22: merge C17/C19b/C19c/C20/C21 low-complexity response evidence.

The catalog deliberately separates three questions that earlier passes answer at
different confidence levels:

* ``effective_shape``: what JSON value shape is proven by parser/helper evidence;
* ``empty_value_status``: whether an empty object/array has a parser-local zero
  path to a known exit;
* ``consumer``: where an opaque top-level ``data`` value is first consumed.

No response value is generated.  In particular, a proven object/array shape does
not imply that ``{}``/``[]`` is accepted, and parser-local empty-value proof would
still remain below untouched-client/device acceptance.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SCHEMA = 1


class CatalogError(ValueError):
    pass


def load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogError(f"could not read {label}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise CatalogError(f"{label} must contain schema=1")
    return value


def route_index(report: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
    rows = report.get("routes")
    if not isinstance(rows, list):
        raise CatalogError(f"{label} must contain routes")
    out: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("route"), str):
            raise CatalogError(f"malformed {label} route row")
        route = row["route"]
        if route in out:
            raise CatalogError(f"duplicate {label} route {route}")
        out[route] = row
    return out


def c17_base_shape(row: dict[str, Any]) -> str:
    klass = str(row.get("route_class") or "")
    prefix = "data-only:"
    if klass.startswith(prefix):
        return klass[len(prefix):]
    return "multi-field"


def effective_shape_for(
    c17_row: dict[str, Any],
    c19c_row: dict[str, Any] | None,
    c21_row: dict[str, Any] | None,
) -> tuple[str, str]:
    base = c17_base_shape(c17_row)
    if c21_row is not None:
        refined = str(c21_row.get("shape_refinement") or "")
        if refined == "helper-proven-object":
            return "proven-object", "C21-helper-json-operations"
        if refined == "helper-proven-array":
            return "proven-array", "C21-helper-json-operations"
        if refined == "helper-countable-ambiguous":
            return "countable-collection-ambiguous", "C21-helper-json-operations"
    if c19c_row is not None:
        usage = str(c19c_row.get("container_usage_class") or "")
        if usage == "string-key-object":
            return "proven-object", "C19c-string-key-get_Item-signature"
        if usage == "integer-index-sequence":
            return "proven-array", "C19c-integer-index-get_Item-signature"
        if usage == "count-only-no-index":
            return "countable-collection-ambiguous", "C19c-count-only"
    return base, "C17-direct-parser-shape"


def empty_status_for(
    c19b_row: dict[str, Any] | None,
    c19c_row: dict[str, Any] | None,
) -> tuple[str, str | None]:
    if c19b_row is not None and c19b_row.get("parser_empty_object_class") == "parser-empty-object-zero-path":
        return "parser-local-empty-object-zero-path", "C19b"
    if c19c_row is not None:
        klass = c19c_row.get("parser_empty_container_class")
        if klass == "parser-empty-object-zero-path":
            return "parser-local-empty-object-zero-path", "C19c"
        if klass == "parser-empty-sequence-zero-path":
            return "parser-local-empty-array-zero-path", "C19c"
    return "not-proven", None


def build(
    c17: dict[str, Any],
    c19b: dict[str, Any],
    c19c: dict[str, Any],
    c20: dict[str, Any],
    c21: dict[str, Any],
) -> dict[str, Any]:
    i17 = route_index(c17, "C17")
    i19b = route_index(c19b, "C19b")
    i19c = route_index(c19c, "C19c")
    i20 = route_index(c20, "C20")
    i21 = route_index(c21, "C21")
    if len(i17) != 76:
        raise CatalogError(f"expected 76 C17 routes, got {len(i17)}")
    if not set(i19b) <= set(i17) or not set(i19c) <= set(i17) or not set(i20) <= set(i17) or not set(i21) <= set(i17):
        raise CatalogError("downstream evidence contains route outside C17 scope")

    rows = []
    shape_counts: Counter[str] = Counter()
    empty_counts: Counter[str] = Counter()
    consumer_counts: Counter[str] = Counter()
    shape_source_counts: Counter[str] = Counter()
    for route in sorted(i17):
        base = i17[route]
        r19b, r19c, r20, r21 = i19b.get(route), i19c.get(route), i20.get(route), i21.get(route)
        shape, shape_source = effective_shape_for(base, r19c, r21)
        empty_status, empty_source = empty_status_for(r19b, r19c)
        consumer_resolution = str(r20.get("consumer_resolution")) if r20 is not None else "not-applicable"
        shape_counts[shape] += 1
        empty_counts[empty_status] += 1
        consumer_counts[consumer_resolution] += 1
        shape_source_counts[shape_source] += 1
        first_consumer = r20.get("first_direct_managed_consumer") if r20 is not None else None
        rows.append({
            "route": route,
            "endpoint_id": base.get("endpoint_id"),
            "c17_route_class": base.get("route_class"),
            "c17_fields": base.get("fields", []),
            "effective_shape": shape,
            "effective_shape_source": shape_source,
            "empty_value_status": empty_status,
            "empty_value_source": empty_source,
            "consumer_resolution": consumer_resolution,
            "first_direct_managed_consumer": first_consumer,
            "c21_shape_refinement": r21.get("shape_refinement") if r21 is not None else None,
            "next_action": (
                "device/runtime-observation-or-deeper-empty-value-proof"
                if empty_status == "not-proven" and shape in {"proven-object", "proven-array", "countable-collection-ambiguous"}
                else "reconstruct-business-value-semantics"
            ),
            "static_evidence_only": True,
            "untouched_client_acceptance": False,
        })

    return {
        "schema": SCHEMA,
        "scope": (
            "C22 merged final-client low-complexity response evidence; shapes, empty-value proof, "
            "and consumer provenance remain separate; no response values generated"
        ),
        "route_count": len(rows),
        "effective_shape_counts": dict(sorted(shape_counts.items())),
        "effective_shape_source_counts": dict(sorted(shape_source_counts.items())),
        "empty_value_status_counts": dict(sorted(empty_counts.items())),
        "consumer_resolution_counts": dict(sorted(consumer_counts.items())),
        "parser_local_empty_value_proven_route_count": sum(v for k, v in empty_counts.items() if k != "not-proven"),
        "untouched_client_accepted_route_count": 0,
        "routes": rows,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--c17", type=Path, required=True)
    p.add_argument("--c19b", type=Path, required=True)
    p.add_argument("--c19c", type=Path, required=True)
    p.add_argument("--c20", type=Path, required=True)
    p.add_argument("--c21", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        report = build(
            load(args.c17, "C17"), load(args.c19b, "C19b"), load(args.c19c, "C19c"),
            load(args.c20, "C20"), load(args.c21, "C21"),
        )
    except CatalogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "route_count": report["route_count"],
        "effective_shape_counts": report["effective_shape_counts"],
        "effective_shape_source_counts": report["effective_shape_source_counts"],
        "empty_value_status_counts": report["empty_value_status_counts"],
        "consumer_resolution_counts": report["consumer_resolution_counts"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
