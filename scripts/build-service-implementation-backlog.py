#!/usr/bin/env python3
"""C16: turn C14 into an evidence-aware full-service implementation backlog.

The ranking deliberately discounts contract pieces already supplied by the generic
server envelope: common ``Stage.BaseTask`` overlays and concrete reads of
``data_headers/result_code/servertime/sid``.  It does not infer response values.
The goal is to identify which of the remaining final-client routes can be
reconstructed next with the least unresolved parser/state surface.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.api_registry import BOOTSTRAP_HTTP_ROUTES  # noqa: E402

SCHEMA = 1
ENVELOPE_FIELDS = {"data_headers", "result_code", "servertime", "sid"}
TIER_ORDER = {
    "bootstrap-owned": 0,
    "c15-empty-baseline": 1,
    "envelope-only": 2,
    "shape-only-low": 3,
    "shape-plus-base-low": 4,
    "state-light-no-unknown": 5,
    "large-shape": 6,
    "complex-state": 7,
    "unknown-cfg": 8,
    "ambiguous-route": 9,
}
EXPECTED_FINAL_TIER_COUNTS = {
    "ambiguous-route": 9,
    "bootstrap-owned": 5,
    "c15-empty-baseline": 154,
    "complex-state": 102,
    "envelope-only": 1,
    "large-shape": 26,
    "shape-only-low": 76,
    "shape-plus-base-low": 24,
    "state-light-no-unknown": 115,
    "unknown-cfg": 14,
}


class BacklogError(ValueError):
    pass


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BacklogError(f"could not read C14 catalog: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise BacklogError("C14 catalog must contain schema=1")
    if not isinstance(value.get("routes"), list):
        raise BacklogError("C14 catalog routes must be a list")
    return value


def _unresolved_metrics(endpoint: dict[str, Any]) -> dict[str, Any]:
    concrete_raw = endpoint.get("concrete_response_fields")
    overlays_raw = endpoint.get("effective_base_parsers")
    mutations = endpoint.get("exact_state_mutation_count")
    if not isinstance(concrete_raw, list) or not isinstance(overlays_raw, list):
        raise BacklogError("malformed C14 endpoint parser surfaces")
    if not isinstance(mutations, int) or mutations < 0:
        raise BacklogError("malformed C14 state mutation count")

    concrete = []
    for field in concrete_raw:
        if not isinstance(field, dict) or not isinstance(field.get("field"), str):
            raise BacklogError("malformed C14 concrete response field")
        if field["field"] not in ENVELOPE_FIELDS:
            concrete.append(field)

    non_common = []
    for overlay in overlays_raw:
        if not isinstance(overlay, dict):
            raise BacklogError("malformed C14 effective base parser")
        if overlay.get("response_scope") != "common-envelope":
            non_common.append(overlay)

    base_fields = []
    for overlay in non_common:
        fields = overlay.get("fields")
        if not isinstance(fields, list):
            raise BacklogError("malformed C14 effective base parser fields")
        for field in fields:
            if not isinstance(field, dict) or not isinstance(field.get("field"), str):
                raise BacklogError("malformed C14 effective base field")
            base_fields.append(field)

    concrete_unknown = sum(field.get("requiredness") == "unknown-cfg" for field in concrete)
    base_unknown = sum(field.get("requiredness") == "unknown-cfg" for field in base_fields)
    concrete_required = sum(field.get("requiredness") == "required-path" for field in concrete)
    base_required = sum(field.get("requiredness") == "required-path" for field in base_fields)
    data_shape_hints = sorted(
        {
            value_type
            for field in concrete + base_fields
            if field.get("field") == "data"
            for value_type in field.get("value_types", [])
            if isinstance(value_type, str)
        }
    )
    return {
        "concrete_fields": concrete,
        "non_common_base_overlays": non_common,
        "concrete_field_count": len(concrete),
        "concrete_required_count": concrete_required,
        "concrete_unknown_count": concrete_unknown,
        "base_field_count": len(base_fields),
        "base_required_count": base_required,
        "base_unknown_count": base_unknown,
        "non_common_base_parser_count": len(non_common),
        "state_mutation_count": mutations,
        "data_shape_hints": data_shape_hints,
    }


def _is_c15(route: str, endpoint: dict[str, Any]) -> bool:
    if route in BOOTSTRAP_HTTP_ROUTES:
        return False
    if endpoint.get("concrete_response_fields"):
        return False
    if endpoint.get("exact_state_mutation_count") != 0:
        return False
    overlays = endpoint.get("effective_base_parsers")
    return isinstance(overlays, list) and all(
        isinstance(overlay, dict) and overlay.get("response_scope") == "common-envelope"
        for overlay in overlays
    )


def _tier(route: str, endpoint_count: int, endpoint: dict[str, Any] | None) -> tuple[str, dict[str, Any] | None]:
    if endpoint_count != 1:
        return "ambiguous-route", None
    assert endpoint is not None
    if route in BOOTSTRAP_HTTP_ROUTES:
        return "bootstrap-owned", _unresolved_metrics(endpoint)
    if _is_c15(route, endpoint):
        return "c15-empty-baseline", _unresolved_metrics(endpoint)

    metrics = _unresolved_metrics(endpoint)
    unknown = metrics["concrete_unknown_count"] + metrics["base_unknown_count"]
    total_fields = metrics["concrete_field_count"] + metrics["base_field_count"]
    mutations = metrics["state_mutation_count"]
    non_common = metrics["non_common_base_parser_count"]

    if unknown == 0 and mutations == 0 and total_fields == 0:
        return "envelope-only", metrics
    if unknown == 0 and mutations == 0 and non_common == 0 and metrics["concrete_field_count"] <= 3:
        return "shape-only-low", metrics
    if unknown == 0 and mutations == 0 and total_fields <= 8:
        return "shape-plus-base-low", metrics
    if unknown == 0 and mutations <= 2 and total_fields <= 8:
        return "state-light-no-unknown", metrics
    if unknown > 0:
        return "unknown-cfg", metrics
    if mutations > 2:
        return "complex-state", metrics
    return "large-shape", metrics


def build(catalog: dict[str, Any], *, enforce_final_counts: bool = True) -> dict[str, Any]:
    rows = []
    counts: Counter[str] = Counter()
    seen: set[str] = set()
    for route_row in catalog["routes"]:
        if not isinstance(route_row, dict):
            raise BacklogError("malformed C14 route row")
        route = route_row.get("route")
        endpoints = route_row.get("endpoints")
        if not isinstance(route, str) or not route.startswith("/") or route in seen:
            raise BacklogError(f"duplicate/invalid C14 route: {route!r}")
        if not isinstance(endpoints, list) or not endpoints:
            raise BacklogError(f"malformed C14 endpoints for {route}")
        seen.add(route)
        endpoint = endpoints[0] if len(endpoints) == 1 else None
        if endpoint is not None and not isinstance(endpoint, dict):
            raise BacklogError(f"malformed C14 endpoint for {route}")
        tier, metrics = _tier(route, len(endpoints), endpoint)
        counts[tier] += 1
        if endpoint is None:
            endpoint_ids = [
                item.get("endpoint_id") for item in endpoints if isinstance(item, dict)
            ]
            rows.append(
                {
                    "route": route,
                    "tier": tier,
                    "candidate_endpoint_ids": endpoint_ids,
                    "next_action": "resolve_endpoint_identity_before_modeling",
                }
            )
            continue

        subsystems = endpoint.get("inferred_subsystems")
        if not isinstance(subsystems, list):
            raise BacklogError(f"malformed C14 subsystems for {route}")
        assert metrics is not None
        row = {
            "route": route,
            "endpoint_id": endpoint.get("endpoint_id"),
            "tier": tier,
            "subsystems": sorted(set(item for item in subsystems if isinstance(item, str))),
            "concrete_field_count": metrics["concrete_field_count"],
            "concrete_required_count": metrics["concrete_required_count"],
            "concrete_unknown_count": metrics["concrete_unknown_count"],
            "non_common_base_parser_count": metrics["non_common_base_parser_count"],
            "base_field_count": metrics["base_field_count"],
            "base_required_count": metrics["base_required_count"],
            "base_unknown_count": metrics["base_unknown_count"],
            "state_mutation_count": metrics["state_mutation_count"],
            "data_shape_hints": metrics["data_shape_hints"],
            "next_action": (
                "already-served-by-specialized-bootstrap"
                if tier == "bootstrap-owned"
                else "runtime-validate-c15-baseline"
                if tier == "c15-empty-baseline"
                else "define-offline-semantics-before-enabling"
                if tier == "envelope-only"
                else "reconstruct-response-shape"
                if tier in {"shape-only-low", "shape-plus-base-low"}
                else "reconstruct-shape-and-state-transition"
                if tier in {"state-light-no-unknown", "complex-state"}
                else "close-unknown-cfg-before-modeling"
                if tier == "unknown-cfg"
                else "reconstruct-large-response-shape"
            ),
        }
        rows.append(row)

    tier_counts = dict(sorted(counts.items()))
    if enforce_final_counts:
        if catalog.get("endpoint_count") != 538 or catalog.get("unique_route_count") != 526:
            raise BacklogError("C14 final endpoint/route counts do not match frozen final-client evidence")
        if tier_counts != EXPECTED_FINAL_TIER_COUNTS:
            raise BacklogError(f"C16 final tier-count mismatch: {tier_counts!r}")

    rows.sort(
        key=lambda row: (
            TIER_ORDER[row["tier"]],
            row.get("concrete_unknown_count", 999),
            row.get("base_unknown_count", 999),
            row.get("state_mutation_count", 999),
            row.get("concrete_field_count", 999) + row.get("base_field_count", 999),
            row["route"],
        )
    )
    return {
        "schema": SCHEMA,
        "scope": (
            "C16 full-service implementation backlog from C14; common success-envelope "
            "surfaces discounted; no response values inferred"
        ),
        "endpoint_count": catalog.get("endpoint_count"),
        "unique_route_count": catalog.get("unique_route_count"),
        "tier_counts": tier_counts,
        "routes": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--effective-runtime-catalog", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = build(_load(args.effective_runtime_catalog))
    except BacklogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report["tier_counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
