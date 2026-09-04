#!/usr/bin/env python3
"""C17: refine low-complexity endpoint data shapes with exact C3 native evidence.

C14 intentionally retains only normalized value classes.  This pass rejoins the
sanitized C3 access-site report so we can distinguish why a field was labelled a
collection/json value: ``JsonData.get_IsArray``, ``get_IsObject``, ``get_Keys``,
``get_Count``, scalar conversions, or no stronger conversion at all.

No response value is emitted.  Even a proven array/object parser shape does not
prove that an *empty* container is semantically accepted by the endpoint's later
callback; that remains a separate promotion step.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.api_registry import BOOTSTRAP_HTTP_ROUTES  # noqa: E402

SCHEMA = 1
ENVELOPE_FIELDS = {"data_headers", "result_code", "servertime", "sid"}


class ShapeEvidenceError(ValueError):
    pass


def _load(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ShapeEvidenceError(f"could not read {label}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise ShapeEvidenceError(f"{label} must contain schema=1")
    return value


def _non_envelope_fields(endpoint: dict[str, Any]) -> list[dict[str, Any]]:
    fields = endpoint.get("concrete_response_fields")
    if not isinstance(fields, list):
        raise ShapeEvidenceError("malformed C14 concrete response fields")
    out = []
    for field in fields:
        if not isinstance(field, dict) or not isinstance(field.get("field"), str):
            raise ShapeEvidenceError("malformed C14 concrete response field")
        if field["field"] not in ENVELOPE_FIELDS:
            out.append(field)
    return out


def _non_common_base_count(endpoint: dict[str, Any]) -> int:
    overlays = endpoint.get("effective_base_parsers")
    if not isinstance(overlays, list):
        raise ShapeEvidenceError("malformed C14 effective base parser list")
    return sum(
        1
        for overlay in overlays
        if not isinstance(overlay, dict) or overlay.get("response_scope") != "common-envelope"
    )


def _is_shape_only_low(route: str, endpoints: list[Any]) -> bool:
    if len(endpoints) != 1 or route in BOOTSTRAP_HTTP_ROUTES:
        return False
    endpoint = endpoints[0]
    if not isinstance(endpoint, dict):
        raise ShapeEvidenceError(f"malformed C14 endpoint for {route}")
    mutations = endpoint.get("exact_state_mutation_count")
    if not isinstance(mutations, int) or mutations < 0:
        raise ShapeEvidenceError(f"malformed C14 state mutation count for {route}")
    fields = _non_envelope_fields(endpoint)
    if mutations != 0 or _non_common_base_count(endpoint) != 0 or not (1 <= len(fields) <= 3):
        return False
    return all(field.get("requiredness") != "unknown-cfg" for field in fields)


def _access_index(c3: dict[str, Any]) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    accesses = c3.get("accesses")
    if not isinstance(accesses, list):
        raise ShapeEvidenceError("C3 access report must contain accesses")
    index: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in accesses:
        if not isinstance(row, dict):
            raise ShapeEvidenceError("malformed C3 access row")
        task, method, field = row.get("task"), row.get("method"), row.get("field")
        if not all(isinstance(value, str) for value in (task, method, field)):
            raise ShapeEvidenceError("malformed C3 access identity")
        index[(task, method, field)].append(row)
    return index


def _shape_from_accesses(rows: list[dict[str, Any]]) -> tuple[str, list[str]]:
    conversion_names = sorted(
        {
            str(row["conversion_helper"])
            for row in rows
            if isinstance(row.get("conversion_helper"), str)
        }
    )
    value_types = sorted(
        {str(row["value_type"]) for row in rows if isinstance(row.get("value_type"), str)}
    )
    lower = "\n".join(conversion_names).lower()
    if "get_isarray" in lower or "array" in value_types:
        return "proven-array", conversion_names
    if "get_isobject" in lower or "get_keys" in lower or "object" in value_types:
        return "proven-object", conversion_names
    scalar_types = sorted(set(value_types) & {"int", "long", "bool", "string"})
    if scalar_types:
        return "proven-scalar:" + "+".join(scalar_types), conversion_names
    if "get_count" in lower or "collection" in value_types:
        return "countable-collection-ambiguous", conversion_names
    if value_types:
        return "opaque:" + "+".join(value_types), conversion_names
    return "unresolved-no-c3-access", conversion_names


def build(c14: dict[str, Any], c3: dict[str, Any]) -> dict[str, Any]:
    routes = c14.get("routes")
    if not isinstance(routes, list):
        raise ShapeEvidenceError("C14 catalog must contain routes")
    index = _access_index(c3)
    result_rows = []
    shape_counts: Counter[str] = Counter()
    route_class_counts: Counter[str] = Counter()

    for route_row in routes:
        if not isinstance(route_row, dict) or not isinstance(route_row.get("route"), str):
            raise ShapeEvidenceError("malformed C14 route row")
        route = route_row["route"]
        endpoints = route_row.get("endpoints")
        if not isinstance(endpoints, list) or not endpoints:
            raise ShapeEvidenceError(f"malformed C14 endpoint list for {route}")
        if not _is_shape_only_low(route, endpoints):
            continue
        endpoint = endpoints[0]
        fields = _non_envelope_fields(endpoint)
        field_rows = []
        for field in fields:
            key = (str(field.get("task")), str(field.get("method")), field["field"])
            accesses = index.get(key, [])
            shape, conversions = _shape_from_accesses(accesses)
            shape_counts[shape] += 1
            field_rows.append(
                {
                    "field": field["field"],
                    "task": field.get("task"),
                    "method": field.get("method"),
                    "requiredness": field.get("requiredness"),
                    "c14_value_types": field.get("value_types", []),
                    "c3_access_count": len(accesses),
                    "c3_access_styles": sorted(
                        {str(row["access_style"]) for row in accesses if isinstance(row.get("access_style"), str)}
                    ),
                    "c3_value_types": sorted(
                        {str(row["value_type"]) for row in accesses if isinstance(row.get("value_type"), str)}
                    ),
                    "conversion_helpers": conversions,
                    "refined_shape": shape,
                }
            )

        if len(fields) == 1 and fields[0]["field"] == "data":
            route_class = "data-only:" + field_rows[0]["refined_shape"]
        else:
            route_class = "small-multi-field"
        route_class_counts[route_class] += 1
        result_rows.append(
            {
                "route": route,
                "endpoint_id": endpoint.get("endpoint_id"),
                "route_class": route_class,
                "fields": field_rows,
                "empty_value_promotion": "not-proven-by-c17",
                "next_action": (
                    "analyze-callback-empty-container-acceptance"
                    if route_class.startswith("data-only:proven-array")
                    or route_class.startswith("data-only:proven-object")
                    or route_class.startswith("data-only:countable-collection")
                    else "reconstruct-field-semantics"
                ),
            }
        )

    result_rows.sort(key=lambda row: (row["route_class"], row["route"]))
    return {
        "schema": SCHEMA,
        "scope": (
            "C17 exact C3 conversion-helper refinement for low-complexity C14 response shapes; "
            "no response values and no empty-container acceptance inferred"
        ),
        "source_c14_endpoint_count": c14.get("endpoint_count"),
        "source_c14_unique_route_count": c14.get("unique_route_count"),
        "source_c3_classified_access_count": c3.get("classified_access_count"),
        "shape_only_route_count": len(result_rows),
        "refined_field_shape_counts": dict(sorted(shape_counts.items())),
        "route_class_counts": dict(sorted(route_class_counts.items())),
        "routes": result_rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--effective-runtime-catalog", type=Path, required=True)
    parser.add_argument("--c3-response-field-accesses", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = build(
            _load(args.effective_runtime_catalog, "C14 catalog"),
            _load(args.c3_response_field_accesses, "C3 response field accesses"),
        )
    except ShapeEvidenceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "shape_only_route_count": report["shape_only_route_count"],
        "refined_field_shape_counts": report["refined_field_shape_counts"],
        "route_class_counts": report["route_class_counts"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
