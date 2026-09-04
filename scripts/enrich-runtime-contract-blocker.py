#!/usr/bin/env python3
"""Join schema-5 runtime blocker reports with the sanitized C14 contract catalog.

This is an offline diagnostic join.  It never changes server responses and never
adds parser field names or response values to runtime logs.  The output contains
only aggregate contract counts, subsystem labels and provenance kinds for the
endpoint candidates already exposed by the sanitized runtime event stream.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

RUNTIME_SCHEMA = 5
CATALOG_SCHEMA = 1
OUTPUT_SCHEMA = 1


class EnrichmentError(ValueError):
    pass


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EnrichmentError(f"could not read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise EnrichmentError(f"{label} root must be an object")
    return value


def _index_catalog(catalog: dict[str, Any]) -> dict[int, dict[str, Any]]:
    if catalog.get("schema") != CATALOG_SCHEMA:
        raise EnrichmentError("C14 catalog must contain schema=1")
    routes = catalog.get("routes")
    if not isinstance(routes, list):
        raise EnrichmentError("C14 catalog routes must be a list")

    by_id: dict[int, dict[str, Any]] = {}
    for route_row in routes:
        if not isinstance(route_row, dict) or not isinstance(route_row.get("route"), str):
            raise EnrichmentError("malformed C14 route record")
        route = route_row["route"]
        endpoints = route_row.get("endpoints")
        if not isinstance(endpoints, list):
            raise EnrichmentError("malformed C14 endpoint list")
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or not isinstance(endpoint.get("endpoint_id"), int):
                raise EnrichmentError("malformed C14 endpoint record")
            endpoint_id = endpoint["endpoint_id"]
            if endpoint_id <= 0 or endpoint_id in by_id:
                raise EnrichmentError(f"duplicate/invalid C14 endpoint id: {endpoint_id}")
            by_id[endpoint_id] = {"route": route, **endpoint}
    return by_id


def _candidate_summary(endpoint: dict[str, Any]) -> dict[str, Any]:
    concrete = endpoint.get("concrete_response_fields")
    required = endpoint.get("concrete_required_response_fields")
    unknown = endpoint.get("concrete_unknown_response_fields")
    base = endpoint.get("effective_base_parser_summary")
    subsystems = endpoint.get("inferred_subsystems")
    if not isinstance(concrete, list) or not isinstance(required, list) or not isinstance(unknown, list):
        raise EnrichmentError("malformed C14 concrete response field lists")
    if not isinstance(base, dict):
        raise EnrichmentError("malformed C14 effective base parser summary")
    if not isinstance(subsystems, list) or any(not isinstance(item, str) for item in subsystems):
        raise EnrichmentError("malformed C14 subsystem list")

    keys = (
        "effective_base_parser_count",
        "effective_base_field_link_count",
        "effective_base_required_field_link_count",
        "effective_base_unknown_field_link_count",
    )
    for key in keys:
        if not isinstance(base.get(key), int) or base[key] < 0:
            raise EnrichmentError(f"malformed C14 base summary field: {key}")
    provenance = base.get("effective_base_provenance")
    if not isinstance(provenance, list) or any(not isinstance(item, str) for item in provenance):
        raise EnrichmentError("malformed C14 base provenance")

    exact_mutations = endpoint.get("exact_state_mutation_count")
    if not isinstance(exact_mutations, int) or exact_mutations < 0:
        raise EnrichmentError("malformed C14 exact_state_mutation_count")

    return {
        "endpoint_id": endpoint["endpoint_id"],
        "route": endpoint["route"],
        "concrete_response_field_count": len(concrete),
        "concrete_required_response_field_count": len(required),
        "concrete_unknown_response_field_count": len(unknown),
        "exact_state_mutation_count": exact_mutations,
        "effective_base_parser_count": base["effective_base_parser_count"],
        "effective_base_field_link_count": base["effective_base_field_link_count"],
        "effective_base_required_field_link_count": base[
            "effective_base_required_field_link_count"
        ],
        "effective_base_unknown_field_link_count": base[
            "effective_base_unknown_field_link_count"
        ],
        "effective_base_provenance": sorted(set(provenance)),
        "inferred_subsystems": sorted(set(subsystems)),
    }


def enrich(runtime: dict[str, Any], catalog: dict[str, Any]) -> dict[str, Any]:
    if runtime.get("schema") != RUNTIME_SCHEMA:
        raise EnrichmentError("runtime analysis must contain schema=5")
    runs = runtime.get("runs")
    if not isinstance(runs, dict):
        raise EnrichmentError("runtime analysis runs must be an object")
    by_id = _index_catalog(catalog)

    enriched_runs: dict[str, Any] = {}
    for label, run in runs.items():
        if not isinstance(label, str) or not isinstance(run, dict):
            raise EnrichmentError("malformed runtime run entry")
        blocker = run.get("semantic_contract_blocker")
        if blocker is None:
            enriched_runs[label] = {"semantic_contract_blocker": None}
            continue
        if not isinstance(blocker, dict):
            raise EnrichmentError("malformed semantic_contract_blocker")
        route = blocker.get("route")
        endpoint_ids = blocker.get("candidate_endpoint_ids")
        if not isinstance(route, str):
            raise EnrichmentError("semantic blocker route must be a string")
        if not isinstance(endpoint_ids, list) or any(
            not isinstance(endpoint_id, int) or endpoint_id <= 0 for endpoint_id in endpoint_ids
        ):
            raise EnrichmentError("semantic blocker endpoint IDs must be positive integers")

        candidates: list[dict[str, Any]] = []
        for endpoint_id in endpoint_ids:
            endpoint = by_id.get(endpoint_id)
            if endpoint is None:
                raise EnrichmentError(f"runtime endpoint {endpoint_id} is absent from C14")
            if endpoint["route"] != route:
                raise EnrichmentError(
                    f"runtime/C14 route mismatch for endpoint {endpoint_id}: "
                    f"{route} != {endpoint['route']}"
                )
            candidates.append(_candidate_summary(endpoint))

        enriched_runs[label] = {
            "semantic_contract_blocker": {
                "route": route,
                "status": blocker.get("status"),
                "candidate_endpoint_ids": endpoint_ids,
                "route_identity_ambiguous": len(endpoint_ids) != 1,
                "effective_contract_candidates": candidates,
                "next_action": (
                    "resolve_endpoint_identity_before_response_model"
                    if len(endpoint_ids) != 1
                    else "reconstruct_concrete_plus_effective_base_response_model"
                ),
            }
        }

    return {
        "schema": OUTPUT_SCHEMA,
        "scope": "runtime schema-5 semantic blockers enriched with aggregate C14 evidence",
        "source_runtime_schema": RUNTIME_SCHEMA,
        "source_catalog_schema": CATALOG_SCHEMA,
        "catalog_endpoint_count": catalog.get("endpoint_count"),
        "catalog_unique_route_count": catalog.get("unique_route_count"),
        "runs": enriched_runs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-analysis", type=Path, required=True)
    parser.add_argument("--effective-runtime-catalog", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        runtime = _load_object(args.runtime_analysis, "runtime analysis")
        catalog = _load_object(args.effective_runtime_catalog, "C14 catalog")
        report = enrich(runtime, catalog)
    except EnrichmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
