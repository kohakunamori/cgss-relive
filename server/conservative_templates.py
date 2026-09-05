"""Runtime loader for statically conservative C14 empty-data service candidates.

This module turns only the strongest C14 contracts into normal response templates:
unique path identity, no concrete response fields, no exact state mutations, and
no effective base-parser surface beyond the common success envelope.  It never
manufactures field values.  These routes remain static candidates until accepted
by the untouched client; callers must opt in explicitly.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .api_registry import BOOTSTRAP_HTTP_ROUTES
from .response_templates import ResponseTemplate, ResponseTemplateStore
from .semantic_contracts import SemanticContractIndex

CATALOG_SCHEMA = 1
EXPECTED_ENDPOINT_COUNT = 538
EXPECTED_UNIQUE_ROUTE_COUNT = 526
EXPECTED_DUPLICATE_ROUTE_COUNT = 9
EXPECTED_CANDIDATE_COUNT = 154

EVIDENCE = (
    "C15 static candidate: unique final-client route; zero concrete response fields; "
    "zero exact state mutations; effective base parsers are common-envelope only. "
    "Requires untouched-client acceptance before promotion."
)


class ConservativeTemplateError(ValueError):
    pass


def _load_catalog(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConservativeTemplateError(f"could not read C14 catalog: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != CATALOG_SCHEMA:
        raise ConservativeTemplateError("C14 catalog root must contain schema=1")
    if not isinstance(value.get("routes"), list):
        raise ConservativeTemplateError("C14 catalog routes must be a list")
    return value


def _eligible_endpoint(route: str, route_row: dict[str, Any]) -> dict[str, Any] | None:
    endpoints = route_row.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise ConservativeTemplateError(f"malformed C14 endpoint list for {route}")
    if len(endpoints) != 1 or route in BOOTSTRAP_HTTP_ROUTES:
        return None

    endpoint = endpoints[0]
    if not isinstance(endpoint, dict) or not isinstance(endpoint.get("endpoint_id"), int):
        raise ConservativeTemplateError(f"malformed C14 endpoint for {route}")
    concrete = endpoint.get("concrete_response_fields")
    overlays = endpoint.get("effective_base_parsers")
    mutations = endpoint.get("exact_state_mutation_count")
    if not isinstance(concrete, list):
        raise ConservativeTemplateError(f"malformed concrete response fields for {route}")
    if not isinstance(overlays, list):
        raise ConservativeTemplateError(f"malformed effective base parsers for {route}")
    if not isinstance(mutations, int) or mutations < 0:
        raise ConservativeTemplateError(f"malformed state mutation count for {route}")
    if concrete or mutations:
        return None

    for overlay in overlays:
        if not isinstance(overlay, dict):
            raise ConservativeTemplateError(f"malformed effective base parser for {route}")
        if overlay.get("response_scope") != "common-envelope":
            return None
    return endpoint


def load_conservative_empty_templates(
    path: Path,
    *,
    semantic_index: SemanticContractIndex,
    enforce_final_counts: bool = True,
) -> ResponseTemplateStore:
    catalog = _load_catalog(path)
    if enforce_final_counts:
        expected = {
            "endpoint_count": EXPECTED_ENDPOINT_COUNT,
            "unique_route_count": EXPECTED_UNIQUE_ROUTE_COUNT,
            "duplicate_route_count": EXPECTED_DUPLICATE_ROUTE_COUNT,
        }
        actual = {key: catalog.get(key) for key in expected}
        if actual != expected:
            raise ConservativeTemplateError(f"C14 final-count mismatch: {actual!r}")

    templates: dict[str, ResponseTemplate] = {}
    seen_routes: set[str] = set()
    for row in catalog["routes"]:
        if not isinstance(row, dict):
            raise ConservativeTemplateError("malformed C14 route entry")
        route = row.get("route")
        if not isinstance(route, str) or not route.startswith("/") or route in seen_routes:
            raise ConservativeTemplateError(f"duplicate/invalid C14 route: {route!r}")
        seen_routes.add(route)
        endpoint = _eligible_endpoint(route, row)
        if endpoint is None:
            continue

        endpoint_id = endpoint["endpoint_id"]
        candidates = semantic_index.route_candidates(route)
        if len(candidates) != 1:
            raise ConservativeTemplateError(
                f"C14 conservative route is not unique in C9: {route}"
            )
        if candidates[0].endpoint_id != endpoint_id:
            raise ConservativeTemplateError(
                f"C14/C9 endpoint identity mismatch for {route}: "
                f"{endpoint_id} != {candidates[0].endpoint_id}"
            )
        templates[route] = ResponseTemplate(
            route=route,
            endpoint_id=endpoint_id,
            data={},
            evidence=EVIDENCE,
        )

    if enforce_final_counts and len(templates) != EXPECTED_CANDIDATE_COUNT:
        raise ConservativeTemplateError(
            f"C15 conservative candidate count mismatch: {len(templates)}"
        )
    return ResponseTemplateStore(templates)
