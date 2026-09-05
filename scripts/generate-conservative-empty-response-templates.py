#!/usr/bin/env python3
"""C15: derive the strongest static empty-data response candidates from C14.

A generated template is intentionally conservative.  It is emitted only when:
- the HTTP path maps to exactly one final-client endpoint;
- the path is not already handled by the bootstrap server;
- the concrete endpoint parser has no response fields;
- there are no exact endpoint->state mutations;
- every effective base-parser overlay is common-envelope only.

The output is a normal schema-1 ResponseTemplateStore document and therefore can
be supplied explicitly with ``--response-templates``.  This is still static
parser evidence, not device acceptance.  The generator never emits guessed field
values and never auto-enables templates in the server.
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

CATALOG_SCHEMA = 1
OUTPUT_SCHEMA = 1


class CandidateError(ValueError):
    pass


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateError(f"could not read C14 catalog: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema") != CATALOG_SCHEMA:
        raise CandidateError("C14 catalog root must contain schema=1")
    if not isinstance(value.get("routes"), list):
        raise CandidateError("C14 catalog routes must be a list")
    return value


def classify_route(route_row: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    route = route_row.get("route")
    endpoints = route_row.get("endpoints")
    if not isinstance(route, str) or not route.startswith("/"):
        raise CandidateError("malformed C14 route")
    if not isinstance(endpoints, list) or not endpoints:
        raise CandidateError(f"malformed C14 endpoints for {route}")
    if len(endpoints) != 1:
        return "ambiguous-route", None
    if route in BOOTSTRAP_HTTP_ROUTES:
        return "bootstrap-owned", None

    endpoint = endpoints[0]
    if not isinstance(endpoint, dict) or not isinstance(endpoint.get("endpoint_id"), int):
        raise CandidateError(f"malformed C14 endpoint for {route}")
    concrete = endpoint.get("concrete_response_fields")
    overlays = endpoint.get("effective_base_parsers")
    mutations = endpoint.get("exact_state_mutation_count")
    if not isinstance(concrete, list):
        raise CandidateError(f"malformed concrete fields for {route}")
    if not isinstance(overlays, list):
        raise CandidateError(f"malformed base parser overlays for {route}")
    if not isinstance(mutations, int) or mutations < 0:
        raise CandidateError(f"malformed mutation count for {route}")

    if concrete:
        return "concrete-response-shape-required", None
    if mutations:
        return "state-mutation-semantics-required", None

    non_common = []
    for overlay in overlays:
        if not isinstance(overlay, dict):
            raise CandidateError(f"malformed base parser overlay for {route}")
        scope = overlay.get("response_scope")
        if scope != "common-envelope":
            non_common.append(overlay)
    if non_common:
        return "base-parser-shape-required", None

    endpoint_id = endpoint["endpoint_id"]
    return (
        "conservative-empty-data-candidate",
        {
            "endpoint_id": endpoint_id,
            "data": {},
            "evidence": (
                "C15 static candidate: unique final-client route; zero concrete response fields; "
                "zero exact state mutations; effective base parsers are common-envelope only. "
                "Requires runtime acceptance before promotion."
            ),
        },
    )


def generate(catalog: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    counts: Counter[str] = Counter()
    templates: dict[str, Any] = {}
    candidates: list[dict[str, Any]] = []

    seen_routes: set[str] = set()
    for raw in catalog["routes"]:
        if not isinstance(raw, dict):
            raise CandidateError("malformed C14 route entry")
        route = raw.get("route")
        if not isinstance(route, str) or route in seen_routes:
            raise CandidateError(f"duplicate/invalid C14 route: {route!r}")
        seen_routes.add(route)
        classification, template = classify_route(raw)
        counts[classification] += 1
        if template is not None:
            templates[route] = template
            candidates.append(
                {
                    "route": route,
                    "endpoint_id": template["endpoint_id"],
                    "classification": classification,
                }
            )

    template_doc = {
        "schema": OUTPUT_SCHEMA,
        "routes": dict(sorted(templates.items())),
    }
    report = {
        "schema": 1,
        "scope": (
            "C15 conservative empty-data template candidates derived from C14; "
            "static parser evidence only, not runtime acceptance"
        ),
        "catalog_endpoint_count": catalog.get("endpoint_count"),
        "catalog_unique_route_count": catalog.get("unique_route_count"),
        "candidate_count": len(candidates),
        "classification_counts": dict(sorted(counts.items())),
        "candidates": sorted(candidates, key=lambda item: (item["route"], item["endpoint_id"])),
    }
    return template_doc, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--effective-runtime-catalog", type=Path, required=True)
    parser.add_argument("--templates-output", type=Path, required=True)
    parser.add_argument("--report-output", type=Path, required=True)
    args = parser.parse_args()

    try:
        catalog = _load(args.effective_runtime_catalog)
        templates, report = generate(catalog)
    except CandidateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    args.templates_output.parent.mkdir(parents=True, exist_ok=True)
    args.report_output.parent.mkdir(parents=True, exist_ok=True)
    args.templates_output.write_text(
        json.dumps(templates, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    args.report_output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "candidate_count": report["candidate_count"],
        "classification_counts": report["classification_counts"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
