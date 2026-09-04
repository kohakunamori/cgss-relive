#!/usr/bin/env python3
"""Export a deterministic server-facing catalog from sanitized C9 semantics.

The catalog is evidence, not a generated success-response corpus.  It preserves
route collisions and flat parser-field requiredness so server/runtime work can be
driven from the database without hand-maintaining 538 routes.  No values from
requests, resources or proprietary response bodies are emitted.
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

from server.semantic_contracts import SemanticContractIndex  # noqa: E402

SCHEMA = 1


def field_record(field: Any) -> dict[str, Any]:
    return {
        "task": field.task,
        "method": field.method,
        "field": field.field,
        "requiredness": field.requiredness,
        "value_types": list(field.value_types),
    }


def endpoint_record(endpoint: Any) -> dict[str, Any]:
    counts = Counter(field.requiredness or "unknown" for field in endpoint.response_fields)
    return {
        "endpoint_id": endpoint.endpoint_id,
        "enum": endpoint.enum,
        "status": endpoint.status,
        "group": endpoint.group,
        "api_key": endpoint.api_key,
        "request_field_count": endpoint.request_field_count,
        "response_field_count": endpoint.response_field_count,
        "exact_state_mutation_count": endpoint.exact_state_mutation_count,
        "inferred_subsystems": list(endpoint.inferred_subsystems),
        "response_requiredness_counts": dict(sorted(counts.items())),
        "required_response_fields": [field_record(x) for x in endpoint.required_response_fields],
        "unknown_response_fields": [field_record(x) for x in endpoint.unknown_response_fields],
        "response_fields": [field_record(x) for x in endpoint.response_fields],
    }


def build_catalog(index: SemanticContractIndex) -> dict[str, Any]:
    routes = []
    endpoint_count = 0
    for route in index.routes:
        candidates = index.route_candidates(route)
        endpoint_count += len(candidates)
        routes.append(
            {
                "route": route,
                "ambiguous_path_identity": len(candidates) > 1,
                "candidate_endpoint_ids": [candidate.endpoint_id for candidate in candidates],
                "endpoints": [endpoint_record(candidate) for candidate in candidates],
            }
        )
    duplicate_routes = [
        {
            "route": route,
            "endpoint_ids": [candidate.endpoint_id for candidate in candidates],
            "identities": [
                {
                    "endpoint_id": candidate.endpoint_id,
                    "group": candidate.group,
                    "api_key": candidate.api_key,
                    "enum": candidate.enum,
                    "status": candidate.status,
                }
                for candidate in candidates
            ],
        }
        for route, candidates in sorted(index.duplicate_routes.items())
    ]
    return {
        "schema": SCHEMA,
        "scope": (
            "runtime route/flat parser-field evidence exported from sanitized final-client C9; "
            "not a response-body generator"
        ),
        "endpoint_count": endpoint_count,
        "unique_route_count": len(routes),
        "duplicate_route_count": len(duplicate_routes),
        "duplicate_routes": duplicate_routes,
        "routes": routes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Export C9 runtime contract catalog")
    parser.add_argument("--semantic-db", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    index = SemanticContractIndex(args.semantic_db)
    catalog = build_catalog(index)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if args.markdown_output:
        lines = [
            "# Final 11.6.3 runtime contract catalog", "",
            "Sanitized C9 route and flat parser-field evidence. This is not a generated response corpus.", "",
            f"- endpoint records: **{catalog['endpoint_count']}**",
            f"- unique HTTP paths: **{catalog['unique_route_count']}**",
            f"- ambiguous path groups: **{catalog['duplicate_route_count']}**", "",
            "## Ambiguous path identities", "",
        ]
        for row in catalog["duplicate_routes"]:
            identities = ", ".join(
                f"{item['group']}:{item['api_key']} {item['enum']} (id={item['endpoint_id']})"
                for item in row["identities"]
            )
            lines.append(f"- `{row['route']}` — {identities}")
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(
        json.dumps(
            {
                "schema": catalog["schema"],
                "endpoint_count": catalog["endpoint_count"],
                "unique_route_count": catalog["unique_route_count"],
                "duplicate_route_count": catalog["duplicate_route_count"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
