#!/usr/bin/env python3
"""C14: export a runtime contract catalog combining C9 and C13 evidence.

C9 concrete parser fields and C13 effective base-parser overlays remain separate
objects.  This catalog is intended for blocker diagnosis/model generation; it
contains no response values and does not turn a parser field name into a valid
JSON template automatically.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.parser_overlays import EffectiveParserOverlayIndex  # noqa: E402
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


def load_overlay_document(path: Path) -> dict[str, Any]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("schema") != 1:
        raise ValueError("C13 overlay document must contain schema=1")
    return doc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--semantic-db", type=Path, required=True)
    parser.add_argument("--parser-overlays", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    semantic = SemanticContractIndex(args.semantic_db)
    overlay_index = EffectiveParserOverlayIndex(
        args.parser_overlays,
        semantic_index=semantic,
    )
    overlay_doc = load_overlay_document(args.parser_overlays)
    full_overlay_by_key = {
        (int(row["endpoint"]["endpoint_id"]), int(row["base_parser_rva"])): row
        for row in overlay_doc["overlays"]
    }

    route_rows: list[dict[str, Any]] = []
    concrete_field_count = 0
    effective_field_link_count = 0
    for route in semantic.routes:
        endpoints = []
        for endpoint in semantic.route_candidates(route):
            concrete = [field_record(field) for field in endpoint.response_fields]
            concrete_field_count += len(concrete)
            effective = []
            for overlay in overlay_index.endpoint_overlays(endpoint.endpoint_id):
                raw = full_overlay_by_key[(endpoint.endpoint_id, overlay.base_parser_rva)]
                effective.append({
                    "base_task": overlay.base_task,
                    "base_parser_method": overlay.base_parser_method,
                    "base_parser_rva": overlay.base_parser_rva,
                    "field_count": overlay.field_count,
                    "required_field_count": overlay.required_field_count,
                    "unknown_field_count": overlay.unknown_field_count,
                    "provenance_kinds": list(overlay.provenance_kinds),
                    "fields": raw["fields"],
                    "provenance": raw["provenance"],
                    "response_scope": (
                        "common-envelope"
                        if overlay.base_task == "Stage.BaseTask"
                        and overlay.base_parser_method == "Stage.BaseTask$$Parse"
                        else "base-parser-surface"
                    ),
                })
                effective_field_link_count += overlay.field_count
            endpoints.append({
                "endpoint_id": endpoint.endpoint_id,
                "enum": endpoint.enum,
                "status": endpoint.status,
                "group": endpoint.group,
                "api_key": endpoint.api_key,
                "request_field_count": endpoint.request_field_count,
                "concrete_response_fields": concrete,
                "concrete_required_response_fields": [
                    item for item in concrete if item["requiredness"] == "required-path"
                ],
                "concrete_unknown_response_fields": [
                    item for item in concrete if item["requiredness"] == "unknown-cfg"
                ],
                "exact_state_mutation_count": endpoint.exact_state_mutation_count,
                "inferred_subsystems": list(endpoint.inferred_subsystems),
                "effective_base_parsers": effective,
                "effective_base_parser_summary": overlay_index.safe_endpoint_summary(endpoint.endpoint_id),
            })
        route_rows.append({
            "route": route,
            "ambiguous_path_identity": len(endpoints) > 1,
            "candidate_endpoint_ids": [item["endpoint_id"] for item in endpoints],
            "endpoints": endpoints,
        })

    report = {
        "schema": SCHEMA,
        "scope": (
            "C14 runtime contract catalog: C9 concrete parser semantics + C13 provenance-preserving "
            "effective base-parser overlays; no response values"
        ),
        "endpoint_count": semantic.endpoint_count,
        "unique_route_count": semantic.unique_route_count,
        "duplicate_route_count": len(semantic.duplicate_routes),
        "endpoint_with_effective_base_parser_count": overlay_index.endpoint_count,
        "effective_base_parser_relation_count": overlay_index.relation_count,
        "effective_base_parser_field_link_count": overlay_index.field_link_count,
        "concrete_bound_response_field_count": concrete_field_count,
        "residual_unmapped_base_method_count": int(overlay_doc["residual_unmapped_method_count"]),
        "residual_unmapped_base_methods": overlay_doc["residual_unmapped_methods"],
        "routes": route_rows,
    }
    if effective_field_link_count != overlay_index.field_link_count:
        raise RuntimeError("C14 field-link accounting mismatch")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = [
            "# Final 11.6.3 effective runtime contract catalog", "",
            "C9 concrete fields and C13 base-parser overlays remain separate provenance classes.", "",
            f"- endpoint records: **{report['endpoint_count']}**",
            f"- unique HTTP paths: **{report['unique_route_count']}**",
            f"- ambiguous path groups: **{report['duplicate_route_count']}**",
            f"- endpoints with effective base-parser overlays: **{report['endpoint_with_effective_base_parser_count']}**",
            f"- effective base-parser relations: **{report['effective_base_parser_relation_count']}**",
            f"- effective base-parser field links: **{report['effective_base_parser_field_link_count']}**",
            f"- residual unmapped base methods: **{report['residual_unmapped_base_method_count']}**", "",
            "The common `Stage.BaseTask.Parse` overlay is marked `common-envelope`; it is not a list of keys to place inside the endpoint `data` object.",
        ]
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({k: report[k] for k in (
        "endpoint_count", "unique_route_count", "duplicate_route_count",
        "endpoint_with_effective_base_parser_count", "effective_base_parser_relation_count",
        "effective_base_parser_field_link_count", "concrete_bound_response_field_count",
        "residual_unmapped_base_method_count",
    )}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
