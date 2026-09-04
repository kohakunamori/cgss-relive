#!/usr/bin/env python3
"""Compile final-client static response baselines plus stronger explicit templates.

The output is a normal schema-1 ResponseTemplateStore document accepted by
``server.http_server --response-templates``.

Static layers are kept distinct before composition:

- C15: 154 unique routes with zero concrete response fields/state mutations and
  common-envelope-only base parser surface;
- C18: parser-proven omission routes where every concrete business field is
  optional/defaulted, with zero state mutations and common-envelope-only base
  parser surface.

Optional explicit templates override a static route only when the exact endpoint
identity is unchanged. Exact JSON-like ``data`` shapes are preserved; arrays,
scalars and null are never coerced into objects.

This command performs no network/device work and does not promote static evidence
to untouched-client acceptance.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.conservative_templates import (  # noqa: E402
    ConservativeTemplateError,
    load_conservative_empty_templates,
)
from server.optional_omission_templates import (  # noqa: E402
    OptionalOmissionTemplateError,
    load_optional_omission_templates,
)
from server.response_templates import ResponseTemplateStore  # noqa: E402
from server.semantic_contracts import SemanticContractIndex  # noqa: E402


def _document(store: ResponseTemplateStore) -> dict:
    routes = {}
    for route in store.routes:
        template = store.get(route)
        assert template is not None
        item = {
            "endpoint_id": template.endpoint_id,
            "data": copy.deepcopy(template.data),
        }
        if template.evidence is not None:
            item["evidence"] = template.evidence
        routes[route] = item
    return {"schema": 1, "routes": routes}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--semantic-db", type=Path, required=True)
    parser.add_argument("--effective-runtime-catalog", type=Path, required=True)
    parser.add_argument(
        "--explicit-templates",
        type=Path,
        help="optional stronger schema-1 templates; exact endpoint identity must match",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        semantic = SemanticContractIndex(args.semantic_db)
        c15 = load_conservative_empty_templates(
            args.effective_runtime_catalog,
            semantic_index=semantic,
        )
        c18 = load_optional_omission_templates(
            args.effective_runtime_catalog,
            semantic_index=semantic,
        )
        static_baseline = c15.merged(c18)
        compiled = static_baseline
        explicit_count = 0
        if args.explicit_templates is not None:
            explicit = ResponseTemplateStore.load(
                args.explicit_templates,
                semantic_index=semantic,
            )
            explicit_count = explicit.count
            compiled = static_baseline.merged(explicit)
    except (
        OSError,
        ValueError,
        ConservativeTemplateError,
        OptionalOmissionTemplateError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(_document(compiled), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "c15_baseline_routes": c15.count,
                "c18_optional_omission_routes": c18.count,
                "static_baseline_routes": static_baseline.count,
                "explicit_template_routes": explicit_count,
                "compiled_template_routes": compiled.count,
                "evidence_level": "static-template-candidate",
                "device_acceptance": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
