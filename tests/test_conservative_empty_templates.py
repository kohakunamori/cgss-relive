from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "generate-conservative-empty-response-templates.py"
)
SPEC = importlib.util.spec_from_file_location("conservative_empty_templates", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _endpoint(
    endpoint_id: int,
    *,
    concrete: list | None = None,
    mutations: int = 0,
    scopes: list[str] | None = None,
) -> dict:
    if concrete is None:
        concrete = []
    if scopes is None:
        scopes = []
    return {
        "endpoint_id": endpoint_id,
        "concrete_response_fields": concrete,
        "exact_state_mutation_count": mutations,
        "effective_base_parsers": [
            {"response_scope": scope, "base_task": "Synthetic"}
            for scope in scopes
        ],
    }


def test_generates_only_strong_empty_data_candidate() -> None:
    catalog = {
        "schema": 1,
        "endpoint_count": 5,
        "unique_route_count": 5,
        "routes": [
            {"route": "/candidate", "endpoints": [_endpoint(1, scopes=["common-envelope"])]},
            {
                "route": "/needs/concrete",
                "endpoints": [_endpoint(2, concrete=[{"field": "value"}])],
            },
            {"route": "/needs/state", "endpoints": [_endpoint(3, mutations=1)]},
            {
                "route": "/needs/base",
                "endpoints": [_endpoint(4, scopes=["base-parser-surface"])],
            },
            {
                "route": "/ambiguous",
                "endpoints": [_endpoint(5), _endpoint(6)],
            },
        ],
    }

    templates, report = MODULE.generate(catalog)
    assert list(templates["routes"]) == ["/candidate"]
    assert templates["routes"]["/candidate"]["endpoint_id"] == 1
    assert templates["routes"]["/candidate"]["data"] == {}
    assert report["candidate_count"] == 1
    assert report["classification_counts"] == {
        "ambiguous-route": 1,
        "base-parser-shape-required": 1,
        "concrete-response-shape-required": 1,
        "conservative-empty-data-candidate": 1,
        "state-mutation-semantics-required": 1,
    }


def test_bootstrap_route_is_never_generated() -> None:
    catalog = {
        "schema": 1,
        "endpoint_count": 1,
        "unique_route_count": 1,
        "routes": [
            {"route": "/load/index", "endpoints": [_endpoint(12)]},
        ],
    }
    templates, report = MODULE.generate(catalog)
    assert templates["routes"] == {}
    assert report["classification_counts"] == {"bootstrap-owned": 1}
