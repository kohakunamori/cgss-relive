from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "build-service-implementation-backlog.py"
SPEC = importlib.util.spec_from_file_location("service_implementation_backlog", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _endpoint(
    endpoint_id: int,
    *,
    fields: list[dict] | None = None,
    overlays: list[dict] | None = None,
    mutations: int = 0,
) -> dict:
    return {
        "endpoint_id": endpoint_id,
        "concrete_response_fields": fields or [],
        "effective_base_parsers": overlays or [],
        "exact_state_mutation_count": mutations,
        "inferred_subsystems": [],
    }


def _field(name: str, requiredness: str = "conditional-direct", value_type: str = "collection") -> dict:
    return {
        "field": name,
        "requiredness": requiredness,
        "value_types": [value_type],
    }


class ServiceImplementationBacklogTests(unittest.TestCase):
    def test_common_envelope_is_discounted_from_unresolved_surface(self) -> None:
        catalog = {
            "schema": 1,
            "endpoint_count": 2,
            "unique_route_count": 2,
            "routes": [
                {
                    "route": "/c15",
                    "endpoints": [
                        _endpoint(
                            1,
                            overlays=[
                                {
                                    "response_scope": "common-envelope",
                                    "fields": [_field("result_code", "unknown-cfg", "int")],
                                }
                            ],
                        )
                    ],
                },
                {
                    "route": "/shape",
                    "endpoints": [
                        _endpoint(
                            2,
                            fields=[
                                _field("data_headers", "required-path", "json"),
                                _field("result_code", "required-path", "int"),
                                _field("data", "conditional-direct", "collection"),
                            ],
                            overlays=[
                                {
                                    "response_scope": "common-envelope",
                                    "fields": [_field("result_code", "unknown-cfg", "int")],
                                }
                            ],
                        )
                    ],
                },
            ],
        }
        report = MODULE.build(catalog, enforce_final_counts=False)
        by_route = {row["route"]: row for row in report["routes"]}
        self.assertEqual(by_route["/c15"]["tier"], "c15-empty-baseline")
        self.assertEqual(by_route["/shape"]["tier"], "shape-only-low")
        self.assertEqual(by_route["/shape"]["concrete_field_count"], 1)
        self.assertEqual(by_route["/shape"]["base_unknown_count"], 0)
        self.assertEqual(by_route["/shape"]["data_shape_hints"], ["collection"])

    def test_non_common_unknown_base_surface_stays_blocking(self) -> None:
        catalog = {
            "schema": 1,
            "endpoint_count": 1,
            "unique_route_count": 1,
            "routes": [
                {
                    "route": "/unknown",
                    "endpoints": [
                        _endpoint(
                            3,
                            overlays=[
                                {
                                    "response_scope": "base-parser-surface",
                                    "fields": [_field("value", "unknown-cfg", "json")],
                                }
                            ],
                        )
                    ],
                }
            ],
        }
        report = MODULE.build(catalog, enforce_final_counts=False)
        row = report["routes"][0]
        self.assertEqual(row["tier"], "unknown-cfg")
        self.assertEqual(row["base_unknown_count"], 1)
        self.assertEqual(row["next_action"], "close-unknown-cfg-before-modeling")

    def test_duplicate_path_never_receives_shape_priority(self) -> None:
        catalog = {
            "schema": 1,
            "endpoint_count": 2,
            "unique_route_count": 1,
            "routes": [
                {
                    "route": "/duplicate",
                    "endpoints": [_endpoint(4), _endpoint(5)],
                }
            ],
        }
        report = MODULE.build(catalog, enforce_final_counts=False)
        row = report["routes"][0]
        self.assertEqual(row["tier"], "ambiguous-route")
        self.assertEqual(row["candidate_endpoint_ids"], [4, 5])


if __name__ == "__main__":
    unittest.main()
