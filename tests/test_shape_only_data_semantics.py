from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze-shape-only-data-semantics.py"
SPEC = importlib.util.spec_from_file_location("shape_only_data_semantics", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _endpoint(endpoint_id: int, field: str = "data", *, multi: bool = False) -> dict:
    fields = [
        {
            "field": field,
            "task": f"Stage.Task{endpoint_id}",
            "method": "Parse",
            "requiredness": "conditional-direct",
            "value_types": ["json"],
        }
    ]
    if multi:
        fields.append(
            {
                "field": "other",
                "task": f"Stage.Task{endpoint_id}",
                "method": "Parse",
                "requiredness": "optional-conditional",
                "value_types": ["int"],
            }
        )
    return {
        "endpoint_id": endpoint_id,
        "concrete_response_fields": fields,
        "exact_state_mutation_count": 0,
        "effective_base_parsers": [{"response_scope": "common-envelope"}],
    }


def _c14() -> dict:
    return {
        "schema": 1,
        "endpoint_count": 6,
        "unique_route_count": 6,
        "routes": [
            {"route": "/shape/array", "endpoints": [_endpoint(1)]},
            {"route": "/shape/object", "endpoints": [_endpoint(2)]},
            {"route": "/shape/scalar", "endpoints": [_endpoint(3)]},
            {"route": "/shape/countable", "endpoints": [_endpoint(4)]},
            {"route": "/shape/multi", "endpoints": [_endpoint(5, multi=True)]},
            {
                "route": "/shape/stateful",
                "endpoints": [
                    {
                        **_endpoint(6),
                        "exact_state_mutation_count": 1,
                    }
                ],
            },
        ],
    }


def _access(task: str, field: str, value_type: str, helper: str | None) -> dict:
    row = {
        "task": task,
        "method": "Parse",
        "field": field,
        "access_style": "direct-index",
        "value_type": value_type,
    }
    if helper is not None:
        row["conversion_helper"] = helper
    return row


def _c3() -> dict:
    return {
        "schema": 1,
        "classified_access_count": 6,
        "accesses": [
            _access("Stage.Task1", "data", "array", "LitJson.JsonData$$get_IsArray"),
            _access("Stage.Task2", "data", "object", "LitJson.JsonData$$get_IsObject"),
            _access("Stage.Task3", "data", "int", "LitJson.JsonData$$ToInt"),
            _access("Stage.Task4", "data", "collection", "LitJson.JsonData$$get_Count"),
            _access("Stage.Task5", "data", "json", None),
            _access("Stage.Task5", "other", "int", "LitJson.JsonData$$ToInt"),
        ],
    }


class ShapeOnlyDataSemanticsTests(unittest.TestCase):
    def test_refines_native_conversion_helpers_without_promoting_values(self) -> None:
        report = MODULE.build(_c14(), _c3())
        self.assertEqual(report["shape_only_route_count"], 5)
        by_route = {row["route"]: row for row in report["routes"]}
        self.assertEqual(by_route["/shape/array"]["route_class"], "data-only:proven-array")
        self.assertEqual(by_route["/shape/object"]["route_class"], "data-only:proven-object")
        self.assertEqual(by_route["/shape/scalar"]["route_class"], "data-only:proven-scalar:int")
        self.assertEqual(
            by_route["/shape/countable"]["route_class"],
            "data-only:countable-collection-ambiguous",
        )
        self.assertEqual(by_route["/shape/multi"]["route_class"], "small-multi-field")
        self.assertNotIn("/shape/stateful", by_route)
        for row in report["routes"]:
            self.assertEqual(row["empty_value_promotion"], "not-proven-by-c17")

    def test_unknown_cfg_is_not_in_shape_only_low_set(self) -> None:
        c14 = _c14()
        c14["routes"][0]["endpoints"][0]["concrete_response_fields"][0]["requiredness"] = "unknown-cfg"
        report = MODULE.build(c14, _c3())
        self.assertEqual(report["shape_only_route_count"], 4)
        self.assertNotIn("/shape/array", {row["route"] for row in report["routes"]})


if __name__ == "__main__":
    unittest.main()
