import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-low-complexity-response-evidence-c25.py"
SPEC = importlib.util.spec_from_file_location("c25_catalog", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class C25CatalogTests(unittest.TestCase):
    def test_recursive_object_overlay_does_not_promote_empty_value(self):
        c22_routes = []
        for i in range(76):
            c22_routes.append({
                "route": f"/r{i}",
                "endpoint_id": i + 1,
                "effective_shape": "opaque:json" if i == 0 else "multi-field",
                "effective_shape_source": "C17-direct-parser-shape",
                "empty_value_status": "not-proven",
                "consumer_resolution": "not-applicable",
                "next_action": "reconstruct-business-value-semantics",
                "static_evidence_only": True,
                "untouched_client_acceptance": False,
            })
        c22 = {
            "schema": 1,
            "route_count": 76,
            "parser_local_empty_value_proven_route_count": 0,
            "untouched_client_accepted_route_count": 0,
            "routes": c22_routes,
        }
        c24 = {
            "schema": 1,
            "target_route_count": 1,
            "routes": [{
                "route": "/r0",
                "recursive_shape_refinement": "helper-proven-object",
                "visited_helper_count": 2,
            }],
        }
        out = MOD.build(c22, c24)
        row = out["routes"][0]
        self.assertEqual(row["route"], "/r0")
        self.assertEqual(row["effective_shape"], "proven-object")
        self.assertEqual(row["effective_shape_source"], "C24-recursive-helper-json-operations")
        self.assertEqual(row["empty_value_status"], "not-proven")
        self.assertFalse(row["untouched_client_acceptance"])
        self.assertEqual(out["c24_shape_overlay_route_count"], 1)

    def test_unresolved_c24_does_not_replace_c22_shape(self):
        c22_routes = [{
            "route": f"/r{i}",
            "endpoint_id": i + 1,
            "effective_shape": "opaque:json" if i == 0 else "multi-field",
            "effective_shape_source": "C17-direct-parser-shape",
            "empty_value_status": "not-proven",
            "consumer_resolution": "not-applicable",
            "next_action": "reconstruct-business-value-semantics",
            "static_evidence_only": True,
            "untouched_client_acceptance": False,
        } for i in range(76)]
        c22 = {
            "schema": 1,
            "route_count": 76,
            "parser_local_empty_value_proven_route_count": 0,
            "untouched_client_accepted_route_count": 0,
            "routes": c22_routes,
        }
        c24 = {
            "schema": 1,
            "target_route_count": 1,
            "routes": [{"route": "/r0", "recursive_shape_refinement": "helper-unresolved"}],
        }
        out = MOD.build(c22, c24)
        row = out["routes"][0]
        self.assertEqual(row["effective_shape"], "opaque:json")
        self.assertEqual(out["c24_shape_overlay_route_count"], 0)


if __name__ == "__main__":
    unittest.main()
