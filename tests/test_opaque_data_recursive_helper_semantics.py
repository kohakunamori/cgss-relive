import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-opaque-data-recursive-helper-semantics.py"
SPEC = importlib.util.spec_from_file_location("c24_recursive_helpers", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class RecursiveHelperSemanticsTests(unittest.TestCase):
    def test_load_targets_keeps_only_c21_unresolved(self):
        c20 = {
            "schema": 1,
            "target_route_count": 15,
            "routes": [
                {"route": "/a", "endpoint_id": 1, "task": "A", "first_direct_managed_consumer": {"target_rva": 100, "argument_positions": [0]}},
                {"route": "/b", "endpoint_id": 2, "task": "B", "first_direct_managed_consumer": {"target_rva": 200, "argument_positions": [1]}},
            ] + [
                {"route": f"/f{i}", "endpoint_id": i + 10, "task": "F", "first_direct_managed_consumer": None}
                for i in range(13)
            ],
        }
        c21 = {
            "schema": 1,
            "target_route_count": 15,
            "routes": [
                {"route": "/a", "shape_refinement": "helper-unresolved"},
                {"route": "/b", "shape_refinement": "helper-proven-object"},
            ] + [
                {"route": f"/f{i}", "shape_refinement": "helper-opaque-json"}
                for i in range(13)
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            p20 = Path(td) / "c20.json"; p21 = Path(td) / "c21.json"
            p20.write_text(json.dumps(c20)); p21.write_text(json.dumps(c21))
            rows = MOD.load_targets(p20, p21)
        self.assertEqual([row["route"] for row in rows], ["/a"])
        self.assertEqual(rows[0]["first_direct_managed_consumer"]["target_rva"], 100)

    def test_shape_refinement_stays_operation_driven(self):
        self.assertEqual(MOD.C21.shape_from_operations(["json-index-string"]), "helper-proven-object")
        self.assertEqual(MOD.C21.shape_from_operations(["json-index-int"]), "helper-proven-array")
        self.assertEqual(MOD.C21.shape_from_operations([]), "helper-unresolved")


if __name__ == "__main__":
    unittest.main()
