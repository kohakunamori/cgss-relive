import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-opaque-data-first-consumers.py"
SPEC = importlib.util.spec_from_file_location("c20_opaque_data", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class OpaqueDataFirstConsumerTests(unittest.TestCase):
    def test_load_targets_keeps_only_opaque_data_routes(self):
        c17 = {
            "schema": 1,
            "routes": [
                {
                    "route": "/opaque",
                    "endpoint_id": 1,
                    "route_class": "data-only:opaque:json",
                    "fields": [{"field": "data", "task": "Stage.X", "method": "Stage.X$$Parse", "requiredness": "conditional-direct"}],
                },
                {
                    "route": "/object",
                    "endpoint_id": 2,
                    "route_class": "data-only:proven-object",
                    "fields": [{"field": "data", "task": "Stage.Y", "method": "Stage.Y$$Parse", "requiredness": "conditional-direct"}],
                },
            ],
        }
        c3 = {
            "schema": 1,
            "accesses": [
                {"task": "Stage.X", "method": "Stage.X$$Parse", "field": "data", "method_rva": 0x1000, "access_rva": 0x1010},
                {"task": "Stage.Y", "method": "Stage.Y$$Parse", "field": "data", "method_rva": 0x2000, "access_rva": 0x2010},
            ],
        }
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "c17.json"; p2 = Path(td) / "c3.json"
            p1.write_text(json.dumps(c17)); p2.write_text(json.dumps(c3))
            rows = MOD.load_targets(p1, p2)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["route"], "/opaque")
        self.assertEqual(rows[0]["method_rva"], 0x1000)
        self.assertEqual(rows[0]["data_access_rva"], 0x1010)

    def test_consumer_classifier_recognizes_parse_and_scalar_helpers(self):
        self.assertEqual(
            MOD.classify_consumer([{"name": "Stage.Helper$$ParseData", "signature": "void Stage_Helper__ParseData (LitJson_JsonData_o* data);"}]),
            "managed-parse-helper",
        )
        self.assertEqual(
            MOD.classify_consumer([{"name": "LitJson.JsonData$$ToInt", "signature": "int32_t LitJson_JsonData__ToInt (LitJson_JsonData_o* __this);"}]),
            "scalar-int-like",
        )
        self.assertEqual(
            MOD.classify_consumer([{"name": "LitJson.JsonData$$get_Keys", "signature": "System_Collections_Generic_ICollection_string__o* LitJson_JsonData__get_Keys (...);"}]),
            "json-keys",
        )


if __name__ == "__main__":
    unittest.main()
