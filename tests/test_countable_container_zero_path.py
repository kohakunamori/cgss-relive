from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze-countable-container-zero-path.py"
SPEC = importlib.util.spec_from_file_location("countable_container_zero_path", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CountableContainerZeroPathTests(unittest.TestCase):
    def test_signature_kind_distinguishes_index_overloads(self) -> None:
        self.assertEqual(MODULE.item_signature_kind("JsonData get_Item(Int32 index)"), "integer-index")
        self.assertEqual(MODULE.item_signature_kind("JsonData get_Item(System_String key)"), "string-key")
        self.assertEqual(MODULE.item_signature_kind(None), "unknown")

    def test_load_targets_keeps_only_countable_data_only_routes(self) -> None:
        c17 = {
            "schema": 1,
            "routes": [
                {
                    "route": "/countable",
                    "endpoint_id": 1,
                    "route_class": "data-only:countable-collection-ambiguous",
                    "fields": [{
                        "task": "Stage.CountTask",
                        "method": "Stage.CountTask$$Parse",
                        "field": "data",
                        "requiredness": "conditional-direct",
                    }],
                },
                {
                    "route": "/object",
                    "endpoint_id": 2,
                    "route_class": "data-only:proven-object",
                    "fields": [{
                        "task": "Stage.ObjectTask",
                        "method": "Stage.ObjectTask$$Parse",
                        "field": "data",
                    }],
                },
            ],
        }
        c3 = {
            "schema": 1,
            "accesses": [{
                "task": "Stage.CountTask",
                "method": "Stage.CountTask$$Parse",
                "field": "data",
                "method_rva": 0x1000,
                "access_rva": 0x1010,
                "conversion_rva": 0x1020,
                "conversion_helper": "LitJson.JsonData$$get_Count",
            }],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = root / "c17.json"
            b = root / "c3.json"
            a.write_text(json.dumps(c17), encoding="utf-8")
            b.write_text(json.dumps(c3), encoding="utf-8")
            rows = MODULE.load_targets(a, b)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["route"], "/countable")
        self.assertEqual(rows[0]["count_rva"], 0x1020)


if __name__ == "__main__":
    unittest.main()
