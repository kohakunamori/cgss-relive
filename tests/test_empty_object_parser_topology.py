from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze-empty-object-parser-topology.py"
SPEC = importlib.util.spec_from_file_location("empty_object_parser_topology", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class EmptyObjectParserTopologyTests(unittest.TestCase):
    def test_load_targets_keeps_only_data_only_proven_object_get_keys(self) -> None:
        c17 = {
            "schema": 1,
            "routes": [
                {
                    "route": "/object",
                    "endpoint_id": 1,
                    "route_class": "data-only:proven-object",
                    "fields": [{
                        "task": "Stage.ObjectTask",
                        "method": "Stage.ObjectTask$$Parse",
                        "field": "data",
                        "requiredness": "conditional-direct",
                    }],
                },
                {
                    "route": "/opaque",
                    "endpoint_id": 2,
                    "route_class": "data-only:opaque:json",
                    "fields": [{
                        "task": "Stage.OpaqueTask",
                        "method": "Stage.OpaqueTask$$Parse",
                        "field": "data",
                        "requiredness": "conditional-direct",
                    }],
                },
            ],
        }
        c3 = {
            "schema": 1,
            "accesses": [
                {
                    "task": "Stage.ObjectTask",
                    "method": "Stage.ObjectTask$$Parse",
                    "field": "data",
                    "method_rva": 0x1000,
                    "access_rva": 0x1010,
                    "conversion_rva": 0x1020,
                    "conversion_helper": "LitJson.JsonData$$get_Keys",
                },
                {
                    "task": "Stage.OpaqueTask",
                    "method": "Stage.OpaqueTask$$Parse",
                    "field": "data",
                    "method_rva": 0x2000,
                    "access_rva": 0x2010,
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            c17_path = root / "c17.json"
            c3_path = root / "c3.json"
            c17_path.write_text(json.dumps(c17), encoding="utf-8")
            c3_path.write_text(json.dumps(c3), encoding="utf-8")
            rows = MODULE.load_targets(c17_path, c3_path)
        self.assertEqual(rows, [{
            "route": "/object",
            "endpoint_id": 1,
            "task": "Stage.ObjectTask",
            "method": "Stage.ObjectTask$$Parse",
            "field": "data",
            "requiredness": "conditional-direct",
            "method_rva": 0x1000,
            "get_keys_rva": 0x1020,
        }])

    def test_call_classifier_separates_json_and_collection_operations(self) -> None:
        self.assertEqual(MODULE.classify_call("LitJson.JsonData$$get_Item"), "json-index")
        self.assertEqual(MODULE.classify_call("LitJson.JsonData$$get_Keys"), "json-keys")
        self.assertEqual(MODULE.classify_call("System.Collections.Generic.List$$get_Count"), "collection-count")
        self.assertEqual(MODULE.classify_call("Foo$$GetEnumerator"), "enumerator")
        self.assertEqual(MODULE.classify_call("Foo$$MoveNext"), "move-next")


if __name__ == "__main__":
    unittest.main()
