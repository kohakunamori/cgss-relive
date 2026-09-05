from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-polling-fromjson-result-c32.py"
SPEC = importlib.util.spec_from_file_location("c32_polling_fromjson", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class PollingFromJsonResultC32Tests(unittest.TestCase):
    def test_exact_shared_fromjson_sink_is_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c30.json"
            path.write_text(json.dumps({
                "schema": 1,
                "route": "/concert/mv_polling",
                "endpoint_id": 306,
                "helper_method": "Stage.ConcertMVPollingTask$$CheckJson",
                "helper_rva": 0x2000,
                "semantic_sinks": [{
                    "kind": "call-argument",
                    "call_kind": "direct",
                    "argument_positions": [0],
                    "rva": 0x2010,
                    "target_rva": MOD.FROMJSON_SHARED_RVA,
                }],
            }), encoding="utf-8")
            target = MOD.load_target(path)
            self.assertEqual(target["helper_rva"], 0x2000)
            self.assertEqual(target["fromjson_callsite_rva"], 0x2010)

    def test_wrong_sink_target_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "c30.json"
            path.write_text(json.dumps({
                "schema": 1,
                "route": "/concert/mv_polling",
                "endpoint_id": 306,
                "helper_method": "Stage.ConcertMVPollingTask$$CheckJson",
                "helper_rva": 0x2000,
                "semantic_sinks": [{
                    "kind": "call-argument", "call_kind": "direct",
                    "argument_positions": [0], "rva": 0x2010, "target_rva": 0xDEAD,
                }],
            }), encoding="utf-8")
            with self.assertRaises(MOD.C32Error):
                MOD.load_target(path)

if __name__ == "__main__": unittest.main()
