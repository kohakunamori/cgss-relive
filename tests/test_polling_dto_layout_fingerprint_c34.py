from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-polling-dto-layout-fingerprint-c34.py"
SPEC = importlib.util.spec_from_file_location("c34_polling_dto", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class PollingDtoFingerprintC34Tests(unittest.TestCase):
    def test_exact_offset_fingerprint_candidate_is_ranked_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dump = root / "dump.cs"
            dump.write_text(
                "// Namespace: Stage\n"
                "public class ExactDto // TypeDefIndex: 1\n{\n"
                " public System.Int32 a; // 0x10\n"
                " public System.Int32 b; // 0x18\n"
                " public System.Int32 c; // 0x20\n"
                " public System.Int32 d; // 0x28\n"
                " public System.Int32 e; // 0x30\n"
                " public System.Int32 f; // 0x3C\n}\n"
                "// Namespace: Stage\n"
                "public class SupersetDto // TypeDefIndex: 2\n{\n"
                " public System.Int32 a; // 0x10\n public System.Int32 b; // 0x18\n"
                " public System.Int32 c; // 0x20\n public System.Int32 d; // 0x28\n"
                " public System.Int32 e; // 0x30\n public System.Int32 x; // 0x38\n"
                " public System.Int32 f; // 0x3C\n}\n",
                encoding="utf-8",
            )
            c32 = root / "c32.json"
            c32.write_text(json.dumps({
                "schema": 1, "route": "/concert/mv_polling", "endpoint_id": 306,
                "semantic_sinks": [
                    {"kind":"dereference","offset":v} for v in [16,24,32,40,48,60]
                ],
            }), encoding="utf-8")
            report = MOD.build(dump, c32)
            self.assertEqual(report["candidate_type_count"], 2)
            self.assertEqual(report["exact_offset_set_candidate_count"], 1)
            self.assertEqual(report["candidates"][0]["type"], "Stage.ExactDto")

if __name__ == "__main__": unittest.main()
