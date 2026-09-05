from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-jsonutility-task-dto-metadata-c33.py"
SPEC = importlib.util.spec_from_file_location("c33_dto_metadata", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class JsonUtilityDtoMetadataC33Tests(unittest.TestCase):
    def test_dump_parser_and_store_offset_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dump = root / "dump.cs"
            chunks = []
            for task in MOD.TARGET_TASKS:
                short = task.split(".")[-1]
                chunks.append(
                    f"// Namespace: Stage\npublic class {short} : BaseTask // TypeDefIndex: 1\n{{\n"
                    "    private System.Int32 id; // 0x40\n"
                    "    private Stage.SampleDto response; // 0x50\n"
                    "}\n"
                )
            chunks.append(
                "// Namespace: Stage\npublic class SampleDto // TypeDefIndex: 2\n{\n"
                "    public System.Int32 code; // 0x10\n"
                "    public System.String name; // 0x18\n"
                "}\n"
            )
            dump.write_text("\n".join(chunks), encoding="utf-8")
            c31 = root / "c31.json"
            c31.write_text(json.dumps({
                "schema": 1,
                "route_count": 3,
                "routes": [{
                    "task": "Stage.BusSetFavoriteTask",
                    "semantic_sinks": [{"kind": "nonstack-store", "offset": 80}],
                }, {"task": "Stage.ConcertMVFinishMVLoadingTask", "semantic_sinks": []},
                {"task": "Stage.ConcertMVStartTask", "semantic_sinks": []}],
            }), encoding="utf-8")
            report = MOD.build(dump, c31)
            match = report["store_offset_matches"][0]
            self.assertEqual(match["store_offset"], 80)
            self.assertEqual(match["field_matches"][0]["name"], "response")
            surfaces = {r["type"]: r for r in report["referenced_type_surfaces"]}
            self.assertIn("Stage.SampleDto", surfaces)
            self.assertEqual([f["name"] for f in surfaces["Stage.SampleDto"]["fields"]], ["code", "name"])


if __name__ == "__main__": unittest.main()
