from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-nested-response-dto-metadata-c35.py"
SPEC = importlib.util.spec_from_file_location("c35_nested_dto", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


class NestedResponseDtoMetadataC35Tests(unittest.TestCase):
    def test_nested_response_type_keeps_parent_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dump = Path(tmp) / "dump.cs"
            chunks = []
            for task in MOD.TARGET_TASKS:
                short = task.split(".")[-1]
                chunks.append(
                    "// Namespace: Stage\n"
                    f"public class {short} : BaseTask // TypeDefIndex: 1\n"
                    "{\n"
                    "    private Action<ResponseDataMain> _callback; // 0x58\n"
                    "    [Serializable]\n"
                    "    private class ResponseDataMain // TypeDefIndex: 2\n"
                    "    {\n"
                    "        public int status; // 0x10\n"
                    "        public string token; // 0x18\n"
                    "    }\n"
                    "}\n"
                )
            dump.write_text("\n".join(chunks), encoding="utf-8")
            report = MOD.build(dump)
            self.assertEqual(report["target_task_count"], 4)
            self.assertEqual(report["response_candidate_count"], 4)
            names = {row["type"] for row in report["response_candidates"]}
            self.assertIn("Stage.ConcertMVStartTask.ResponseDataMain", names)
            start = next(row for row in report["response_candidates"] if row["type"] == "Stage.ConcertMVStartTask.ResponseDataMain")
            self.assertEqual([f["name"] for f in start["fields"]], ["status", "token"])


if __name__ == "__main__":
    unittest.main()
