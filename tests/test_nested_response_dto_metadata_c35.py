from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "analyze-nested-response-dto-metadata-c35.py"
SPEC = importlib.util.spec_from_file_location("c35_nested_dto", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def _type_block(name: str, index: int, fields: list[tuple[str, str, int]]) -> str:
    body = ["// Namespace: Stage", f"public class {name} // TypeDefIndex: {index}", "{"]
    for field_type, field_name, offset in fields:
        body.append(f"    public {field_type} {field_name}; // 0x{offset:X}")
    body.append("}")
    return "\n".join(body)


class NestedResponseDtoMetadataC35Tests(unittest.TestCase):
    def test_dummy_nested_relation_recovers_flattened_dump_types(self) -> None:
        """Real dump.cs may flatten nested types; TypeDef identity must still recover them."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dump = root / "dump.cs"
            dummy = root / "dummy.json"
            c33 = root / "c33.json"

            # DummyDll RID -> dump TypeDefIndex uses one synthetic +100 delta.
            dummy_rows = [
                (1, "Stage.BusSetFavoriteTask", "BusSetFavoriteTask", None),
                (10, "Stage.ConcertMVFinishMVLoadingTask", "ConcertMVFinishMVLoadingTask", None),
                (11, "Stage.ConcertMVFinishMVLoadingTask.ResponseDataMain", "ResponseDataMain", "Stage.ConcertMVFinishMVLoadingTask"),
                (20, "Stage.ConcertMVPollingTask", "ConcertMVPollingTask", None),
                (21, "Stage.ConcertMVPollingTask.GuestStampData", "GuestStampData", "Stage.ConcertMVPollingTask"),
                (22, "Stage.ConcertMVPollingTask.ConcertMVPollingTaskParam", "ConcertMVPollingTaskParam", "Stage.ConcertMVPollingTask"),
                (30, "Stage.ConcertMVStartTask", "ConcertMVStartTask", None),
                (31, "Stage.ConcertMVStartTask.ResponseDataMain", "ResponseDataMain", "Stage.ConcertMVStartTask"),
            ]
            dummy.write_text(json.dumps({
                "schema": 1,
                "assembly": "Assembly-CSharp.dll",
                "type_count": len(dummy_rows),
                "types": [
                    {
                        "metadata_rid": rid,
                        "type": name,
                        "short_name": short,
                        "namespace": "Stage" if parent is None else "",
                        "enclosing_type": parent,
                        "nested": parent is not None,
                    }
                    for rid, name, short, parent in dummy_rows
                ],
            }), encoding="utf-8")

            dump.write_text("\n\n".join([
                _type_block("BusSetFavoriteTask", 101, []),
                _type_block("ConcertMVFinishMVLoadingTask", 110, [
                    ("Action<ConcertMVFinishMVLoadingTask.ResponseDataMain>", "_callback", 0x58),
                ]),
                # These are deliberately FLAT declarations: old C35 saw zero nesting.
                _type_block("ResponseDataMain", 111, [
                    ("int", "status", 0x10), ("string", "token", 0x18),
                ]),
                _type_block("ConcertMVPollingTask", 120, [
                    ("ConcertMVPollingTask.ConcertMVPollingTaskParam", "_pollingTaskParam", 0x90),
                ]),
                _type_block("GuestStampData", 121, [("long", "user_id", 0x10)]),
                _type_block("ConcertMVPollingTaskParam", 122, [("int", "room_id", 0x10)]),
                _type_block("ConcertMVStartTask", 130, [
                    ("Action<ConcertMVStartTask.ResponseDataMain>", "_callback", 0x58),
                ]),
                _type_block("ResponseDataMain", 131, [
                    ("int", "result", 0x10), ("long", "start_time", 0x18),
                ]),
            ]), encoding="utf-8")

            task_fields = {
                "Stage.BusSetFavoriteTask": [],
                "Stage.ConcertMVFinishMVLoadingTask": [
                    {"field_type": "Action<ConcertMVFinishMVLoadingTask.ResponseDataMain>"}
                ],
                "Stage.ConcertMVPollingTask": [
                    {"field_type": "Action<List<ConcertApiDefine.StampData>, ConcertMVPollingTask.GuestStampData[]>"},
                    {"field_type": "ConcertMVPollingTask.ConcertMVPollingTaskParam"},
                ],
                "Stage.ConcertMVStartTask": [
                    {"field_type": "Action<ConcertMVStartTask.ResponseDataMain>"}
                ],
            }
            c33.write_text(json.dumps({
                "schema": 1,
                "target_task_count": 4,
                "tasks": [
                    {"task": task, "fields": fields}
                    for task, fields in task_fields.items()
                ],
            }), encoding="utf-8")

            report = MOD.build(dump, dummy, c33)
            self.assertEqual(report["schema"], 2)
            self.assertEqual(report["dummy_typedef_to_dump_index_delta"], 100)
            self.assertEqual(report["unresolved_c33_task_nested_ref_count"], 0)
            self.assertEqual(report["c33_task_nested_ref_count"], 4)
            names = {row["type"] for row in report["response_candidates"]}
            self.assertIn("Stage.ConcertMVStartTask.ResponseDataMain", names)
            self.assertIn("Stage.ConcertMVFinishMVLoadingTask.ResponseDataMain", names)
            start = next(
                row for row in report["response_candidates"]
                if row["type"] == "Stage.ConcertMVStartTask.ResponseDataMain"
            )
            self.assertEqual(start["type_def_index"], 131)
            self.assertEqual([f["name"] for f in start["fields"]], ["result", "start_time"])
            self.assertEqual(start["dump_declared_type"], "Stage.ResponseDataMain")

    def test_inconsistent_typedef_translation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dump = root / "dump.cs"
            dummy = root / "dummy.json"
            c33 = root / "c33.json"
            dump.write_text("\n".join(
                _type_block(task.split(".")[-1], 100 + i, []).strip()
                for i, task in enumerate(MOD.TARGET_TASKS)
            ), encoding="utf-8")
            dummy.write_text(json.dumps({
                "schema": 1,
                "types": [
                    {"metadata_rid": 1 + i * 10, "type": task, "short_name": task.split(".")[-1], "enclosing_type": None}
                    for i, task in enumerate(MOD.TARGET_TASKS)
                ],
            }), encoding="utf-8")
            c33.write_text(json.dumps({
                "schema": 1,
                "target_task_count": 4,
                "tasks": [{"task": task, "fields": []} for task in MOD.TARGET_TASKS],
            }), encoding="utf-8")
            with self.assertRaises(MOD.C35Error):
                MOD.build(dump, dummy, c33)


if __name__ == "__main__":
    unittest.main()
