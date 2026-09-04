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


def _row(rid, name, short, parent=None, fields=None, serializable=True):
    return {
        "metadata_rid": rid,
        "type": name,
        "short_name": short,
        "namespace": "Stage" if parent is None else "",
        "enclosing_type": parent,
        "nested": parent is not None,
        "serializable_flag": serializable,
        "custom_attributes": [],
        "field_count": len(fields or []),
        "fields": fields or [],
    }


def _field(rid, name, field_type, *, visibility="public", static=False, attrs=None):
    return {
        "metadata_rid": rid,
        "name": name,
        "field_type": field_type,
        "visibility": visibility,
        "is_static": static,
        "is_init_only": False,
        "custom_attributes": attrs or [],
    }


def _write_c33(path: Path) -> None:
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
    path.write_text(json.dumps({
        "schema": 1,
        "target_task_count": 4,
        "tasks": [{"task": task, "fields": fields} for task, fields in task_fields.items()],
    }), encoding="utf-8")


class NestedResponseDtoMetadataC35Tests(unittest.TestCase):
    def test_exact_nested_identity_and_serialization_candidate_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dummy = root / "dummy.json"
            c33 = root / "c33.json"
            rows = [
                _row(1, "Stage.BusSetFavoriteTask", "BusSetFavoriteTask", serializable=False),
                _row(10, "Stage.ConcertMVFinishMVLoadingTask", "ConcertMVFinishMVLoadingTask", serializable=False),
                _row(11, "Stage.ConcertMVFinishMVLoadingTask.ResponseDataMain", "ResponseDataMain", "Stage.ConcertMVFinishMVLoadingTask", [
                    _field(1, "status", "int"),
                    _field(2, "_token", "string", visibility="private", attrs=["UnityEngine.SerializeField"]),
                    _field(3, "ignored", "int", visibility="private"),
                ]),
                _row(20, "Stage.ConcertMVPollingTask", "ConcertMVPollingTask", serializable=False),
                _row(21, "Stage.ConcertMVPollingTask.GuestStampData", "GuestStampData", "Stage.ConcertMVPollingTask", [_field(4, "user_id", "long")]),
                _row(22, "Stage.ConcertMVPollingTask.ConcertMVPollingTaskParam", "ConcertMVPollingTaskParam", "Stage.ConcertMVPollingTask", [_field(5, "room_id", "int")]),
                _row(30, "Stage.ConcertMVStartTask", "ConcertMVStartTask", serializable=False),
                _row(31, "Stage.ConcertMVStartTask.ResponseDataMain", "ResponseDataMain", "Stage.ConcertMVStartTask", [
                    _field(6, "result", "int"), _field(7, "start_time", "long")
                ]),
            ]
            dummy.write_text(json.dumps({"schema": 2, "types": rows}), encoding="utf-8")
            _write_c33(c33)

            report = MOD.build(dummy, c33)
            self.assertEqual(report["schema"], 3)
            self.assertEqual(report["unresolved_c33_task_nested_ref_count"], 0)
            self.assertEqual(report["c33_task_nested_ref_count"], 4)
            names = {row["type"] for row in report["response_candidates"]}
            self.assertIn("Stage.ConcertMVStartTask.ResponseDataMain", names)
            finish = next(row for row in report["response_candidates"] if row["type"].endswith("FinishMVLoadingTask.ResponseDataMain"))
            candidates = {f["name"]: f["unity_serialized_field_candidate"] for f in finish["fields"]}
            self.assertEqual(candidates, {"status": True, "_token": True, "ignored": False})

    def test_missing_c33_nested_reference_is_reported_not_invented(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dummy = root / "dummy.json"
            c33 = root / "c33.json"
            rows = [_row(i + 1, task, task.split(".")[-1], serializable=False) for i, task in enumerate(MOD.TARGET_TASKS)]
            dummy.write_text(json.dumps({"schema": 2, "types": rows}), encoding="utf-8")
            _write_c33(c33)
            report = MOD.build(dummy, c33)
            self.assertEqual(report["unresolved_c33_task_nested_ref_count"], 4)
            self.assertEqual(report["response_candidate_count"], 0)


if __name__ == "__main__":
    unittest.main()
