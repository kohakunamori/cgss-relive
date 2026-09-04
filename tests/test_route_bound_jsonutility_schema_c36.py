from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-route-bound-jsonutility-schema-c36.py"
SPEC = importlib.util.spec_from_file_location("c36_route_schema", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)

TASKS = MOD.TARGET_TASKS


def field(name, field_type):
    return {
        "name": name,
        "field_type": field_type,
        "visibility": "public",
        "metadata_rid": 1,
        "unity_serialized_field_candidate": True,
    }


def nested(type_name, fields):
    return {"type": type_name, "fields": fields, "serializable_flag": True}


def c14_fixture():
    mapping = {
        "Stage.BusSetFavoriteTask": ("/bus/favorite", 317),
        "Stage.ConcertMVFinishMVLoadingTask": ("/concert/finish_mv_loading", 304),
        "Stage.ConcertMVPollingTask": ("/concert/mv_polling", 306),
        "Stage.ConcertMVStartTask": ("/concert/mv_start", 303),
    }
    routes = []
    for task, (route, endpoint_id) in mapping.items():
        routes.append({
            "route": route,
            "ambiguous_path_identity": False,
            "endpoints": [{
                "endpoint_id": endpoint_id,
                "api_key": endpoint_id - 1,
                "enum": "X",
                "status": "proven-static",
                "concrete_response_fields": [{
                    "task": task,
                    "method": task + "$$Parse",
                    "field": "data",
                }],
            }],
        })
    return {"routes": routes}


def c35_fixture():
    rows = {
        "Stage.BusSetFavoriteTask": [
            nested("Stage.BusSetFavoriteTask.BusSetFavoriteResponse", [
                field("favorite_chara_ids", "System.Collections.Generic.List`1<int>"),
                field("un_favorite_chara_ids", "System.Collections.Generic.List`1<int>"),
            ]),
        ],
        "Stage.ConcertMVFinishMVLoadingTask": [
            nested("Stage.ConcertMVFinishMVLoadingTask.ResponseDataMain", [
                field("loading_wait_time", "int"),
                field("mv_end_wait_time", "int"),
            ]),
        ],
        "Stage.ConcertMVPollingTask": [
            nested("Stage.ConcertMVPollingTask.GuestStampData", [
                field("stamp_id", "int"), field("count", "int"),
            ]),
            nested("Stage.ConcertMVPollingTask.ResponseDataMain", [
                field("host_stamp_list", "Stage.Concert.ConcertApiDefine.StampData[]"),
                field("guest_stamp_list", "Stage.ConcertMVPollingTask.GuestStampData[]"),
                field("room_status", "int"),
            ]),
        ],
        "Stage.ConcertMVStartTask": [
            nested("Stage.ConcertMVStartTask.CharaData", [field("card_id", "int")]),
            nested("Stage.ConcertMVStartTask.ResponseDataMain", [
                field("live_id", "int"),
                field("unit_list", "Stage.ConcertMVStartTask.CharaData[]"),
            ]),
        ],
    }
    tasks = [{"task": task, "nested_types": rows[task]} for task in TASKS]
    candidates = []
    for task, types in rows.items():
        for row in types:
            candidates.append({"task": task, **row})
    return {
        "schema": 3,
        "identity_proof": "DummyDll-ECMA335-NestedClass",
        "field_surface_proof": "DummyDll-ECMA335-FieldDefinition",
        "tasks": tasks,
        "response_candidates": candidates,
    }


class C36Tests(unittest.TestCase):
    def test_exact_bindings_and_recursive_shapes(self):
        report = MOD.build(c14_fixture(), c35_fixture())
        self.assertEqual(report["route_count"], 4)
        by_route = {row["route"]: row for row in report["routes"]}
        self.assertEqual(by_route["/bus/favorite"]["endpoint_id"], 317)
        self.assertEqual(
            by_route["/concert/mv_polling"]["root_dto_type"],
            "Stage.ConcertMVPollingTask.ResponseDataMain",
        )
        polling = by_route["/concert/mv_polling"]["response_json_schema"]
        guest = next(f for f in polling["fields"] if f["json_key"] == "guest_stamp_list")
        self.assertEqual(guest["kind"], "array")
        self.assertEqual(guest["element"]["field_count"], 2)
        self.assertIn(
            "Stage.Concert.ConcertApiDefine.StampData",
            polling["unresolved_external_types"],
        )
        start = by_route["/concert/mv_start"]["response_json_schema"]
        unit = next(f for f in start["fields"] if f["json_key"] == "unit_list")
        self.assertEqual(unit["element"]["fields"][0]["json_key"], "card_id")
        self.assertFalse(report["value_semantics_inferred"])
        self.assertEqual(report["runtime_templates_promoted"], 0)

    def test_ambiguous_task_route_fails_closed(self):
        c14 = c14_fixture()
        duplicate = {**c14["routes"][0], "route": "/wrong/duplicate"}
        c14["routes"].append(duplicate)
        with self.assertRaises(MOD.C36Error):
            MOD.build(c14, c35_fixture())

    def test_ambiguous_root_fails_closed(self):
        c35 = c35_fixture()
        bus = next(row for row in c35["tasks"] if row["task"] == "Stage.BusSetFavoriteTask")
        extra = nested("Stage.BusSetFavoriteTask.OtherResponse", [field("x", "int")])
        bus["nested_types"].append(extra)
        c35["response_candidates"].append({"task": "Stage.BusSetFavoriteTask", **extra})
        with self.assertRaises(MOD.C36Error):
            MOD.build(c14_fixture(), c35)


if __name__ == "__main__":
    unittest.main()
