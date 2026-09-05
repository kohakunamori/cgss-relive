from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze-task-response-consumers.py"
SPEC = importlib.util.spec_from_file_location("task_response_consumers", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class TaskResponseConsumerTests(unittest.TestCase):
    def test_dump_field_parser_keeps_instance_offsets_only(self) -> None:
        text = """
// Namespace: Stage
public class SampleTask : BaseTask // TypeDefIndex: 100
{
    // Fields
    private LitJson.JsonData _data; // 0x18
    public int count; // 0x20
    private static int StaticValue; // 0x0

    // Methods
}
// Namespace: Other
public class IgnoreMe // TypeDefIndex: 101
{
    // Fields
    public int value; // 0x18
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dump.cs"
            path.write_text(text, encoding="utf-8")
            layouts = MODULE.parse_dump_fields(path, {"Stage.SampleTask"})
        self.assertEqual(set(layouts), {"Stage.SampleTask"})
        self.assertEqual(layouts["Stage.SampleTask"][0x18].name, "_data")
        self.assertEqual(layouts["Stage.SampleTask"][0x18].type_name, "LitJson.JsonData")
        self.assertEqual(layouts["Stage.SampleTask"][0x20].name, "count")
        self.assertNotIn(0, layouts["Stage.SampleTask"])

    def _route(self, route: str, endpoint_id: int) -> dict:
        return {
            "route": route,
            "endpoint_id": endpoint_id,
            "route_class": "data-only:proven-object",
            "fields": [
                {
                    "task": "Stage.SampleTask",
                    "method": "Stage.SampleTask$$Parse",
                    "field": "data",
                    "refined_shape": "proven-object",
                    "requiredness": "conditional-direct",
                }
            ],
        }

    def test_shared_parser_keeps_route_relations_distinct(self) -> None:
        c17 = {
            "schema": 1,
            "shape_only_route_count": 2,
            "routes": [self._route("/sample/a", 1), self._route("/sample/b", 2)],
        }
        targets = MODULE._target_fields(c17)
        self.assertEqual(len(targets), 1)
        self.assertEqual(len(next(iter(targets.values()))), 2)
        report = MODULE.build_report(c17, [], [], [])
        self.assertEqual(report["schema"], 2)
        self.assertEqual(report["target_route_field_relation_count"], 2)
        self.assertEqual(report["unique_native_parser_field_origin_count"], 1)
        self.assertEqual(
            report["relation_class_counts"],
            {"no-direct-task-field-store": 2},
        )

    def test_report_preserves_structural_evidence_without_promotion(self) -> None:
        c17 = {
            "schema": 1,
            "shape_only_route_count": 1,
            "routes": [self._route("/sample", 1)],
        }
        stores = [
            {
                "task": "Stage.SampleTask",
                "parser_method": "Stage.SampleTask$$Parse",
                "response_field": "data",
                "parser_rva": 0x1000,
                "store_rva": 0x1010,
                "task_field": "_data",
                "task_field_type": "LitJson.JsonData",
                "task_field_offset": 0x18,
            }
        ]
        readers = [
            {
                "task": "Stage.SampleTask",
                "task_field_offset": 0x18,
                "reader_rva": 0x2000,
                "reader_methods": ["Stage.SampleTask$$get_Data"],
                "load_rva": 0x2000,
            }
        ]
        callers = [
            {
                "task": "Stage.SampleTask",
                "task_field_offset": 0x18,
                "reader_rva": 0x2000,
                "reader_methods": ["Stage.SampleTask$$get_Data"],
                "call_kind": "BL",
                "callsite_rva": 0x3010,
                "caller_rva": 0x3000,
                "caller_methods": ["Stage.SampleView$$CallbackOnSuccess"],
            }
        ]
        report = MODULE.build_report(c17, stores, readers, callers)
        self.assertEqual(report["target_route_field_relation_count"], 1)
        self.assertEqual(report["unique_native_parser_field_origin_count"], 1)
        self.assertEqual(report["relation_class_counts"], {"stored-reader-direct-caller": 1})
        row = report["fields"][0]
        self.assertEqual(row["relation_class"], "stored-reader-direct-caller")
        self.assertEqual(row["direct_reader_callers"][0]["caller_methods"], ["Stage.SampleView$$CallbackOnSuccess"])
        self.assertEqual(row["empty_value_promotion"], "not-proven-by-c18b")


if __name__ == "__main__":
    unittest.main()
