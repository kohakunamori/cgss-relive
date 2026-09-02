from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze-runtime-events.py"
spec = importlib.util.spec_from_file_location("analyze_runtime_events", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class RuntimeEventAnalysisTests(unittest.TestCase):
    def event(self, route: str, *, status: int = 200, res_ver: str | None = None, result: int | None = 1, error: str | None = None):
        value = {"time": 1.0, "route": route, "status": status}
        if res_ver is not None:
            value["headers"] = {"APP-VER": "11.6.3", "RES-VER": res_ver}
        if result is not None:
            value["response_data_headers"] = {"result_code": result}
        if error is not None:
            value["error"] = error
        return value

    def test_analyze_resource_negotiation_and_post_index_endpoint(self) -> None:
        events = [
            self.event("/load/check", res_ver="10133000", result=214),
            self.event("/load/check", res_ver="10133800", result=1),
            self.event("/load/title"),
            self.event("/load/index"),
            self.event("/bn_consent/get_state", status=404, result=None, error="endpoint_not_implemented"),
        ]
        events[-1]["api_candidates"] = [
            {"group": "A", "key": 14, "name": "BnContentGetState", "literal_index": 23438}
        ]
        report = module.analyze_events(events)
        self.assertEqual(report["phase"], "post_load_index_observed")
        self.assertTrue(report["resource_negotiation"]["saw_214"])
        self.assertTrue(report["resource_negotiation"]["final_10133800_success"])
        self.assertEqual(report["after_load_index"]["route"], "/bn_consent/get_state")
        self.assertEqual(report["first_failure"]["api_candidates"][0]["key"], 14)

    def test_compare_runs_reports_first_divergence(self) -> None:
        prefix = [self.event("/load/check", res_ver="10133800"), self.event("/load/title")]
        starter = prefix + [self.event("/load/index"), self.event("/foo", status=404, result=None, error="endpoint_not_implemented")]
        empty = prefix + [self.event("/load/index", status=400, result=None, error="ValueError")]
        report = module.compare_runs([("starter", starter), ("empty", empty)])
        self.assertEqual(report["common_prefix_events"], 2)
        self.assertEqual(report["states"]["starter"]["status"], 200)
        self.assertEqual(report["states"]["empty"]["status"], 400)

    def test_load_events_rejects_unsanitized_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(json.dumps({"route": "/load/check", "status": 200, "UDID": "secret"}) + "\n")
            with self.assertRaises(module.UnsafeEventLog):
                module.load_events(path)

    def test_request_key_names_are_allowed_but_values_are_not_part_of_schema(self) -> None:
        value = {
            "route": "/load/index",
            "status": 200,
            "request_keys": ["viewer_id", "timezone"],
            "response_data_keys": ["user_info"],
        }
        validated = module.validate_event(value, line_number=1)
        self.assertEqual(validated["request_keys"], ["viewer_id", "timezone"])


if __name__ == "__main__":
    unittest.main()
