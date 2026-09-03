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
    def event(
        self,
        route: str,
        *,
        status: int = 200,
        res_ver: str | None = None,
        result: int | None = 1,
        required_res_ver: str | None = None,
        error: str | None = None,
    ):
        value = {"time": 1.0, "route": route, "status": status}
        if res_ver is not None:
            value["headers"] = {"APP-VER": "11.6.3", "RES-VER": res_ver}
        if result is not None or required_res_ver is not None:
            response_headers = {}
            if result is not None:
                response_headers["result_code"] = result
            if required_res_ver is not None:
                response_headers["required_res_ver"] = required_res_ver
            value["response_data_headers"] = response_headers
        if error is not None:
            value["error"] = error
        return value

    def test_analyze_resource_negotiation_and_post_index_endpoint(self) -> None:
        events = [
            self.event(
                "/load/check",
                res_ver="10133000",
                result=214,
                required_res_ver="10133800",
            ),
            self.event("/load/check", res_ver="10133800", result=1),
            self.event("/load/title"),
            self.event("/load/index"),
            self.event(
                "/bn_consent/get_state",
                status=404,
                result=None,
                error="endpoint_not_implemented",
            ),
        ]
        events[-1]["api_candidates"] = [
            {"group": "A", "key": 14, "name": "BnContentGetState", "literal_index": 23438}
        ]
        report = module.analyze_events(events)
        self.assertEqual(report["phase"], "post_load_index_observed")
        negotiation = report["resource_negotiation"]
        self.assertTrue(negotiation["server_returned_214"])
        self.assertTrue(negotiation["observed_later_control_request_after_214"])
        self.assertTrue(negotiation["observed_later_10133800_load_check_after_214"])
        self.assertFalse(negotiation["server_returned_direct_success_with_required_res_ver"])
        self.assertTrue(negotiation["server_returned_success_for_10133800"])
        self.assertTrue(negotiation["observed_followup_request_after_10133800_success"])
        self.assertEqual(report["after_load_index"]["route"], "/bn_consent/get_state")
        self.assertEqual(report["first_failure"]["api_candidates"][0]["key"], 14)

    def test_214_alone_does_not_claim_retry_or_acceptance(self) -> None:
        report = module.analyze_events(
            [
                self.event(
                    "/load/check",
                    res_ver="10133000",
                    result=214,
                    required_res_ver="10133800",
                )
            ]
        )
        self.assertEqual(report["phase"], "resource_version_214_responded")
        negotiation = report["resource_negotiation"]
        self.assertTrue(negotiation["server_returned_214"])
        self.assertFalse(negotiation["observed_later_control_request_after_214"])
        self.assertFalse(negotiation["observed_later_10133800_load_check_after_214"])

    def test_direct_success_is_reported_separately_from_final_version_success(self) -> None:
        events = [
            self.event(
                "/load/check",
                res_ver="10133000",
                result=1,
                required_res_ver="10133800",
            ),
            self.event("/load/index"),
        ]
        report = module.analyze_events(events)
        negotiation = report["resource_negotiation"]
        self.assertTrue(negotiation["server_returned_direct_success_with_required_res_ver"])
        self.assertTrue(negotiation["observed_followup_request_after_direct_success"])
        self.assertFalse(negotiation["server_returned_success_for_10133800"])
        self.assertEqual(report["phase"], "load_index_reached")

    def test_final_success_response_alone_does_not_claim_client_acceptance(self) -> None:
        report = module.analyze_events([self.event("/load/check", res_ver="10133800", result=1)])
        self.assertEqual(report["phase"], "final_version_load_check_responded")
        negotiation = report["resource_negotiation"]
        self.assertFalse(negotiation["server_returned_214"])
        self.assertFalse(negotiation["observed_later_10133800_load_check_after_214"])
        self.assertTrue(negotiation["server_returned_success_for_10133800"])
        self.assertFalse(negotiation["observed_followup_request_after_10133800_success"])

    def test_load_title_does_not_advance_hard_mainline_phase(self) -> None:
        report = module.analyze_events(
            [
                self.event("/load/check", res_ver="10133800", result=1),
                self.event("/load/title"),
            ]
        )
        self.assertEqual(report["phase"], "final_version_load_check_responded")
        self.assertTrue(report["reached"]["load_title"])

    def test_compare_runs_reports_first_divergence(self) -> None:
        prefix = [self.event("/load/check", res_ver="10133800"), self.event("/load/title")]
        starter = prefix + [
            self.event("/load/index"),
            self.event("/foo", status=404, result=None, error="endpoint_not_implemented"),
        ]
        empty = prefix + [self.event("/load/index", status=400, result=None, error="ValueError")]
        report = module.compare_runs([("starter", starter), ("empty", empty)])
        self.assertEqual(report["common_prefix_events"], 2)
        self.assertEqual(report["states"]["starter"]["status"], 200)
        self.assertEqual(report["states"]["empty"]["status"], 400)

    def test_load_events_rejects_unsanitized_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(
                json.dumps({"route": "/load/check", "status": 200, "UDID": "secret"}) + "\n"
            )
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
