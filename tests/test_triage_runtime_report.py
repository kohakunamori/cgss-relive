from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "triage-runtime-report.py"
spec = importlib.util.spec_from_file_location("triage_runtime_report", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class RuntimeTriageTests(unittest.TestCase):
    def run(
        self,
        *,
        phase: str,
        sequence: list[dict] | None = None,
        reached: dict | None = None,
        negotiation: dict | None = None,
        resource_routes: list[str] | None = None,
        first_failure: dict | None = None,
        device: dict | None = None,
    ) -> dict:
        reached_value = {
            "load_check": False,
            "load_title": False,
            "resource_plane": False,
            "resource_manifest": False,
            "load_index": False,
        }
        if reached:
            reached_value.update(reached)
        negotiation_value = {
            "server_returned_214": False,
            "observed_resource_request_after_214": False,
            "observed_successful_resource_response_after_214": False,
            "server_returned_direct_success_with_required_res_ver": False,
            "observed_followup_request_after_direct_success": False,
            "server_returned_success_for_10133800": False,
            "observed_followup_request_after_10133800_success": False,
        }
        if negotiation:
            negotiation_value.update(negotiation)
        return {
            "phase": phase,
            "events": len(sequence or []),
            "reached": reached_value,
            "resource_negotiation": negotiation_value,
            "resource_plane": {
                "events": 0,
                "successful_events": 0,
                "routes": resource_routes or [],
            },
            "first_failure": first_failure,
            "after_load_index": None,
            "sequence": sequence or [],
            **({"device_diagnostics": device} if device is not None else {}),
        }

    def source(self, run: dict) -> dict:
        return {
            "schema": 4,
            "final_resource_version": "10133800",
            "runs": {"starter": run},
            "comparison": None,
        }

    def device(
        self,
        *,
        first_category: str | None = None,
        tls: bool = False,
        crash: bool = False,
        anr: bool = False,
        network: bool = False,
    ) -> dict:
        return {
            "events": 1 if first_category else 0,
            "categories": {},
            "severities": {},
            "first_event": None,
            "first_failure": (
                {"time": 1.0, "category": first_category, "severity": "error"}
                if first_category
                else None
            ),
            "has_tls_error": tls,
            "has_process_crash": crash,
            "has_anr": anr,
            "has_network_error": network,
        }

    def classification(self, run: dict) -> dict:
        return module.build_triage_report(self.source(run))["runs"]["starter"]

    def test_no_http_tls_error_is_pre_http_tls_gate(self) -> None:
        result = self.classification(
            self.run(
                phase="no_http_request",
                device=self.device(first_category="tls_certificate_error", tls=True),
            )
        )
        self.assertEqual(result["classification"], "pre_http_tls_failure")
        self.assertEqual(result["next_gate"], "fix_device_tls_trust_or_route")
        self.assertFalse(result["visible_home_proven"])

    def test_214_without_resource_does_not_require_second_load_check(self) -> None:
        result = self.classification(
            self.run(
                phase="resource_version_214_responded",
                sequence=[{"route": "/load/check", "status": 200}],
                reached={"load_check": True},
                negotiation={"server_returned_214": True},
            )
        )
        self.assertEqual(result["classification"], "stalled_after_214_before_resource")
        self.assertEqual(result["next_gate"], "verify_savedata_res_ver_and_storage_route")
        self.assertIn("second /load/check", result["reason"])

    def test_unresolved_resource_family_precedes_generic_stall(self) -> None:
        result = self.classification(
            self.run(
                phase="resource_plane_observed",
                sequence=[
                    {"route": "/load/check", "status": 200},
                    {"route": "@resource/unresolved", "status": 200},
                ],
                reached={"load_check": True, "resource_plane": True},
                negotiation={
                    "server_returned_214": True,
                    "observed_resource_request_after_214": True,
                },
                resource_routes=["@resource/unresolved"],
            )
        )
        self.assertEqual(result["classification"], "resource_route_unresolved")
        self.assertEqual(result["next_gate"], "identify_missing_resource_url_family_privately")

    def test_served_resource_without_index_is_resource_stall(self) -> None:
        result = self.classification(
            self.run(
                phase="resource_plane_served",
                sequence=[
                    {"route": "/load/check", "status": 200},
                    {"route": "@resource/manifest", "status": 200},
                ],
                reached={
                    "load_check": True,
                    "resource_plane": True,
                    "resource_manifest": True,
                },
                negotiation={
                    "server_returned_214": True,
                    "observed_resource_request_after_214": True,
                    "observed_successful_resource_response_after_214": True,
                },
                resource_routes=["@resource/manifest"],
            )
        )
        self.assertEqual(result["classification"], "stalled_after_resource_plane")
        self.assertEqual(result["next_gate"], "capture_next_resource_or_load_index_action")

    def test_load_index_success_never_claims_visible_home(self) -> None:
        result = self.classification(
            self.run(
                phase="load_index_reached",
                sequence=[
                    {"route": "/load/check", "status": 200},
                    {"route": "@resource/manifest", "status": 200},
                    {"route": "/load/index", "status": 200},
                ],
                reached={
                    "load_check": True,
                    "resource_plane": True,
                    "resource_manifest": True,
                    "load_index": True,
                },
            )
        )
        self.assertEqual(result["classification"], "load_index_reached_visual_gate")
        self.assertFalse(result["visible_home_proven"])
        self.assertEqual(result["next_gate"], "confirm_visible_home_or_capture_next_action")

    def test_load_index_failure_is_server_contract_gate(self) -> None:
        result = self.classification(
            self.run(
                phase="load_index_reached",
                sequence=[{"route": "/load/index", "status": 500}],
                reached={"load_index": True},
                first_failure={
                    "event_index": 0,
                    "route": "/load/index",
                    "status": 500,
                    "error": "internal_error",
                },
            )
        )
        self.assertEqual(result["classification"], "load_index_response_failure")
        self.assertEqual(result["first_server_failure"]["route"], "/load/index")

    def test_failed_load_index_retry_then_success_prefers_progress(self) -> None:
        result = self.classification(
            self.run(
                phase="load_index_reached",
                sequence=[
                    {"route": "/load/index", "status": 500},
                    {"route": "/load/index", "status": 200},
                ],
                reached={"load_index": True},
                first_failure={
                    "event_index": 0,
                    "route": "/load/index",
                    "status": 500,
                    "error": "internal_error",
                },
            )
        )
        self.assertEqual(result["classification"], "load_index_reached_visual_gate")
        self.assertFalse(result["visible_home_proven"])

    def test_first_failure_after_index_is_post_index_server_gap(self) -> None:
        result = self.classification(
            self.run(
                phase="post_load_index_observed",
                sequence=[
                    {"route": "/load/index", "status": 200},
                    {"route": "/bn_consent/get_state", "status": 404},
                ],
                reached={"load_index": True},
                first_failure={
                    "event_index": 1,
                    "route": "/bn_consent/get_state",
                    "status": 404,
                    "error": "endpoint_not_implemented",
                },
            )
        )
        self.assertEqual(result["classification"], "post_load_index_server_gap")
        self.assertEqual(result["next_gate"], "implement_first_post_load_index_route")

    def test_earlier_recoverable_failure_does_not_override_load_index_progress(self) -> None:
        result = self.classification(
            self.run(
                phase="load_index_reached",
                sequence=[
                    {"route": "/optional", "status": 404},
                    {"route": "/load/index", "status": 200},
                ],
                reached={"load_index": True},
                first_failure={
                    "event_index": 0,
                    "route": "/optional",
                    "status": 404,
                    "error": "endpoint_not_implemented",
                },
            )
        )
        self.assertEqual(result["classification"], "load_index_reached_visual_gate")

    def test_crash_after_load_index_is_device_gate(self) -> None:
        result = self.classification(
            self.run(
                phase="load_index_reached",
                sequence=[{"route": "/load/index", "status": 200}],
                reached={"load_index": True},
                device=self.device(first_category="process_crash", crash=True),
            )
        )
        self.assertEqual(result["classification"], "client_failure_after_load_index")
        self.assertEqual(result["first_device_failure_category"], "process_crash")

    def test_wrong_source_schema_is_rejected(self) -> None:
        source = self.source(self.run(phase="no_http_request"))
        source["schema"] = 3
        with self.assertRaises(module.UnsafeRuntimeReport):
            module.build_triage_report(source)

    def test_triage_output_is_summary_not_source_passthrough(self) -> None:
        source = self.source(self.run(phase="no_http_request"))
        source["secret"] = "must-not-pass-through"
        report = module.build_triage_report(source)
        self.assertNotIn("secret", report)
        self.assertEqual(report["schema"], 1)
        self.assertTrue(report["visible_home_requires_real_device_observation"])


if __name__ == "__main__":
    unittest.main()
