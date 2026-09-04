import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

from server.low_complexity_evidence import LowComplexityEvidenceIndex

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "enrich-runtime-contract-blocker.py"
SPEC = importlib.util.spec_from_file_location("runtime_blocker_enrichment", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


def runtime():
    return {
        "schema": 5,
        "runs": {
            "device": {
                "semantic_contract_blocker": {
                    "route": "/x",
                    "status": 501,
                    "candidate_endpoint_ids": [7],
                }
            }
        },
    }


def c14():
    return {
        "schema": 1,
        "endpoint_count": 1,
        "unique_route_count": 1,
        "routes": [
            {
                "route": "/x",
                "endpoints": [
                    {
                        "endpoint_id": 7,
                        "concrete_response_fields": [],
                        "concrete_required_response_fields": [],
                        "concrete_unknown_response_fields": [],
                        "effective_base_parser_summary": {
                            "effective_base_parser_count": 0,
                            "effective_base_field_link_count": 0,
                            "effective_base_required_field_link_count": 0,
                            "effective_base_unknown_field_link_count": 0,
                            "effective_base_provenance": [],
                        },
                        "inferred_subsystems": [],
                        "exact_state_mutation_count": 0,
                    }
                ],
            }
        ],
    }


class RuntimeContractBlockerEnrichmentTests(unittest.TestCase):
    def _low_index(self):
        td = tempfile.TemporaryDirectory()
        path = Path(td.name) / "c22.json"
        path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "routes": [
                        {
                            "route": "/x",
                            "endpoint_id": 7,
                            "effective_shape": "proven-object",
                            "effective_shape_source": "C21-helper-json-operations",
                            "empty_value_status": "not-proven",
                            "consumer_resolution": "direct-managed-consumer",
                            "next_action": "device/runtime-observation-or-deeper-empty-value-proof",
                            "static_evidence_only": True,
                            "untouched_client_acceptance": False,
                            "c17_fields": [{"field": "must-not-leak"}],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return td, LowComplexityEvidenceIndex(path, enforce_final_counts=False)

    def test_optional_c22_summary_is_runtime_safe(self):
        td, index = self._low_index()
        try:
            report = MOD.enrich(runtime(), c14(), index)
        finally:
            td.cleanup()
        blocker = report["runs"]["device"]["semantic_contract_blocker"]
        low = blocker["low_complexity_response_evidence"]
        self.assertEqual(low["effective_shape"], "proven-object")
        self.assertEqual(low["empty_value_status"], "not-proven")
        self.assertNotIn("c17_fields", low)
        self.assertEqual(blocker["next_action"], "observe_runtime_or_prove_empty_value_before_template")
        self.assertEqual(report["low_complexity_route_count"], 1)

    def test_without_c22_preserves_contract_reconstruction_action(self):
        report = MOD.enrich(runtime(), c14())
        blocker = report["runs"]["device"]["semantic_contract_blocker"]
        self.assertNotIn("low_complexity_response_evidence", blocker)
        self.assertEqual(
            blocker["next_action"],
            "reconstruct_concrete_plus_effective_base_response_model",
        )

    def test_rejects_c22_endpoint_mismatch(self):
        td, index = self._low_index()
        bad = runtime()
        bad["runs"]["device"]["semantic_contract_blocker"]["candidate_endpoint_ids"] = [8]
        try:
            with self.assertRaises(MOD.EnrichmentError):
                MOD.enrich(bad, c14(), index)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
