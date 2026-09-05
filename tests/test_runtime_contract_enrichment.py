from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "enrich-runtime-contract-blocker.py"
SPEC = importlib.util.spec_from_file_location("runtime_contract_enrichment", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _catalog() -> dict:
    return {
        "schema": 1,
        "endpoint_count": 538,
        "unique_route_count": 526,
        "routes": [
            {
                "route": "/story/start",
                "endpoints": [
                    {
                        "endpoint_id": 48,
                        "concrete_response_fields": [
                            {"field": "story_id"},
                            {"field": "result"},
                        ],
                        "concrete_required_response_fields": [{"field": "story_id"}],
                        "concrete_unknown_response_fields": [],
                        "exact_state_mutation_count": 3,
                        "inferred_subsystems": ["story-commu"],
                        "effective_base_parser_summary": {
                            "effective_base_parser_count": 1,
                            "effective_base_field_link_count": 4,
                            "effective_base_required_field_link_count": 1,
                            "effective_base_unknown_field_link_count": 2,
                            "effective_base_provenance": ["direct-BL"],
                        },
                    }
                ],
            }
        ],
    }


def _runtime(route: str = "/story/start", endpoint_ids: list[int] | None = None) -> dict:
    if endpoint_ids is None:
        endpoint_ids = [48]
    return {
        "schema": 5,
        "runs": {
            "device": {
                "semantic_contract_blocker": {
                    "route": route,
                    "status": 501,
                    "candidate_endpoint_ids": endpoint_ids,
                }
            }
        },
    }


class RuntimeContractEnrichmentTests(unittest.TestCase):
    def test_enriches_unique_blocker_without_field_names(self) -> None:
        report = MODULE.enrich(_runtime(), _catalog())
        blocker = report["runs"]["device"]["semantic_contract_blocker"]
        self.assertEqual(
            blocker["next_action"],
            "reconstruct_concrete_plus_effective_base_response_model",
        )
        self.assertFalse(blocker["route_identity_ambiguous"])
        candidate = blocker["effective_contract_candidates"][0]
        self.assertEqual(
            candidate,
            {
                "endpoint_id": 48,
                "route": "/story/start",
                "concrete_response_field_count": 2,
                "concrete_required_response_field_count": 1,
                "concrete_unknown_response_field_count": 0,
                "exact_state_mutation_count": 3,
                "effective_base_parser_count": 1,
                "effective_base_field_link_count": 4,
                "effective_base_required_field_link_count": 1,
                "effective_base_unknown_field_link_count": 2,
                "effective_base_provenance": ["direct-BL"],
                "inferred_subsystems": ["story-commu"],
            },
        )
        text = repr(report)
        self.assertNotIn("story_id", text)
        self.assertNotIn("result", text)

    def test_enrichment_rejects_runtime_catalog_route_mismatch(self) -> None:
        with self.assertRaisesRegex(MODULE.EnrichmentError, "runtime/C14 route mismatch"):
            MODULE.enrich(_runtime(route="/wrong"), _catalog())

    def test_run_without_semantic_blocker_remains_explicitly_empty(self) -> None:
        runtime = {"schema": 5, "runs": {"device": {"semantic_contract_blocker": None}}}
        report = MODULE.enrich(runtime, _catalog())
        self.assertEqual(
            report["runs"]["device"],
            {"semantic_contract_blocker": None},
        )


if __name__ == "__main__":
    unittest.main()
