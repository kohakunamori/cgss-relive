import json
import tempfile
import unittest
from pathlib import Path

from server.low_complexity_evidence import LowComplexityEvidenceIndex


class LowComplexityEvidenceIndexTests(unittest.TestCase):
    def _write(self, row):
        td = tempfile.TemporaryDirectory()
        path = Path(td.name) / "c22.json"
        path.write_text(json.dumps({"schema": 1, "routes": [row]}), encoding="utf-8")
        return td, path

    def test_safe_summary_excludes_parser_fields_and_values(self):
        row = {
            "route": "/x",
            "endpoint_id": 7,
            "effective_shape": "proven-object",
            "effective_shape_source": "C21-helper-json-operations",
            "empty_value_status": "not-proven",
            "consumer_resolution": "direct-managed-consumer",
            "next_action": "device/runtime-observation-or-deeper-empty-value-proof",
            "static_evidence_only": True,
            "untouched_client_acceptance": False,
            "c17_fields": [{"field": "secret-parser-field"}],
        }
        td, path = self._write(row)
        try:
            index = LowComplexityEvidenceIndex(path, enforce_final_counts=False)
            summary = index.safe_route_summary("x?foo=1")
        finally:
            td.cleanup()
        self.assertEqual(summary["route"], "/x")
        self.assertEqual(summary["effective_shape"], "proven-object")
        self.assertNotIn("c17_fields", summary)
        self.assertNotIn("response_value", summary)

    def test_rejects_any_client_acceptance_claim(self):
        row = {
            "route": "/x",
            "endpoint_id": 7,
            "effective_shape": "opaque:json",
            "effective_shape_source": "C17-direct-parser-shape",
            "empty_value_status": "not-proven",
            "consumer_resolution": "no-consumer-recovered",
            "next_action": "reconstruct-business-value-semantics",
            "static_evidence_only": True,
            "untouched_client_acceptance": True,
        }
        td, path = self._write(row)
        try:
            with self.assertRaises(ValueError):
                LowComplexityEvidenceIndex(path, enforce_final_counts=False)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
