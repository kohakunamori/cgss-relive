import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build-low-complexity-response-evidence.py"
SPEC = importlib.util.spec_from_file_location("c22_low_complexity", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)


class LowComplexityEvidenceTests(unittest.TestCase):
    def test_effective_shape_upgrades_only_from_stronger_evidence(self):
        base = {"route_class": "data-only:opaque:json"}
        self.assertEqual(
            MOD.effective_shape_for(base, None, {"shape_refinement": "helper-proven-object"}),
            ("proven-object", "C21-helper-json-operations"),
        )
        self.assertEqual(
            MOD.effective_shape_for(base, None, {"shape_refinement": "helper-unresolved"}),
            ("opaque:json", "C17-direct-parser-shape"),
        )
        countable = {"route_class": "data-only:countable-collection-ambiguous"}
        self.assertEqual(
            MOD.effective_shape_for(countable, {"container_usage_class": "string-key-object"}, None),
            ("proven-object", "C19c-string-key-get_Item-signature"),
        )

    def test_empty_shape_and_empty_value_are_separate(self):
        status, source = MOD.empty_status_for(
            {"parser_empty_object_class": "not-proven"},
            {"parser_empty_container_class": "not-proven"},
        )
        self.assertEqual(status, "not-proven")
        self.assertIsNone(source)
        status, source = MOD.empty_status_for(
            {"parser_empty_object_class": "parser-empty-object-zero-path"}, None
        )
        self.assertEqual(status, "parser-local-empty-object-zero-path")
        self.assertEqual(source, "C19b")

    def test_route_index_rejects_duplicates(self):
        with self.assertRaises(MOD.CatalogError):
            MOD.route_index({"routes": [{"route": "/x"}, {"route": "/x"}]}, "synthetic")


if __name__ == "__main__":
    unittest.main()
