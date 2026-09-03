from __future__ import annotations

import importlib.util
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "preflight-local-resources.py"
spec = importlib.util.spec_from_file_location("preflight_local_resources", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class LocalResourcePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "cache"
        self.root.mkdir(parents=True)
        self.db = Path(self.temp.name) / "manifest.db"
        self.hashes = (
            "0123456789abcdef0123456789abcdef",
            "fedcba9876543210fedcba9876543210",
        )
        with sqlite3.connect(self.db) as connection:
            connection.execute("CREATE TABLE manifests (name TEXT, hash TEXT)")
            connection.executemany(
                "INSERT INTO manifests(name, hash) VALUES (?, ?)",
                [("a", self.hashes[0]), ("b", self.hashes[1])],
            )
        wire = self.root / "manifests"
        wire.mkdir()
        for name in module.WIRE_MANIFESTS:
            (wire / name).write_bytes(b"wire")
        for digest in self.hashes:
            path = self.root / "objects" / digest[:2] / digest
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"object")

        self.old_rows = module.EXPECTED_MANIFEST_ROWS
        self.old_hashes = module.EXPECTED_UNIQUE_HASHES
        module.EXPECTED_MANIFEST_ROWS = 2
        module.EXPECTED_UNIQUE_HASHES = 2

    def tearDown(self) -> None:
        module.EXPECTED_MANIFEST_ROWS = self.old_rows
        module.EXPECTED_UNIQUE_HASHES = self.old_hashes
        self.temp.cleanup()

    def test_complete_cache_is_ready(self) -> None:
        report = module.run_preflight(self.root, self.db, version=module.FINAL_RESOURCE_VERSION)
        self.assertTrue(report["ready"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["manifest"]["quick_check"], ["ok"])
        self.assertEqual(report["manifest"]["rows"], 2)
        self.assertEqual(report["manifest"]["unique_hashes"], 2)
        self.assertEqual(report["wire_manifests_present"], 2)
        self.assertEqual(report["objects"]["present"], 2)
        self.assertEqual(report["objects"]["missing"], 0)

    def test_missing_wire_and_object_are_sanitized_failures(self) -> None:
        (self.root / "manifests" / module.WIRE_MANIFESTS[0]).unlink()
        missing_digest = self.hashes[1]
        (self.root / "objects" / missing_digest[:2] / missing_digest).unlink()

        report = module.run_preflight(self.root, self.db, version=module.FINAL_RESOURCE_VERSION)
        self.assertFalse(report["ready"])
        self.assertIn("wire_manifest_missing", report["failures"])
        self.assertIn("resource_objects_missing", report["failures"])
        self.assertEqual(report["objects"]["missing"], 1)
        serialized = repr(report)
        self.assertNotIn(missing_digest, serialized)
        self.assertNotIn("all_dbmanifest", serialized)

    def test_wrong_version_and_invalid_hash_are_rejected(self) -> None:
        with sqlite3.connect(self.db) as connection:
            connection.execute("UPDATE manifests SET hash='not-a-hash' WHERE name='a'")
        report = module.run_preflight(self.root, self.db, version="10133000")
        self.assertFalse(report["ready"])
        self.assertIn("resource_version_mismatch", report["failures"])
        self.assertIn("manifest_contains_invalid_hash", report["failures"])


if __name__ == "__main__":
    unittest.main()
