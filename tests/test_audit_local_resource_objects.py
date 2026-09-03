from __future__ import annotations

import hashlib
import importlib.util
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit-local-resource-objects.py"
SPEC = importlib.util.spec_from_file_location("audit_local_resource_objects", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class LocalResourceObjectAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "cache"
        self.db = Path(self.temp.name) / "manifest.db"
        self.payloads = (b"first-object", b"second-object")
        self.digests = tuple(hashlib.md5(payload).hexdigest() for payload in self.payloads)
        with sqlite3.connect(self.db) as connection:
            connection.execute("CREATE TABLE manifests(name TEXT, hash TEXT)")
            connection.executemany(
                "INSERT INTO manifests(name, hash) VALUES (?, ?)",
                [
                    ("first", self.digests[0]),
                    ("first-alias", self.digests[0]),
                    ("second", self.digests[1]),
                ],
            )
        for digest, payload in zip(self.digests, self.payloads):
            path = self.root / "objects" / digest[:2] / digest
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_complete_audit_hashes_every_unique_object_once(self) -> None:
        report = module.audit(self.root, self.db, expected_unique_hashes=2)
        self.assertTrue(report["complete"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(
            report["objects"],
            {
                "manifest_unique": 2,
                "checked": 2,
                "missing": 0,
                "unreadable": 0,
                "mismatched": 0,
                "invalid_manifest_hashes": 0,
            },
        )
        serialized = repr(report)
        for digest in self.digests:
            self.assertNotIn(digest, serialized)

    def test_hash_mismatch_and_missing_are_aggregate_only(self) -> None:
        first = self.root / "objects" / self.digests[0][:2] / self.digests[0]
        second = self.root / "objects" / self.digests[1][:2] / self.digests[1]
        first.write_bytes(b"corrupt")
        second.unlink()

        report = module.audit(self.root, self.db, expected_unique_hashes=2)
        self.assertFalse(report["complete"])
        self.assertIn("object_hash_mismatch", report["failures"])
        self.assertIn("objects_missing", report["failures"])
        self.assertEqual(report["objects"]["checked"], 1)
        self.assertEqual(report["objects"]["mismatched"], 1)
        self.assertEqual(report["objects"]["missing"], 1)
        serialized = repr(report)
        for digest in self.digests:
            self.assertNotIn(digest, serialized)

    def test_expected_unique_count_is_enforced(self) -> None:
        report = module.audit(self.root, self.db, expected_unique_hashes=3)
        self.assertFalse(report["complete"])
        self.assertIn("unique_hash_count_mismatch", report["failures"])


if __name__ == "__main__":
    unittest.main()
