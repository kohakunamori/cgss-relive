from __future__ import annotations

import hashlib
import importlib.util
import sqlite3
import struct
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


def literal_only_block(payload: bytes) -> bytes:
    length = len(payload)
    if length < 15:
        return bytes([length << 4]) + payload
    extra = length - 15
    extensions = bytearray()
    while extra >= 255:
        extensions.append(255)
        extra -= 255
    extensions.append(extra)
    return b"\xF0" + bytes(extensions) + payload


def wrap_lz4(payload: bytes) -> bytes:
    return (
        b"CGSS"
        + struct.pack("<I", len(payload))
        + b"\x00" * 8
        + literal_only_block(payload)
    )


class LocalResourcePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "cache"
        self.root.mkdir(parents=True)
        self.db = Path(self.temp.name) / "manifest.db"
        self.master_payload = b"synthetic-master-object"
        self.master_digest = hashlib.md5(self.master_payload).hexdigest()
        self.other_digest = "fedcba9876543210fedcba9876543210"
        self.hashes = (self.master_digest, self.other_digest)
        with sqlite3.connect(self.db) as connection:
            connection.execute("CREATE TABLE manifests (name TEXT, hash TEXT)")
            connection.executemany(
                "INSERT INTO manifests(name, hash) VALUES (?, ?)",
                [("master.mdb", self.master_digest), ("b", self.other_digest)],
            )
            connection.commit()

        wire = self.root / "manifests"
        wire.mkdir()
        compressed = wrap_lz4(self.db.read_bytes())
        compressed_md5 = hashlib.md5(compressed).hexdigest()
        (wire / "all_dbmanifest").write_text(
            f"Android_AHigh_SHigh,{compressed_md5},{len(compressed)}\n",
            encoding="utf-8",
        )
        (wire / "Android_AHigh_SHigh").write_bytes(compressed)

        master_path = self.root / "objects" / self.master_digest[:2] / self.master_digest
        master_path.parent.mkdir(parents=True, exist_ok=True)
        master_path.write_bytes(self.master_payload)

        other_path = self.root / "objects" / self.other_digest[:2] / self.other_digest
        other_path.parent.mkdir(parents=True, exist_ok=True)
        other_path.write_bytes(b"object")

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
        self.assertEqual(report["schema"], 3)
        self.assertEqual(report["manifest"]["quick_check"], ["ok"])
        self.assertEqual(report["manifest"]["rows"], 2)
        self.assertEqual(report["manifest"]["unique_hashes"], 2)
        self.assertEqual(report["wire_manifests_present"], 2)
        self.assertEqual(
            report["wire_chain"],
            {
                "index_parsed": True,
                "android_wire_md5_matches_index": True,
                "android_wire_decodes": True,
                "decoded_is_sqlite": True,
                "decoded_matches_manifest_db": True,
            },
        )
        self.assertEqual(report["objects"]["present"], 2)
        self.assertEqual(report["objects"]["missing"], 0)
        self.assertEqual(
            report["master_object"],
            {
                "manifest_entry_present": True,
                "object_present": True,
                "md5_matches_manifest": True,
            },
        )

    def test_missing_wire_and_object_are_sanitized_failures(self) -> None:
        (self.root / "manifests" / module.WIRE_MANIFESTS[0]).unlink()
        missing_digest = self.other_digest
        (self.root / "objects" / missing_digest[:2] / missing_digest).unlink()

        report = module.run_preflight(self.root, self.db, version=module.FINAL_RESOURCE_VERSION)
        self.assertFalse(report["ready"])
        self.assertIn("wire_manifest_missing", report["failures"])
        self.assertIn("resource_objects_missing", report["failures"])
        self.assertEqual(report["objects"]["missing"], 1)
        serialized = repr(report)
        self.assertNotIn(missing_digest, serialized)
        self.assertNotIn("all_dbmanifest", serialized)

    def test_wire_android_md5_mismatch_is_rejected(self) -> None:
        path = self.root / "manifests" / "Android_AHigh_SHigh"
        path.write_bytes(path.read_bytes() + b"corrupt")
        report = module.run_preflight(self.root, self.db, version=module.FINAL_RESOURCE_VERSION)
        self.assertFalse(report["ready"])
        self.assertIn("wire_android_manifest_md5_mismatch", report["failures"])
        self.assertTrue(report["wire_chain"]["index_parsed"])
        self.assertFalse(report["wire_chain"]["android_wire_md5_matches_index"])

    def test_wire_decoded_database_mismatch_is_rejected(self) -> None:
        other_db = Path(self.temp.name) / "other.db"
        with sqlite3.connect(other_db) as connection:
            connection.execute("CREATE TABLE manifests (name TEXT, hash TEXT)")
            connection.execute(
                "INSERT INTO manifests(name, hash) VALUES (?, ?)",
                ("different", self.master_digest),
            )
            connection.commit()
        compressed = wrap_lz4(other_db.read_bytes())
        wire = self.root / "manifests"
        (wire / "Android_AHigh_SHigh").write_bytes(compressed)
        (wire / "all_dbmanifest").write_text(
            f"Android_AHigh_SHigh,{hashlib.md5(compressed).hexdigest()},{len(compressed)}\n",
            encoding="utf-8",
        )

        report = module.run_preflight(self.root, self.db, version=module.FINAL_RESOURCE_VERSION)
        self.assertFalse(report["ready"])
        self.assertIn("wire_manifest_db_mismatch", report["failures"])
        self.assertTrue(report["wire_chain"]["decoded_is_sqlite"])
        self.assertFalse(report["wire_chain"]["decoded_matches_manifest_db"])

    def test_master_object_hash_mismatch_is_rejected(self) -> None:
        path = self.root / "objects" / self.master_digest[:2] / self.master_digest
        path.write_bytes(b"same-path-wrong-content")
        report = module.run_preflight(self.root, self.db, version=module.FINAL_RESOURCE_VERSION)
        self.assertFalse(report["ready"])
        self.assertIn("master_object_md5_mismatch", report["failures"])
        self.assertTrue(report["master_object"]["manifest_entry_present"])
        self.assertTrue(report["master_object"]["object_present"])
        self.assertFalse(report["master_object"]["md5_matches_manifest"])
        self.assertNotIn(self.master_digest, repr(report))

    def test_wrong_version_and_invalid_hash_are_rejected(self) -> None:
        with sqlite3.connect(self.db) as connection:
            connection.execute("UPDATE manifests SET hash='not-a-hash' WHERE name='b'")
        report = module.run_preflight(self.root, self.db, version="10133000")
        self.assertFalse(report["ready"])
        self.assertIn("resource_version_mismatch", report["failures"])
        self.assertIn("manifest_contains_invalid_hash", report["failures"])


if __name__ == "__main__":
    unittest.main()
