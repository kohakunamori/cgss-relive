from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import sqlite3
import sys
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "archive-resources.py"
SPEC = importlib.util.spec_from_file_location("archive_resources", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ArchiveResourceTests(unittest.TestCase):
    def _manifest(self, root: pathlib.Path, known_hash: str) -> pathlib.Path:
        path = root / "manifest.db"
        conn = sqlite3.connect(path)
        try:
            conn.execute("CREATE TABLE manifests (name TEXT, hash TEXT)")
            conn.executemany(
                "INSERT INTO manifests(name, hash) VALUES (?, ?)",
                [
                    ("card_1.unity3d", known_hash),
                    ("same-content.unity3d", known_hash),
                    ("future.xyz", "1" * 32),
                ],
            )
            conn.commit()
        finally:
            conn.close()
        return path

    def test_plan_deduplicates_hashes_and_reports_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            digest = hashlib.md5(b"hello").hexdigest()
            plans, skipped = MODULE.load_plan(self._manifest(root, digest))
            self.assertEqual(len(plans), 1)
            self.assertEqual(plans[0].category, "AssetBundles")
            self.assertEqual(plans[0].digest, digest)
            self.assertEqual([item.status for item in skipped], ["unknown_category"])

    def test_verify_content_addressed_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            payload = b"preserved object"
            digest = hashlib.md5(payload).hexdigest()
            manifest = self._manifest(root, digest)
            plans, _ = MODULE.load_plan(manifest)
            archive = root / "archive"
            path = MODULE.object_path(archive, digest)
            path.parent.mkdir(parents=True)
            path.write_bytes(payload)
            result = MODULE.verify_one(plans[0], archive)
            self.assertEqual(result.status, "verified")
            self.assertEqual(result.bytes, len(payload))

            path.write_bytes(b"corrupt")
            result = MODULE.verify_one(plans[0], archive)
            self.assertEqual(result.status, "hash_mismatch")

    def test_current_category_routes(self) -> None:
        self.assertEqual(MODULE.category_for_name("x.acb"), "Sound")
        self.assertEqual(MODULE.category_for_name("x.usm"), "Movie")
        self.assertEqual(MODULE.category_for_name("x.bdb"), "Generic")
        self.assertEqual(MODULE.category_for_name("master.mdb"), "Generic")
        self.assertEqual(
            MODULE.resource_path("Sound", "ab" * 16),
            "/dl/resources/Sound/ab/" + "ab" * 16,
        )


if __name__ == "__main__":
    unittest.main()
