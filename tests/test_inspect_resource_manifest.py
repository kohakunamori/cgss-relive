from __future__ import annotations

import importlib.util
import json
import pathlib
import sqlite3
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "inspect-resource-manifest.py"
SPEC = importlib.util.spec_from_file_location("inspect_resource_manifest", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class ResourceManifestTests(unittest.TestCase):
    def _make_db(self, root: pathlib.Path) -> pathlib.Path:
        path = root / "manifest_10133800.db"
        conn = sqlite3.connect(path)
        try:
            conn.execute("CREATE TABLE manifests (name TEXT, hash TEXT, category TEXT)")
            rows = [
                ("card_1.unity3d", "0" * 32, "asset"),
                ("v/card_1.acb", "1" * 32, "sound"),
                ("movie001.usm", "2" * 32, "movie"),
                ("musicscores_m001.bdb", "3" * 32, "generic"),
                ("master.mdb", "4" * 32, "generic"),
                ("future.unknown", "5" * 32, "future"),
            ]
            conn.executemany("INSERT INTO manifests(name, hash, category) VALUES (?, ?, ?)", rows)
            conn.commit()
        finally:
            conn.close()
        return path

    def test_category_and_path_mapping(self) -> None:
        self.assertEqual(MODULE.category_for_name("x.unity3d"), "AssetBundles")
        self.assertEqual(MODULE.category_for_name("x.acb"), "Sound")
        self.assertEqual(MODULE.category_for_name("x.usm"), "Movie")
        self.assertEqual(MODULE.category_for_name("x.bdb"), "Generic")
        self.assertEqual(MODULE.category_for_name("master.mdb"), "Generic")
        self.assertIsNone(MODULE.category_for_name("x.future"))
        self.assertEqual(
            MODULE.resource_path("x.acb", "AB" * 16),
            "/dl/resources/Sound/ab/" + "ab" * 16,
        )

    def test_inventory_reports_unknown_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._make_db(pathlib.Path(directory))
            report = MODULE.inspect_manifest(path)
            self.assertEqual(report["quick_check"], ["ok"])
            self.assertEqual(report["rows"], 6)
            self.assertEqual(report["category_counts"]["AssetBundles"], 1)
            self.assertEqual(report["category_counts"]["Generic"], 2)
            self.assertEqual(report["category_counts"]["<unknown>"], 1)
            self.assertTrue(report["has_declared_category"])
            self.assertEqual(report["declared_category_counts"]["generic"], 2)
            self.assertEqual(
                report["suffix_declared_category_counts"][".acb"],
                {"sound": 1},
            )
            self.assertEqual(report["master_mdb"]["hash"], "4" * 32)
            self.assertEqual(report["unknown_category_examples"][0]["name"], "future.unknown")
            self.assertEqual(report["unknown_category_examples"][0]["declared_category"], "future")

    def test_catalog_is_normalized_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            db = self._make_db(root)
            catalog = root / "catalog.jsonl"
            self.assertEqual(MODULE.write_catalog(db, catalog), 6)
            rows = [json.loads(line) for line in catalog.read_text(encoding="utf-8").splitlines()]
            by_name = {row["name"]: row for row in rows}
            self.assertEqual(by_name["movie001.usm"]["category"], "Movie")
            self.assertEqual(by_name["movie001.usm"]["declared_category"], "movie")
            self.assertIsNone(by_name["future.unknown"]["resource_path"])

    def test_legacy_manifest_without_category_still_works(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "legacy.db"
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE manifests (name TEXT, hash TEXT)")
                db.execute("INSERT INTO manifests VALUES (?, ?)", ("master.mdb", "a" * 32))
            report = MODULE.inspect_manifest(path)
            self.assertFalse(report["has_declared_category"])
            self.assertEqual(report["declared_category_counts"], {})


if __name__ == "__main__":
    unittest.main()
