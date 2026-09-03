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
            conn.execute("CREATE TABLE manifests (name TEXT, hash TEXT)")
            rows = [
                ("card_1.unity3d", "0" * 32),
                ("v/card_1.acb", "1" * 32),
                ("v/card_1.awb", "2" * 32),
                ("score.bytes", "3" * 32),
                ("movie001.usm", "4" * 32),
                ("musicscores_m001.bdb", "5" * 32),
                ("master.mdb", "6" * 32),
                ("future.unknown", "7" * 32),
            ]
            conn.executemany("INSERT INTO manifests(name, hash) VALUES (?, ?)", rows)
            conn.commit()
        finally:
            conn.close()
        return path

    def test_category_and_path_mapping(self) -> None:
        self.assertEqual(MODULE.category_for_name("x.unity3d"), "AssetBundles")
        self.assertEqual(MODULE.category_for_name("x.acb"), "Sound")
        self.assertEqual(MODULE.category_for_name("x.awb"), "Sound")
        self.assertEqual(MODULE.category_for_name("x.bytes"), "Sound")
        self.assertEqual(MODULE.category_for_name("x.usm"), "Movie")
        self.assertEqual(MODULE.category_for_name("x.bdb"), "Generic")
        self.assertEqual(MODULE.category_for_name("master.mdb"), "Generic")
        self.assertIsNone(MODULE.category_for_name("x.future"))
        self.assertEqual(
            MODULE.resource_path("x.awb", "AB" * 16),
            "/dl/resources/Sound/ab/" + "ab" * 16,
        )

    def test_inventory_reports_unknown_without_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._make_db(pathlib.Path(directory))
            report = MODULE.inspect_manifest(path)
            self.assertEqual(report["quick_check"], ["ok"])
            self.assertEqual(report["rows"], 8)
            self.assertEqual(report["category_counts"]["AssetBundles"], 1)
            self.assertEqual(report["category_counts"]["Sound"], 3)
            self.assertEqual(report["category_counts"]["Generic"], 2)
            self.assertEqual(report["category_counts"]["<unknown>"], 1)
            self.assertEqual(report["master_mdb"]["hash"], "6" * 32)
            self.assertEqual(report["unknown_category_examples"][0]["name"], "future.unknown")
            self.assertEqual(
                report["name_shape"],
                {
                    "names_with_slash": 2,
                    "unique_basenames": 8,
                    "basename_collision_groups": 0,
                    "basename_hash_conflict_groups": 0,
                },
            )

    def test_name_shape_detects_basename_collisions_without_exporting_names(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.db"
            conn = sqlite3.connect(path)
            try:
                conn.execute("CREATE TABLE manifests (name TEXT, hash TEXT)")
                conn.executemany(
                    "INSERT INTO manifests(name, hash) VALUES (?, ?)",
                    [
                        ("a/shared.unity3d", "1" * 32),
                        ("b/shared.unity3d", "2" * 32),
                        ("c/same.acb", "3" * 32),
                        ("d/same.acb", "3" * 32),
                        ("plain.awb", "4" * 32),
                    ],
                )
                conn.commit()
            finally:
                conn.close()

            report = MODULE.inspect_manifest(path, unknown_examples=0)
            self.assertEqual(report["name_shape"]["names_with_slash"], 4)
            self.assertEqual(report["name_shape"]["unique_basenames"], 3)
            self.assertEqual(report["name_shape"]["basename_collision_groups"], 2)
            self.assertEqual(report["name_shape"]["basename_hash_conflict_groups"], 1)
            self.assertEqual(report["unknown_category_examples"], [])

    def test_catalog_is_normalized_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            db = self._make_db(root)
            catalog = root / "catalog.jsonl"
            self.assertEqual(MODULE.write_catalog(db, catalog), 8)
            rows = [json.loads(line) for line in catalog.read_text(encoding="utf-8").splitlines()]
            by_name = {row["name"]: row for row in rows}
            self.assertEqual(by_name["movie001.usm"]["category"], "Movie")
            self.assertEqual(by_name["score.bytes"]["category"], "Sound")
            self.assertIsNone(by_name["future.unknown"]["resource_path"])


if __name__ == "__main__":
    unittest.main()
