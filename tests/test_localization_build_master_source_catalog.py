from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import sqlite3
import tempfile
import unittest

MODULE_PATH = (
    pathlib.Path(__file__).parents[1]
    / "localization"
    / "tools"
    / "build_master_source_catalog.py"
)
SPEC = importlib.util.spec_from_file_location("build_master_source_catalog", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BuildMasterSourceCatalogTests(unittest.TestCase):
    def test_builds_stable_catalog_from_reviewed_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db_path = pathlib.Path(directory) / "master.mdb"
            with sqlite3.connect(db_path) as db:
                db.execute(
                    "CREATE TABLE card_data (id INTEGER PRIMARY KEY, name TEXT, internal TEXT)"
                )
                db.executemany(
                    "INSERT INTO card_data VALUES (?, ?, ?)",
                    [
                        (100001, "島村卯月", "do-not-export"),
                        (100002, "", "also-internal"),
                    ],
                )

            field_map = {
                "schema_version": 1,
                "tables": {
                    "card_data": {
                        "primary_key": ["id"],
                        "fields": ["name"],
                    }
                },
            }
            catalog = MODULE.build_catalog(db_path, field_map)

        self.assertEqual(catalog["entry_count"], 1)
        entry = catalog["entries"][0]
        self.assertEqual(entry["id"], "Master.card_data.id:100001.name")
        self.assertEqual(entry["source"], "島村卯月")
        self.assertEqual(
            entry["source_sha256"],
            hashlib.sha256("島村卯月".encode("utf-8")).hexdigest(),
        )
        self.assertEqual(entry["context"]["primary_key"], {"id": 100001})
        self.assertNotIn("do-not-export", repr(catalog))

    def test_rejects_missing_configured_column(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db_path = pathlib.Path(directory) / "master.mdb"
            with sqlite3.connect(db_path) as db:
                db.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY, name TEXT)")

            field_map = {
                "schema_version": 1,
                "tables": {
                    "sample": {
                        "primary_key": ["id"],
                        "fields": ["missing"],
                    }
                },
            }
            with self.assertRaisesRegex(ValueError, "missing columns"):
                MODULE.build_catalog(db_path, field_map)


if __name__ == "__main__":
    unittest.main()
