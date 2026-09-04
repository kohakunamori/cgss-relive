from __future__ import annotations

import importlib.util
import json
import pathlib
import sqlite3
import tempfile
import unittest

MODULE_PATH = (
    pathlib.Path(__file__).parents[1]
    / "localization"
    / "tools"
    / "inventory_master_text.py"
)
SPEC = importlib.util.spec_from_file_location("inventory_master_text", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InventoryMasterTextTests(unittest.TestCase):
    def test_inventory_classifies_text_without_leaking_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "master.mdb"
            with sqlite3.connect(path) as db:
                db.execute(
                    "CREATE TABLE card_data ("
                    "id INTEGER PRIMARY KEY, name TEXT, resource_path TEXT, note TEXT)"
                )
                db.execute(
                    "INSERT INTO card_data VALUES (?, ?, ?, ?)",
                    (1, "島村卯月", "AssetBundles/Android/card_1", "ascii-only"),
                )

            report = MODULE.inspect_master_text(path)

        self.assertEqual(report["quick_check"], ["ok"])
        self.assertEqual(report["summary"]["table_count"], 1)
        self.assertEqual(report["summary"]["text_column_count"], 3)

        columns = {
            column["name"]: column
            for column in report["tables"][0]["text_columns"]
        }
        self.assertEqual(
            columns["name"]["classification"], "user-visible-candidate"
        )
        self.assertEqual(columns["name"]["japanese_like_count"], 1)
        self.assertEqual(
            columns["resource_path"]["classification"], "internal-candidate"
        )
        self.assertEqual(columns["note"]["classification"], "review")

        serialized = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("島村卯月", serialized)
        self.assertNotIn("AssetBundles/Android/card_1", serialized)
        self.assertNotIn("ascii-only", serialized)

    def test_identifier_quoting_handles_unusual_names(self) -> None:
        self.assertEqual(MODULE.quote_identifier('a"b'), '"a""b"')


if __name__ == "__main__":
    unittest.main()
