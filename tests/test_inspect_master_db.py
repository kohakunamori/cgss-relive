from __future__ import annotations

import importlib.util
import pathlib
import sqlite3
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).parents[1] / "scripts" / "inspect-master-db.py"
SPEC = importlib.util.spec_from_file_location("inspect_master_db", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class InspectMasterDBTests(unittest.TestCase):
    def test_reports_integrity_and_requested_card_presence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "master.mdb"
            with sqlite3.connect(path) as db:
                db.execute(
                    "CREATE TABLE card_data (id INTEGER PRIMARY KEY, name TEXT, chara_id INTEGER, rarity INTEGER, attribute INTEGER)"
                )
                db.execute(
                    "INSERT INTO card_data VALUES (?, ?, ?, ?, ?)",
                    (100001, "Synthetic Idol", 101, 3, 1),
                )
            report = MODULE.inspect_master(path, card_ids=[100001, 999999])

        self.assertEqual(report["quick_check"], ["ok"])
        self.assertTrue(report["has_card_data"])
        self.assertEqual(report["card_data"]["row_count"], 1)
        self.assertEqual(report["requested_cards"][0]["id"], 100001)
        self.assertTrue(report["requested_cards"][0]["present"])
        self.assertEqual(report["requested_cards"][0]["name"], "Synthetic Idol")
        self.assertEqual(report["requested_cards"][1], {"id": 999999, "present": False})


if __name__ == "__main__":
    unittest.main()
