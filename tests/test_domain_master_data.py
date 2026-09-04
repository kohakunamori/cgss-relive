from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest

from server.domain import (
    MasterDataRepository,
    MasterTableSpec,
    SQLiteMasterDataRepository,
)


class DomainMasterDataTests(unittest.TestCase):
    def test_configured_master_projection_is_read_only_domain_surface(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "master.mdb"
            connection = sqlite3.connect(path)
            connection.execute(
                "CREATE TABLE card_data(id INTEGER PRIMARY KEY, name TEXT NOT NULL, rarity INTEGER)"
            )
            connection.execute(
                "INSERT INTO card_data(id, name, rarity) VALUES (1001, 'archive card', 7)"
            )
            connection.commit()
            connection.close()

            repo = SQLiteMasterDataRepository.open(
                path,
                master_revision="10133800",
                specs={
                    "card": MasterTableSpec(
                        table="card_data",
                        id_column="id",
                        columns=("id", "name"),
                    )
                },
            )
            try:
                self.assertIsInstance(repo, MasterDataRepository)
                self.assertEqual(repo.master_revision, "10133800")
                self.assertEqual(repo.kinds, ("card",))
                self.assertTrue(repo.contains("card", 1001))
                self.assertFalse(repo.contains("card", 9999))
                self.assertFalse(repo.contains("unknown", 1001))

                row = repo.get("card", 1001)
                self.assertIsNotNone(row)
                assert row is not None
                self.assertEqual(dict(row), {"id": 1001, "name": "archive card"})
                with self.assertRaises(TypeError):
                    row["name"] = "mutated"  # type: ignore[index]
                self.assertIsNone(repo.get("unknown", 1001))
            finally:
                repo.close()

    def test_master_table_spec_rejects_untrusted_identifiers(self) -> None:
        with self.assertRaises(ValueError):
            MasterTableSpec("card_data; DROP TABLE card_data", "id")
        with self.assertRaises(ValueError):
            MasterTableSpec("card_data", "id", columns=("bad column",))
        with self.assertRaises(ValueError):
            MasterTableSpec("card_data", "id", columns=("id", "id"))


if __name__ == "__main__":
    unittest.main()
