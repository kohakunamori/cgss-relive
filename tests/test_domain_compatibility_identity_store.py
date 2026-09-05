from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from server.adapters.identity_store import SQLiteCompatibilityIdentityStore


class CompatibilityIdentityStoreTests(unittest.TestCase):
    def test_allocations_are_stable_across_reopen_and_scoped_per_player(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "compat.sqlite3"
            with SQLiteCompatibilityIdentityStore.open(path) as store:
                self.assertEqual(store.ensure_card_serial("p1", "card:a"), 1)
                self.assertEqual(store.ensure_card_serial("p1", "card:b"), 2)
                self.assertEqual(store.ensure_unit_id("p1", "unit:a"), 1)
                self.assertEqual(store.ensure_card_serial("p2", "card:x"), 1)

            with SQLiteCompatibilityIdentityStore.open(path) as store:
                self.assertEqual(store.ensure_card_serial("p1", "card:a"), 1)
                self.assertEqual(store.ensure_card_serial("p1", "card:b"), 2)
                self.assertEqual(store.get_card_serial("p2", "card:x"), 1)
                self.assertEqual(store.get_user_card_id("p1", 1), "card:a")
                self.assertEqual(store.get_user_card_id("p1", 2), "card:b")
                self.assertEqual(store.get_user_card_id("p2", 1), "card:x")
                self.assertIsNone(store.get_user_card_id("p1", 999))
                self.assertEqual(store.get_unit_id("p1", "unit:a"), 1)
                self.assertEqual(store.ensure_card_serial("p1", "card:c"), 3)

    def test_rejects_invalid_identities(self) -> None:
        with TemporaryDirectory() as tmp:
            with SQLiteCompatibilityIdentityStore.open(Path(tmp) / "compat.sqlite3") as store:
                with self.assertRaises(ValueError):
                    store.ensure_card_serial("", "card:a")
                with self.assertRaises(ValueError):
                    store.ensure_unit_id("p1", "")
                with self.assertRaises(ValueError):
                    store.get_user_card_id("p1", 0)


if __name__ == "__main__":
    unittest.main()
