from __future__ import annotations

from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from server.adapters.identity_store import (
    SQLiteCompatibilityIdentityStore,
    UnitCompatibilitySlot,
)


class CompatibilityIdentityStoreTests(unittest.TestCase):
    def test_allocations_are_stable_across_reopen_and_scoped_per_player(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "compat.sqlite3"
            with SQLiteCompatibilityIdentityStore.open(path) as store:
                self.assertEqual(store.ensure_card_serial("p1", "card:a"), 1)
                self.assertEqual(store.ensure_card_serial("p1", "card:b"), 2)
                self.assertEqual(store.ensure_unit_id("p1", "unit:a"), 1)
                self.assertEqual(store.ensure_unit_id("p1", "unit:b"), 2)
                self.assertEqual(store.ensure_card_serial("p2", "card:x"), 1)
                self.assertEqual(store.ensure_unit_id("p2", "unit:x"), 1)

            with SQLiteCompatibilityIdentityStore.open(path) as store:
                self.assertEqual(store.ensure_card_serial("p1", "card:a"), 1)
                self.assertEqual(store.ensure_card_serial("p1", "card:b"), 2)
                self.assertEqual(store.get_card_serial("p2", "card:x"), 1)
                self.assertEqual(store.get_user_card_id("p1", 1), "card:a")
                self.assertEqual(store.get_user_card_id("p1", 2), "card:b")
                self.assertEqual(store.get_user_card_id("p2", 1), "card:x")
                self.assertIsNone(store.get_user_card_id("p1", 999))
                self.assertEqual(store.get_unit_id("p1", "unit:a"), 1)
                self.assertEqual(store.get_unit_id("p1", "unit:b"), 2)
                self.assertEqual(store.get_domain_unit_id("p1", 1), "unit:a")
                self.assertEqual(store.get_domain_unit_id("p1", 2), "unit:b")
                self.assertEqual(store.get_domain_unit_id("p2", 1), "unit:x")
                self.assertIsNone(store.get_domain_unit_id("p1", 999))
                self.assertEqual(store.ensure_card_serial("p1", "card:c"), 3)

    def test_unit_compatibility_state_round_trips_across_reopen(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "compat.sqlite3"
            slots = (
                UnitCompatibilitySlot(0, 101, 11, 1001),
                UnitCompatibilitySlot(1, 0, 0, 0),
                UnitCompatibilitySlot(2, 202, 22, 2002),
            )
            with SQLiteCompatibilityIdentityStore.open(path) as store:
                store.ensure_unit_id("p1", "unit:a")
                store.replace_unit_compatibility_slots("p1", "unit:a", slots)
                store.set_main_unit("p1", "unit:a")

            with SQLiteCompatibilityIdentityStore.open(path) as store:
                self.assertEqual(store.get_unit_compatibility_slots("p1", "unit:a"), slots)
                self.assertEqual(store.get_main_unit("p1"), "unit:a")
                store.set_main_unit("p1", None)
                self.assertIsNone(store.get_main_unit("p1"))

    def test_schema_v1_migrates_without_losing_identity_rows(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "compat.sqlite3"
            conn = sqlite3.connect(path)
            conn.executescript(
                """
                CREATE TABLE card_identity_bindings (
                    player_id TEXT NOT NULL,
                    user_card_id TEXT NOT NULL,
                    serial_id INTEGER NOT NULL CHECK (serial_id > 0),
                    PRIMARY KEY (player_id, user_card_id),
                    UNIQUE (player_id, serial_id)
                );
                CREATE TABLE unit_identity_bindings (
                    player_id TEXT NOT NULL,
                    domain_unit_id TEXT NOT NULL,
                    client_unit_id INTEGER NOT NULL CHECK (client_unit_id > 0),
                    PRIMARY KEY (player_id, domain_unit_id),
                    UNIQUE (player_id, client_unit_id)
                );
                INSERT INTO card_identity_bindings VALUES ('p1', 'card:a', 7);
                INSERT INTO unit_identity_bindings VALUES ('p1', 'unit:a', 3);
                PRAGMA user_version = 1;
                """
            )
            conn.commit()
            conn.close()

            with SQLiteCompatibilityIdentityStore.open(path) as store:
                self.assertEqual(store.get_card_serial("p1", "card:a"), 7)
                self.assertEqual(store.get_unit_id("p1", "unit:a"), 3)
                store.replace_unit_compatibility_slots(
                    "p1", "unit:a", (UnitCompatibilitySlot(0, 1, 2, 3),)
                )
                self.assertEqual(store.get_main_unit("p1"), None)

            conn = sqlite3.connect(path)
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)
            conn.close()

    def test_rejects_invalid_identities_and_duplicate_slots(self) -> None:
        with TemporaryDirectory() as tmp:
            with SQLiteCompatibilityIdentityStore.open(Path(tmp) / "compat.sqlite3") as store:
                with self.assertRaises(ValueError):
                    store.ensure_card_serial("", "card:a")
                with self.assertRaises(ValueError):
                    store.ensure_unit_id("p1", "")
                with self.assertRaises(ValueError):
                    store.get_user_card_id("p1", 0)
                with self.assertRaises(ValueError):
                    store.get_domain_unit_id("p1", 0)
                with self.assertRaises(ValueError):
                    store.replace_unit_compatibility_slots(
                        "p1",
                        "unit:a",
                        (
                            UnitCompatibilitySlot(0, 1, 2, 3),
                            UnitCompatibilitySlot(0, 4, 5, 6),
                        ),
                    )


if __name__ == "__main__":
    unittest.main()
