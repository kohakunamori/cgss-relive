from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from server.domain import (
    CardOwnership,
    FeatureUnlock,
    PlayerProfile,
    PlayerResource,
    PlayerStateRepository,
    SCHEMA_VERSION,
    SQLiteDomainStore,
    Unit,
    UnitMember,
)


class DomainPersistenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 4, 18, 0, tzinfo=timezone.utc)
        self.store = SQLiteDomainStore.open(
            ":memory:",
            master_revision="10133800",
            resource_revision="10133800",
        )

    def tearDown(self) -> None:
        self.store.close()

    def _save_player(self, player_id: str = "player:1") -> PlayerProfile:
        profile = PlayerProfile(
            player_id=player_id,
            name="Archival Producer",
            producer_level=1,
            experience=0,
            created_at=self.now,
            last_login_at=self.now,
        )
        self.store.save_profile(profile)
        return profile

    def test_schema_and_revision_metadata_are_bound(self) -> None:
        self.assertEqual(self.store.schema_version, SCHEMA_VERSION)
        self.assertEqual(self.store.get_metadata("schema_version"), str(SCHEMA_VERSION))
        self.assertEqual(self.store.get_metadata("master_revision"), "10133800")
        self.assertEqual(self.store.get_metadata("resource_revision"), "10133800")
        with self.assertRaises(ValueError):
            self.store.migrate(master_revision="different")

    def test_store_structurally_implements_player_state_repository(self) -> None:
        self.assertIsInstance(self.store, PlayerStateRepository)

    def test_home_state_round_trip(self) -> None:
        profile = self._save_player()
        self.store.set_resource(PlayerResource(profile.player_id, "stamina", 100))

        card = CardOwnership(
            user_card_id="card:1",
            player_id=profile.player_id,
            master_card_id=100001,
            level=1,
            experience=0,
            skill_level=1,
            star_lesson_step=3,
            love=77,
            is_protected=True,
            favorite=True,
            acquired_at=self.now,
        )
        self.store.save_card(card)
        self.store.save_unit(
            Unit(
                unit_id="unit:1",
                player_id=profile.player_id,
                slot=0,
                name="Archive",
                members=(UnitMember(0, card.user_card_id),),
            )
        )
        self.store.save_feature_unlock(
            FeatureUnlock(
                player_id=profile.player_id,
                unlock_kind="story",
                master_ref_id=200001,
                unlocked_at=self.now,
                source="bootstrap-policy",
            )
        )

        snapshot = self.store.get_home_snapshot(profile.player_id)
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual(snapshot.profile, profile)
        self.assertEqual(snapshot.resources[0].amount, 100)
        self.assertEqual(snapshot.cards[0], card)
        self.assertEqual(snapshot.cards[0].star_lesson_step, 3)
        self.assertEqual(snapshot.cards[0].love, 77)
        self.assertTrue(snapshot.cards[0].is_protected)
        self.assertEqual(snapshot.units[0].members, (UnitMember(0, "card:1"),))
        self.assertEqual(snapshot.unlocks[0].master_ref_id, 200001)

    def test_v1_card_state_migrates_to_proven_v2_semantics(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "domain-v1.sqlite3"
            conn = sqlite3.connect(path)
            conn.executescript(
                """
                CREATE TABLE schema_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                INSERT INTO schema_metadata(key, value) VALUES ('schema_version', '1');
                CREATE TABLE user_cards (
                    user_card_id TEXT PRIMARY KEY,
                    player_id TEXT NOT NULL,
                    master_card_id INTEGER NOT NULL,
                    level INTEGER NOT NULL,
                    experience INTEGER NOT NULL,
                    skill_level INTEGER NOT NULL,
                    locked INTEGER NOT NULL,
                    favorite INTEGER NOT NULL,
                    acquired_at TEXT NOT NULL
                );
                PRAGMA user_version = 1;
                """
            )
            conn.execute(
                """
                INSERT INTO user_cards(
                    user_card_id, player_id, master_card_id, level, experience,
                    skill_level, locked, favorite, acquired_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("card:legacy", "player:legacy", 100001, 1, 12, 2, 1, 0, self.now.isoformat()),
            )
            conn.commit()
            conn.close()

            with SQLiteDomainStore.open(path) as migrated:
                self.assertEqual(migrated.schema_version, 2)
                cards = migrated.list_cards("player:legacy")
                self.assertEqual(len(cards), 1)
                card = cards[0]
                self.assertEqual(card.user_card_id, "card:legacy")
                self.assertEqual(card.experience, 12)
                self.assertEqual(card.skill_level, 2)
                self.assertEqual(card.star_lesson_step, 0)
                self.assertEqual(card.love, 0)
                self.assertTrue(card.is_protected)
                self.assertFalse(card.favorite)

    def test_transaction_rolls_back_multiple_mutations(self) -> None:
        profile = self._save_player()
        with self.assertRaisesRegex(RuntimeError, "abort"):
            with self.store.transaction():
                self.store.set_resource(PlayerResource(profile.player_id, "stamina", 50))
                self.store.save_feature_unlock(
                    FeatureUnlock(
                        profile.player_id,
                        "story",
                        1,
                        self.now,
                        source="test",
                    )
                )
                raise RuntimeError("abort")

        self.assertEqual(self.store.list_resources(profile.player_id), ())
        self.assertEqual(self.store.list_feature_unlocks(profile.player_id), ())

    def test_unit_cannot_reference_another_players_card(self) -> None:
        first = self._save_player("player:1")
        second = self._save_player("player:2")
        self.store.save_card(
            CardOwnership(
                user_card_id="card:2",
                player_id=second.player_id,
                master_card_id=2,
                level=1,
                experience=0,
                skill_level=0,
                star_lesson_step=0,
                love=0,
                is_protected=False,
                favorite=False,
                acquired_at=self.now,
            )
        )
        with self.assertRaisesRegex(ValueError, "another player"):
            self.store.save_unit(
                Unit(
                    "unit:1",
                    first.player_id,
                    0,
                    members=(UnitMember(0, "card:2"),),
                )
            )

    def test_unknown_player_has_no_home_snapshot(self) -> None:
        self.assertIsNone(self.store.get_home_snapshot("missing"))


if __name__ == "__main__":
    unittest.main()
