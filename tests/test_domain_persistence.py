from __future__ import annotations

from datetime import datetime, timezone
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
            skill_level=0,
            locked=False,
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
        self.assertEqual(snapshot.units[0].members, (UnitMember(0, "card:1"),))
        self.assertEqual(snapshot.unlocks[0].master_ref_id, 200001)

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
                "card:2",
                second.player_id,
                2,
                1,
                0,
                0,
                False,
                False,
                self.now,
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
