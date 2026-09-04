from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping
import unittest

from server.domain import (
    BootstrapPolicy,
    EvidenceKind,
    FixedClock,
    InitialUnlock,
    PreservationProfileService,
    SQLiteDomainStore,
    SequentialIdGenerator,
    StarterCardGrant,
)


class FakeMasterData:
    master_revision = "10133800"

    def __init__(self, rows: set[tuple[str, int]]) -> None:
        self.rows = rows

    def contains(self, kind: str, master_id: int) -> bool:
        return (kind, master_id) in self.rows

    def get(self, kind: str, master_id: int) -> Mapping[str, Any] | None:
        if not self.contains(kind, master_id):
            return None
        return {"id": master_id, "kind": kind}


class DomainServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 4, 19, 0, tzinfo=timezone.utc)
        self.store = SQLiteDomainStore.open(
            ":memory:",
            master_revision="10133800",
            resource_revision="10133800",
        )
        self.ids = SequentialIdGenerator()
        self.master = FakeMasterData({("card", 1001), ("story", 2001)})
        self.service = PreservationProfileService(
            self.store,
            clock=FixedClock(self.now),
            ids=self.ids,
            master_data=self.master,
        )

    def tearDown(self) -> None:
        self.store.close()

    def test_bootstrap_creates_deterministic_archival_profile(self) -> None:
        result = self.service.bootstrap_profile(
            BootstrapPolicy(
                name="Archive Producer",
                initial_resources={"stamina": 100, "zero-counter": 0},
                starter_cards=(StarterCardGrant(1001, favorite=True),),
                initial_unlocks=(InitialUnlock("story", 2001),),
            ),
            player_id="player:archive",
        )

        self.assertTrue(result.created)
        self.assertEqual(result.snapshot.profile.player_id, "player:archive")
        self.assertEqual(result.snapshot.profile.created_at, self.now)
        self.assertEqual(result.snapshot.resources[0].resource_kind, "stamina")
        self.assertEqual(len(result.snapshot.resources), 2)
        self.assertEqual(result.snapshot.cards[0].user_card_id, "card:1")
        self.assertEqual(result.snapshot.cards[0].master_card_id, 1001)
        self.assertTrue(result.snapshot.cards[0].favorite)
        self.assertEqual(result.snapshot.unlocks[0].master_ref_id, 2001)

        self.assertTrue(result.changes.profile_changed)
        self.assertEqual(result.changes.resources[0].delta, 100)
        self.assertEqual(len(result.changes.entities), 2)
        self.assertTrue(
            all(change.evidence is not None for change in result.changes.entities)
        )
        self.assertTrue(
            all(
                change.evidence is not None
                and change.evidence.kind is EvidenceKind.POLICY
                for change in result.changes.entities
            )
        )
        self.assertEqual(
            result.changes.metadata["bootstrap_policy"],
            "archival-bootstrap-v0",
        )

    def test_bootstrap_is_idempotent_for_explicit_player_id(self) -> None:
        first = self.service.bootstrap_profile(
            BootstrapPolicy(name="First", starter_cards=(StarterCardGrant(1001),)),
            player_id="player:archive",
        )
        second = self.service.bootstrap_profile(
            BootstrapPolicy(name="Should not overwrite", initial_resources={"stamina": 999}),
            player_id="player:archive",
        )

        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertTrue(second.changes.is_empty)
        self.assertEqual(second.snapshot.profile.name, "First")
        self.assertEqual(second.snapshot.cards[0].user_card_id, "card:1")
        self.assertEqual(second.snapshot.resources, ())

    def test_unknown_master_reference_rolls_back_entire_bootstrap(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown master reference"):
            self.service.bootstrap_profile(
                BootstrapPolicy(
                    name="Rollback",
                    starter_cards=(StarterCardGrant(1001),),
                    initial_unlocks=(InitialUnlock("story", 9999),),
                ),
                player_id="player:rollback",
            )

        self.assertIsNone(self.store.get_home_snapshot("player:rollback"))
        self.assertEqual(self.store.list_cards("player:rollback"), ())

    def test_get_home_snapshot_rejects_unknown_profile(self) -> None:
        with self.assertRaises(KeyError):
            self.service.get_home_snapshot("missing")


if __name__ == "__main__":
    unittest.main()
