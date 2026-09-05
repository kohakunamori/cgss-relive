from __future__ import annotations

from datetime import datetime, timezone
import unittest

from server.domain import (
    CardOwnership,
    EvidenceKind,
    EvidenceStatus,
    PlayerProfile,
    PreservationUnitService,
    SQLiteDomainStore,
    Unit,
    UnitMember,
    UnitMembershipUpdate,
)


class UnitServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 5, 5, 30, tzinfo=timezone.utc)
        self.store = SQLiteDomainStore.open(":memory:")
        self.store.save_profile(
            PlayerProfile("player:1", "Producer", 1, 0, self.now, self.now)
        )
        for index, master_id in enumerate((100001, 100002, 100003), start=1):
            self.store.save_card(
                CardOwnership(
                    user_card_id=f"card:{index}",
                    player_id="player:1",
                    master_card_id=master_id,
                    level=1,
                    experience=0,
                    skill_level=1,
                    star_lesson_step=0,
                    love=0,
                    is_protected=False,
                    favorite=False,
                    acquired_at=self.now,
                )
            )
        self.store.save_unit(
            Unit(
                unit_id="unit:1",
                player_id="player:1",
                slot=0,
                name="Primary",
                members=(UnitMember(0, "card:1"), UnitMember(1, "card:2")),
            )
        )
        self.store.save_unit(
            Unit(
                unit_id="unit:2",
                player_id="player:1",
                slot=1,
                name="Secondary",
                members=(UnitMember(0, "card:2"),),
            )
        )
        self.service = PreservationUnitService(self.store)

    def tearDown(self) -> None:
        self.store.close()

    def test_replaces_multiple_units_atomically_and_preserves_slot_and_name(self) -> None:
        changes = self.service.replace_members(
            "player:1",
            (
                UnitMembershipUpdate(
                    "unit:1",
                    (UnitMember(0, "card:3"), UnitMember(2, "card:1")),
                ),
                UnitMembershipUpdate("unit:2", ()),
            ),
        )

        units = {unit.unit_id: unit for unit in self.store.list_units("player:1")}
        self.assertEqual(units["unit:1"].slot, 0)
        self.assertEqual(units["unit:1"].name, "Primary")
        self.assertEqual(
            units["unit:1"].members,
            (UnitMember(0, "card:3"), UnitMember(2, "card:1")),
        )
        self.assertEqual(units["unit:2"].members, ())

        self.assertEqual(len(changes.entities), 2)
        self.assertTrue(
            all(
                change.evidence is not None
                and change.evidence.status is EvidenceStatus.PROVEN_STATIC
                and change.evidence.kind is EvidenceKind.EXACT
                for change in changes.entities
            )
        )

    def test_invalid_card_rejects_entire_batch_before_any_write(self) -> None:
        before = self.store.list_units("player:1")
        with self.assertRaises(KeyError):
            self.service.replace_members(
                "player:1",
                (
                    UnitMembershipUpdate("unit:1", (UnitMember(0, "card:3"),)),
                    UnitMembershipUpdate("unit:2", (UnitMember(0, "missing"),)),
                ),
            )
        self.assertEqual(self.store.list_units("player:1"), before)

    def test_unknown_unit_rejects_entire_batch(self) -> None:
        before = self.store.list_units("player:1")
        with self.assertRaises(KeyError):
            self.service.replace_members(
                "player:1",
                (
                    UnitMembershipUpdate("unit:1", (UnitMember(0, "card:3"),)),
                    UnitMembershipUpdate("missing", ()),
                ),
            )
        self.assertEqual(self.store.list_units("player:1"), before)

    def test_identical_membership_is_noop(self) -> None:
        changes = self.service.replace_members(
            "player:1",
            (
                UnitMembershipUpdate(
                    "unit:1",
                    (UnitMember(0, "card:1"), UnitMember(1, "card:2")),
                ),
            ),
        )
        self.assertTrue(changes.is_empty)

    def test_duplicate_unit_updates_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.service.replace_members(
                "player:1",
                (
                    UnitMembershipUpdate("unit:1", ()),
                    UnitMembershipUpdate("unit:1", ()),
                ),
            )


if __name__ == "__main__":
    unittest.main()
