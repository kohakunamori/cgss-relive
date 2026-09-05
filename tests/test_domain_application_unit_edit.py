from __future__ import annotations

from datetime import datetime, timezone
import unittest

from server.adapters.identity_store import SQLiteCompatibilityIdentityStore
from server.application import MemberUnitEditConfig, MemberUnitEditController
from server.domain import (
    CardOwnership,
    PlayerProfile,
    PreservationUnitService,
    SQLiteDomainStore,
    Unit,
    UnitMember,
)


class MemberUnitEditApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 5, 6, 30, tzinfo=timezone.utc)
        self.domain = SQLiteDomainStore.open(":memory:")
        self.identities = SQLiteCompatibilityIdentityStore.open(":memory:")
        self.domain.save_profile(
            PlayerProfile("player:1", "Producer", 1, 0, self.now, self.now)
        )
        for index, master_id in enumerate((100001, 100002, 100003), start=1):
            self.domain.save_card(
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
            self.assertEqual(
                self.identities.ensure_card_serial("player:1", f"card:{index}"),
                index,
            )
        self.domain.save_unit(
            Unit(
                unit_id="unit:1",
                player_id="player:1",
                slot=0,
                name="Primary",
                members=(UnitMember(0, "card:1"), UnitMember(1, "card:2")),
            )
        )
        self.assertEqual(self.identities.ensure_unit_id("player:1", "unit:1"), 1)
        self.controller = MemberUnitEditController(
            PreservationUnitService(self.domain),
            self.identities,
            config=MemberUnitEditConfig("player:1"),
        )

    def tearDown(self) -> None:
        self.identities.close()
        self.domain.close()

    @staticmethod
    def request(serial_ids: list[int]) -> dict[str, object]:
        return {
            "unit_info_list": [
                {
                    "unit_id": 1,
                    "serial_ids": serial_ids,
                    "dress_types": [0, 0, 0, 0, 0],
                    "dress_2d_types": [0, 0, 0, 0, 0],
                    "dress_storage_ids": [0, 0, 0, 0, 0],
                }
            ],
            "main_unit_id": 1,
        }

    def test_handle_replaces_members_and_returns_exact_empty_endpoint_data(self) -> None:
        response = self.controller.handle(self.request([3, 0, 1, 0, 0]))
        self.assertEqual(response, {})
        unit = self.domain.list_units("player:1")[0]
        self.assertEqual(
            unit.members,
            (UnitMember(0, "card:3"), UnitMember(2, "card:1")),
        )
        self.assertEqual(unit.slot, 0)
        self.assertEqual(unit.name, "Primary")

    def test_invalid_parallel_slot_count_rejects_without_mutation(self) -> None:
        before = self.domain.list_units("player:1")
        request = self.request([3, 0, 1, 0])
        with self.assertRaises(ValueError):
            self.controller.handle(request)
        self.assertEqual(self.domain.list_units("player:1"), before)

    def test_unknown_serial_rejects_without_mutation(self) -> None:
        before = self.domain.list_units("player:1")
        with self.assertRaises(ValueError):
            self.controller.handle(self.request([999, 0, 1, 0, 0]))
        self.assertEqual(self.domain.list_units("player:1"), before)


if __name__ == "__main__":
    unittest.main()
