from __future__ import annotations

from datetime import datetime, timezone
import unittest

from server.adapters import (
    CardLoadIndexBinding,
    LoadIndexProjectionPolicy,
    UnitLoadIndexBinding,
    project_home_snapshot_to_load_index_data,
)
from server.domain import (
    CardOwnership,
    HomeStateSnapshot,
    PlayerProfile,
    PlayerResource,
    Unit,
    UnitMember,
)
from server.minimal_profile import (
    COMPLETED_TUTORIAL_FLAG,
    STARTER_WORK_CARD_SECTION,
    validate_home_candidate_profile,
)


class DomainLoadIndexAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 9, 4, 20, 0, tzinfo=timezone.utc)
        self.profile = PlayerProfile(
            "player:1",
            "Archive Producer",
            12,
            345,
            self.now,
            self.now,
        )
        self.card = CardOwnership(
            user_card_id="card:alpha",
            player_id=self.profile.player_id,
            master_card_id=100001,
            level=20,
            experience=456,
            skill_level=3,
            star_lesson_step=2,
            love=77,
            is_protected=True,
            favorite=True,
            acquired_at=self.now,
        )
        self.unit = Unit(
            "unit:main",
            self.profile.player_id,
            0,
            "Archive Unit",
            members=(UnitMember(0, self.card.user_card_id),),
        )

    def test_projection_maps_domain_state_and_numeric_wire_bindings(self) -> None:
        snapshot = HomeStateSnapshot(
            profile=self.profile,
            resources=(
                PlayerResource(self.profile.player_id, "stamina", 88),
                PlayerResource(self.profile.player_id, "gold", 12345),
            ),
            cards=(self.card,),
            units=(self.unit,),
        )
        policy = LoadIndexProjectionPolicy(
            viewer_id=42,
            now=1_788_552_000,
            card_bindings={self.card.user_card_id: CardLoadIndexBinding(serial_id=7001)},
            unit_bindings={self.unit.unit_id: UnitLoadIndexBinding(unit_id=9001)},
            leader_user_card_id=self.card.user_card_id,
        )

        data = project_home_snapshot_to_load_index_data(snapshot, policy)
        self.assertEqual(validate_home_candidate_profile(data), [])

        user = data["user_info"]
        self.assertEqual(user["tutorial_flag"], COMPLETED_TUTORIAL_FLAG)
        self.assertEqual(user["viewer_id"], 42)
        self.assertEqual(user["name"], "Archive Producer")
        self.assertEqual(user["level"], 12)
        self.assertEqual(user["exp"], 345)
        self.assertEqual(user["stamina"], 88)
        self.assertEqual(user["gold"], 12345)
        self.assertEqual(user["friend_pt"], 0)
        self.assertEqual(user["leader_serial_id"], 7001)

        self.assertEqual(data["user_card_list"], [])
        self.assertEqual(data["user_chara_list"], [])
        cards = data[STARTER_WORK_CARD_SECTION]
        self.assertEqual(
            cards,
            [
                {
                    "serial_id": 7001,
                    "card_id": 100001,
                    "exp": 456,
                    "step": 2,
                    "love": 77,
                    "skill_level": 3,
                    "protect": 1,
                }
            ],
        )

        units = data["user_unit_list"]
        self.assertEqual(units[0]["unit_slot"], 1)
        self.assertEqual(units[0]["unit_id"], 9001)
        self.assertEqual(units[0]["serial_id_0"], 7001)
        self.assertEqual(
            [units[0][f"serial_id_{index}"] for index in range(1, 5)],
            [0, 0, 0, 0],
        )

    def test_empty_domain_state_stays_parser_safe(self) -> None:
        data = project_home_snapshot_to_load_index_data(
            HomeStateSnapshot(profile=self.profile),
            LoadIndexProjectionPolicy(viewer_id=1, now=0),
        )
        self.assertEqual(validate_home_candidate_profile(data), [])
        self.assertNotIn(STARTER_WORK_CARD_SECTION, data)
        self.assertEqual(data["user_unit_list"], [])

    def test_card_binding_is_required_for_owned_cards(self) -> None:
        snapshot = HomeStateSnapshot(profile=self.profile, cards=(self.card,))
        with self.assertRaisesRegex(ValueError, "missing load-index card binding"):
            project_home_snapshot_to_load_index_data(
                snapshot,
                LoadIndexProjectionPolicy(viewer_id=1, now=0),
            )

    def test_unit_members_cannot_exceed_final_five_serial_slots(self) -> None:
        oversized_unit = Unit(
            "unit:oversized",
            self.profile.player_id,
            0,
            members=(UnitMember(5, self.card.user_card_id),),
        )
        snapshot = HomeStateSnapshot(
            profile=self.profile,
            cards=(self.card,),
            units=(oversized_unit,),
        )
        with self.assertRaisesRegex(ValueError, "slot count"):
            project_home_snapshot_to_load_index_data(
                snapshot,
                LoadIndexProjectionPolicy(
                    viewer_id=1,
                    now=0,
                    card_bindings={"card:alpha": CardLoadIndexBinding(1)},
                    unit_bindings={"unit:oversized": UnitLoadIndexBinding(1)},
                ),
            )

    def test_duplicate_client_serials_are_rejected(self) -> None:
        second = CardOwnership(
            user_card_id="card:beta",
            player_id=self.profile.player_id,
            master_card_id=100002,
            level=1,
            experience=0,
            skill_level=1,
            star_lesson_step=0,
            love=0,
            is_protected=False,
            favorite=False,
            acquired_at=self.now,
        )
        snapshot = HomeStateSnapshot(profile=self.profile, cards=(self.card, second))
        with self.assertRaisesRegex(ValueError, "duplicate CGSS card serial_id"):
            project_home_snapshot_to_load_index_data(
                snapshot,
                LoadIndexProjectionPolicy(
                    viewer_id=1,
                    now=0,
                    card_bindings={
                        "card:alpha": CardLoadIndexBinding(5),
                        "card:beta": CardLoadIndexBinding(5),
                    },
                ),
            )


if __name__ == "__main__":
    unittest.main()
