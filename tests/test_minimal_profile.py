from __future__ import annotations

import unittest

from server.minimal_profile import (
    COMPLETED_TUTORIAL_FLAG,
    COMPLETED_TUTORIAL_LOCAL_STEP,
    FINAL_UNIT_SLOT_COUNT,
    HOME_CANDIDATE_EMPTY_LIST_SECTIONS,
    REQUIRED_COMMON_DEFINE_FIELDS,
    REQUIRED_USER_INFO_FIELDS,
    STARTER_CARD_ID,
    STARTER_CHARA_ID,
    STARTER_SERIAL_ID,
    STARTER_UNIT_ID,
    STARTER_UNIT_SLOT,
    STARTER_WORK_CARD_SECTION,
    build_home_candidate_load_index_data,
    build_minimal_load_index_data,
    build_starter_visible_load_index_data,
    validate_home_candidate_profile,
    validate_minimal_profile,
    validate_starter_visible_profile,
)


class MinimalProfileTests(unittest.TestCase):
    def test_builder_contains_every_statically_required_field(self) -> None:
        data = build_minimal_load_index_data(viewer_id=123, producer_name="Relive", now=456)
        self.assertEqual(validate_minimal_profile(data), [])
        self.assertEqual(data["user_info"]["viewer_id"], 123)
        self.assertEqual(data["user_info"]["name"], "Relive")
        self.assertEqual(data["user_info"]["stamina_heal_time"], 456)
        self.assertEqual(COMPLETED_TUTORIAL_FLAG, 100)
        self.assertEqual(COMPLETED_TUTORIAL_LOCAL_STEP, 1000)
        self.assertEqual(data["user_info"]["tutorial_flag"], COMPLETED_TUTORIAL_FLAG)
        self.assertNotIn("unit_slot", data["user_info"])
        self.assertNotIn("user_card_list", data)
        self.assertNotIn("user_unit_list", data)
        self.assertNotIn("music_list", data)

    def test_home_candidate_keeps_minimal_contract_and_initializes_safe_containers(self) -> None:
        data = build_home_candidate_load_index_data(viewer_id=321, producer_name="Home", now=654)
        self.assertEqual(validate_home_candidate_profile(data), [])
        self.assertEqual(validate_minimal_profile(data), [])
        self.assertEqual(data["user_info"]["viewer_id"], 321)
        self.assertEqual(data["user_info"]["tutorial_flag"], COMPLETED_TUTORIAL_FLAG)
        self.assertNotIn("unit_slot", data["user_info"])
        for section in HOME_CANDIDATE_EMPTY_LIST_SECTIONS:
            self.assertEqual(data[section], [])
        self.assertEqual(data["music_list"], {"normal": []})
        self.assertNotIn(STARTER_WORK_CARD_SECTION, data)

    def test_home_candidate_validator_rejects_wrong_shapes(self) -> None:
        data = build_home_candidate_load_index_data(now=1)
        data[HOME_CANDIDATE_EMPTY_LIST_SECTIONS[0]] = {}
        data["music_list"] = {"normal": {}}
        self.assertEqual(
            validate_home_candidate_profile(data),
            [
                HOME_CANDIDATE_EMPTY_LIST_SECTIONS[0],
                "music_list.normal",
            ],
        )

    def test_home_candidate_validator_rejects_noncompleted_tutorial_flag(self) -> None:
        data = build_home_candidate_load_index_data(now=1)
        data["user_info"]["tutorial_flag"] = 90
        self.assertIn("user_info.tutorial_flag", validate_home_candidate_profile(data))

    def test_starter_visible_profile_populates_work_card_and_final_unit_contract(self) -> None:
        data = build_starter_visible_load_index_data(viewer_id=9, producer_name="Starter", now=10)
        self.assertEqual(validate_starter_visible_profile(data), [])
        self.assertEqual(validate_home_candidate_profile(data), [])

        # user_card_list belongs to the separate guarded Cenere-merge path. The
        # actual WorkCardData.AddCardData parser is the exact literal section.
        self.assertEqual(data["user_card_list"], [])
        self.assertEqual(len(data[STARTER_WORK_CARD_SECTION]), 1)
        card = data[STARTER_WORK_CARD_SECTION][0]
        self.assertEqual(card["serial_id"], STARTER_SERIAL_ID)
        self.assertEqual(card["card_id"], STARTER_CARD_ID)
        self.assertNotIn("join_type", card)
        self.assertNotIn("level", card)

        self.assertEqual(len(data["user_unit_list"]), 1)
        unit = data["user_unit_list"][0]
        self.assertEqual(unit["unit_slot"], STARTER_UNIT_SLOT)
        self.assertEqual(unit["unit_id"], STARTER_UNIT_ID)
        self.assertEqual(unit["serial_id_0"], STARTER_SERIAL_ID)
        self.assertEqual(
            [unit[f"serial_id_{index}"] for index in range(FINAL_UNIT_SLOT_COUNT)],
            [STARTER_SERIAL_ID, 0, 0, 0, 0],
        )
        self.assertNotIn("viewer_id", unit)

        self.assertEqual(data["user_chara_list"], [{"chara_id": STARTER_CHARA_ID, "fan": 0}])
        self.assertEqual(data["user_info"]["leader_serial_id"], STARTER_SERIAL_ID)

    def test_starter_visible_validator_rejects_broken_references(self) -> None:
        data = build_starter_visible_load_index_data(now=1)
        data[STARTER_WORK_CARD_SECTION][0]["card_id"] = 999999
        data["user_unit_list"][0]["unit_slot"] = 2
        data["user_unit_list"][0]["unit_id"] = 2
        data["user_unit_list"][0]["serial_id_0"] = 2
        data["user_chara_list"][0]["chara_id"] = 999
        data["user_info"]["leader_serial_id"] = 2
        errors = validate_starter_visible_profile(data)
        self.assertIn(f"{STARTER_WORK_CARD_SECTION}[0].card_id", errors)
        self.assertIn("user_unit_list[0].unit_slot", errors)
        self.assertIn("user_unit_list[0].unit_id", errors)
        self.assertIn("user_unit_list[0].serial_id_0", errors)
        self.assertIn("user_chara_list[0].chara_id", errors)
        self.assertIn("user_info.leader_serial_id", errors)

    def test_starter_visible_validator_rejects_user_card_duplicate_path(self) -> None:
        data = build_starter_visible_load_index_data(now=1)
        data["user_card_list"] = [dict(data[STARTER_WORK_CARD_SECTION][0])]
        self.assertIn("user_card_list", validate_starter_visible_profile(data))

    def test_starter_visible_validator_requires_work_card_section(self) -> None:
        data = build_starter_visible_load_index_data(now=1)
        del data[STARTER_WORK_CARD_SECTION]
        self.assertIn(f"{STARTER_WORK_CARD_SECTION}[1]", validate_starter_visible_profile(data))

    def test_starter_visible_validator_requires_unit_id_field(self) -> None:
        data = build_starter_visible_load_index_data(now=1)
        del data["user_unit_list"][0]["unit_id"]
        self.assertIn("user_unit_list[0].unit_id", validate_starter_visible_profile(data))

    def test_starter_visible_validator_requires_unit_slot_field(self) -> None:
        data = build_starter_visible_load_index_data(now=1)
        del data["user_unit_list"][0]["unit_slot"]
        self.assertIn("user_unit_list[0].unit_slot", validate_starter_visible_profile(data))

    def test_validator_reports_removed_fields(self) -> None:
        data = build_minimal_load_index_data(now=1)
        del data["common_define"][REQUIRED_COMMON_DEFINE_FIELDS[0]]
        del data["user_info"][REQUIRED_USER_INFO_FIELDS[-1]]
        self.assertEqual(
            validate_minimal_profile(data),
            [
                f"common_define.{REQUIRED_COMMON_DEFINE_FIELDS[0]}",
                f"user_info.{REQUIRED_USER_INFO_FIELDS[-1]}",
            ],
        )

    def test_validator_rejects_missing_sections(self) -> None:
        self.assertEqual(validate_minimal_profile({}), ["common_define", "user_info"])


if __name__ == "__main__":
    unittest.main()
