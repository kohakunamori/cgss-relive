from __future__ import annotations

import unittest

from server.minimal_profile import (
    HOME_CANDIDATE_EMPTY_LIST_SECTIONS,
    REQUIRED_COMMON_DEFINE_FIELDS,
    REQUIRED_USER_INFO_FIELDS,
    build_home_candidate_load_index_data,
    build_minimal_load_index_data,
    validate_home_candidate_profile,
    validate_minimal_profile,
)


class MinimalProfileTests(unittest.TestCase):
    def test_builder_contains_every_statically_required_field(self) -> None:
        data = build_minimal_load_index_data(viewer_id=123, producer_name="Relive", now=456)
        self.assertEqual(validate_minimal_profile(data), [])
        self.assertEqual(data["user_info"]["viewer_id"], 123)
        self.assertEqual(data["user_info"]["name"], "Relive")
        self.assertEqual(data["user_info"]["stamina_heal_time"], 456)
        self.assertEqual(data["user_info"]["tutorial_flag"], 100)
        self.assertNotIn("user_card_list", data)
        self.assertNotIn("music_list", data)

    def test_home_candidate_keeps_minimal_contract_and_initializes_safe_containers(self) -> None:
        data = build_home_candidate_load_index_data(viewer_id=321, producer_name="Home", now=654)
        self.assertEqual(validate_home_candidate_profile(data), [])
        self.assertEqual(validate_minimal_profile(data), [])
        self.assertEqual(data["user_info"]["viewer_id"], 321)
        for section in HOME_CANDIDATE_EMPTY_LIST_SECTIONS:
            self.assertEqual(data[section], [])
        self.assertEqual(data["music_list"], {"normal": []})

    def test_home_candidate_validator_rejects_wrong_container_shapes(self) -> None:
        data = build_home_candidate_load_index_data(now=1)
        data[HOME_CANDIDATE_EMPTY_LIST_SECTIONS[0]] = {}
        data["music_list"] = {"normal": {}}
        self.assertEqual(
            validate_home_candidate_profile(data),
            [HOME_CANDIDATE_EMPTY_LIST_SECTIONS[0], "music_list.normal"],
        )

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
