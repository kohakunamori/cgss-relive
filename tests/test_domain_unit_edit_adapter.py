from __future__ import annotations

import unittest

from server.adapters import (
    MemberUnitEditRequest,
    MemberUnitEditUnitInfo,
    parse_member_unit_edit_request,
)


class MemberUnitEditRequestAdapterTests(unittest.TestCase):
    def test_parses_exact_final_request_fields_without_assigning_costume_semantics(self) -> None:
        request = parse_member_unit_edit_request(
            {
                "unit_info_list": [
                    {
                        "unit_id": 7,
                        "serial_ids": [11, 0, 13, 0, 0],
                        "dress_types": [1, 0, 2, 0, 0],
                        "dress_2d_types": [3, 0, 4, 0, 0],
                        "dress_storage_ids": [5, 0, 6, 0, 0],
                    }
                ],
                "main_unit_id": 7,
            }
        )
        self.assertEqual(
            request,
            MemberUnitEditRequest(
                unit_info_list=(
                    MemberUnitEditUnitInfo(
                        unit_id=7,
                        serial_ids=(11, 0, 13, 0, 0),
                        dress_types=(1, 0, 2, 0, 0),
                        dress_2d_types=(3, 0, 4, 0, 0),
                        dress_storage_ids=(5, 0, 6, 0, 0),
                    ),
                ),
                main_unit_id=7,
            ),
        )

    def test_preserves_empty_arrays_and_zero_main_until_native_semantics_close(self) -> None:
        request = parse_member_unit_edit_request(
            {
                "unit_info_list": [
                    {
                        "unit_id": 1,
                        "serial_ids": [],
                        "dress_types": [],
                        "dress_2d_types": [],
                        "dress_storage_ids": [],
                    }
                ],
                "main_unit_id": 0,
            }
        )
        self.assertEqual(request.main_unit_id, 0)
        self.assertEqual(request.unit_info_list[0].serial_ids, ())

    def test_rejects_missing_or_wrong_managed_shapes(self) -> None:
        invalid = (
            None,
            {},
            {"unit_info_list": [], "main_unit_id": True},
            {"unit_info_list": {}, "main_unit_id": 1},
            {"unit_info_list": [None], "main_unit_id": 1},
            {
                "unit_info_list": [
                    {
                        "unit_id": 1,
                        "serial_ids": [1],
                        "dress_types": [0],
                        "dress_2d_types": [0],
                    }
                ],
                "main_unit_id": 1,
            },
            {
                "unit_info_list": [
                    {
                        "unit_id": 0,
                        "serial_ids": [1],
                        "dress_types": [0],
                        "dress_2d_types": [0],
                        "dress_storage_ids": [0],
                    }
                ],
                "main_unit_id": 1,
            },
            {
                "unit_info_list": [
                    {
                        "unit_id": 1,
                        "serial_ids": [-1],
                        "dress_types": [0],
                        "dress_2d_types": [0],
                        "dress_storage_ids": [0],
                    }
                ],
                "main_unit_id": 1,
            },
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    parse_member_unit_edit_request(value)


if __name__ == "__main__":
    unittest.main()
