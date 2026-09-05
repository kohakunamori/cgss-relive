from __future__ import annotations

import unittest

from server.adapters import (
    MemberProtectRequest,
    parse_member_protect_request,
    project_member_protect_response_data,
)


class MemberProtectRequestAdapterTests(unittest.TestCase):
    def test_parses_exact_serial_ids_array_without_invented_flag(self) -> None:
        parsed = parse_member_protect_request({"serial_ids": [7, 3, 7]})
        self.assertEqual(parsed, MemberProtectRequest((7, 3, 7)))
        self.assertFalse(hasattr(parsed, "protect"))
        self.assertFalse(hasattr(parsed, "is_protected"))

    def test_empty_array_is_preserved_until_semantics_prove_otherwise(self) -> None:
        self.assertEqual(
            parse_member_protect_request({"serial_ids": []}),
            MemberProtectRequest(()),
        )

    def test_response_projects_protected_requested_subset_in_request_order(self) -> None:
        request = MemberProtectRequest((7, 3, 9))
        self.assertEqual(
            project_member_protect_response_data(request, (9, 7)),
            {"protect_card_list": [7, 9]},
        )
        self.assertEqual(
            project_member_protect_response_data(request, ()),
            {"protect_card_list": []},
        )

    def test_response_rejects_unrequested_membership(self) -> None:
        with self.assertRaises(ValueError):
            project_member_protect_response_data(MemberProtectRequest((7,)), (8,))

    def test_rejects_unproven_or_invalid_shapes(self) -> None:
        for invalid in (
            None,
            {},
            {"serial_ids": 1},
            {"serial_ids": [0]},
            {"serial_ids": [-1]},
            {"serial_ids": [True]},
            {"serial_ids": ["1"]},
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    parse_member_protect_request(invalid)


if __name__ == "__main__":
    unittest.main()
