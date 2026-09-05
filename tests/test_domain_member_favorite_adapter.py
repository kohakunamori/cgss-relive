from __future__ import annotations

import unittest

from server.adapters import MemberFavoriteEditRequest, parse_member_favorite_edit_request


class MemberFavoriteEditAdapterTests(unittest.TestCase):
    def test_preserves_parallel_serial_and_flag_arrays_exactly(self) -> None:
        request = parse_member_favorite_edit_request(
            {
                "serial_ids": [7, 3, 7],
                "change_flags": [1, 0, 9],
            }
        )
        self.assertEqual(
            request,
            MemberFavoriteEditRequest(
                serial_ids=(7, 3, 7),
                change_flags=(1, 0, 9),
            ),
        )

    def test_rejects_missing_or_non_parallel_arrays(self) -> None:
        with self.assertRaises(ValueError):
            parse_member_favorite_edit_request({"serial_ids": [1]})
        with self.assertRaises(ValueError):
            parse_member_favorite_edit_request(
                {"serial_ids": [1, 2], "change_flags": [1]}
            )

    def test_rejects_invalid_serials_but_does_not_guess_flag_domain(self) -> None:
        with self.assertRaises(ValueError):
            parse_member_favorite_edit_request(
                {"serial_ids": [0], "change_flags": [1]}
            )
        with self.assertRaises(ValueError):
            parse_member_favorite_edit_request(
                {"serial_ids": [True], "change_flags": [1]}
            )
        with self.assertRaises(ValueError):
            parse_member_favorite_edit_request(
                {"serial_ids": [1], "change_flags": [True]}
            )

        # Exact managed metadata proves int[], not a specific enum/range yet.
        parsed = parse_member_favorite_edit_request(
            {"serial_ids": [1], "change_flags": [-17]}
        )
        self.assertEqual(parsed.change_flags, (-17,))


if __name__ == "__main__":
    unittest.main()
