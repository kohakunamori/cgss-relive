from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from server import cgss_codec
from server.http_server import _load_profile
from server.load_index import build_load_index_payload, encode_load_index_response


class LoadIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.udid = "00112233-4455-6677-8899-aabbccddeeff"
        self.key = b"0123456789abcdefghijklmnopqrstuv"
        self.data = {
            "common_define": {"expanding_count": 5},
            "user_info": {"tutorial_flag": 1000},
            "user_card_list": [],
        }

    def test_payload_wraps_profile_without_mutating_it(self) -> None:
        payload = build_load_index_payload(
            self.data,
            sid="synthetic-sid",
            servertime=1_700_000_000,
            viewer_id=123,
            user_id=456,
        )
        self.assertEqual(payload["data"], self.data)
        self.assertIsNot(payload["data"], self.data)
        self.assertEqual(payload["data_headers"]["result_code"], 1)
        self.assertEqual(payload["data_headers"]["viewer_id"], 123)
        self.assertEqual(payload["data_headers"]["user_id"], 456)

    def test_wire_response_round_trips(self) -> None:
        response = encode_load_index_response(
            self.udid,
            self.data,
            sid="synthetic-sid",
            servertime=1_700_000_000,
            dynamic_key=self.key,
        )
        self.assertEqual(cgss_codec.decode_body(response.body, self.udid), response.payload)

    def test_profile_loader_accepts_data_map_or_full_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data_path = root / "data.json"
            data_path.write_text(json.dumps(self.data), encoding="utf-8")
            self.assertEqual(_load_profile(data_path), self.data)

            response_path = root / "response.json"
            response_path.write_text(
                json.dumps({"data_headers": {"result_code": 1}, "data": self.data}),
                encoding="utf-8",
            )
            self.assertEqual(_load_profile(response_path), self.data)

    def test_profile_loader_rejects_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profile.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(ValueError):
                _load_profile(path)


if __name__ == "__main__":
    unittest.main()
