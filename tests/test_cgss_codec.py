from __future__ import annotations

import base64
import hashlib
import importlib.util
import sys
import unittest
from pathlib import Path


MODULE = Path(__file__).resolve().parents[1] / "server" / "cgss_codec.py"
SPEC = importlib.util.spec_from_file_location("cgss_codec", MODULE)
codec = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = codec
SPEC.loader.exec_module(codec)


class CgssCodecTests(unittest.TestCase):
    def setUp(self) -> None:
        self.udid = "00112233-4455-6677-8899-aabbccddeeff"
        self.key = b"0123456789abcdefghijklmnopqrstuv"

    def test_udid_iv(self) -> None:
        self.assertEqual(
            codec.normalize_udid_iv(self.udid),
            bytes.fromhex("00112233445566778899aabbccddeeff"),
        )

    def test_body_round_trip(self) -> None:
        params = {
            "viewer_id": "synthetic-viewer",
            "timezone": "+09:00:00",
            "app_type": 0,
            "nested": {"enabled": True, "count": 3},
        }
        body = codec.encode_body(params, self.udid, dynamic_key=self.key)
        decoded = codec.decode_body(body, self.udid)
        self.assertEqual(decoded, params)

        outer = base64.b64decode(body)
        self.assertEqual(outer[-32:], self.key)
        self.assertEqual(len(outer[:-32]) % 16, 0)

    def test_compute_param_matches_definition(self) -> None:
        params = {"viewer_id": "fixture", "timezone": "+09:00:00"}
        plain = codec.pack_plain(params)
        got = codec.compute_param(self.udid, 12345, "/load/check", plain)
        expected = hashlib.sha1(
            self.udid.encode("utf-8")
            + b"12345"
            + b"/load/check"
            + plain
        ).hexdigest()
        self.assertEqual(got, expected)

    def test_sid_requires_injected_salt(self) -> None:
        session = "12345" + self.udid
        salt = "synthetic-local-salt"
        expected = hashlib.md5(
            (session + salt).encode("utf-8"), usedforsecurity=False
        ).hexdigest()
        self.assertEqual(codec.compute_sid(session, salt), expected)

    def test_rejects_bad_udid(self) -> None:
        with self.assertRaises(ValueError):
            codec.normalize_udid_iv("not-a-udid")


if __name__ == "__main__":
    unittest.main()
