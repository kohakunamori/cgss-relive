from __future__ import annotations

import unittest

from server import bootstrap_core, cgss_codec, header_codec


def synthetic_header_encode(value: str) -> str:
    """Deterministic fixture implementing the final client's encode layout."""
    groups = "".join("12" + chr(ord(ch) + 10) + "3" for ch in value)
    return f"{len(value):04x}" + groups + ("7" * 32)


class HeaderCodecTests(unittest.TestCase):
    def test_decodes_final_layout(self) -> None:
        value = "00112233-4455-6677-8899-aabbccddeeff"
        self.assertEqual(header_codec.decode_header_value(synthetic_header_encode(value)), value)

    def test_rejects_truncated_value(self) -> None:
        with self.assertRaises(header_codec.HeaderDecodeError):
            header_codec.decode_header_value("0002" + "12A3")


class BootstrapCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.udid = "00112233-4455-6677-8899-aabbccddeeff"
        self.request_key = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
        self.response_key = b"0123456789abcdefghijklmnopqrstuv"
        self.request = {
            "campaign_data": "",
            "campaign_user": 0,
            "campaign_sign": "",
            "app_type": 0,
            "viewer_id": "opaque-viewer-id",
            "timezone": "+09:00:00",
        }

    def _headers(self, res_ver: str) -> dict[str, str]:
        return {
            "UDID": synthetic_header_encode(self.udid),
            "RES-VER": res_ver,
            "SID": "synthetic-sid",
            "APP-VER": "11.6.3",
        }

    def test_complete_mismatch_exchange(self) -> None:
        body = cgss_codec.encode_body(self.request, self.udid, dynamic_key=self.request_key)
        exchange = bootstrap_core.process_load_check_request(
            self._headers("10133000"),
            body,
            final_res_ver="10133800",
            servertime=1_700_000_000,
            dynamic_key=self.response_key,
        )
        self.assertEqual(exchange.udid, self.udid)
        self.assertEqual(exchange.request, self.request)
        self.assertEqual(exchange.response["data_headers"]["result_code"], 214)
        self.assertEqual(exchange.response["data_headers"]["required_res_ver"], "10133800")
        self.assertEqual(exchange.response["data_headers"]["sid"], "synthetic-sid")
        self.assertEqual(
            cgss_codec.decode_body(exchange.response_body, self.udid),
            exchange.response,
        )

    def test_migration_status_normal_exchange(self) -> None:
        body = cgss_codec.encode_body(self.request, self.udid, dynamic_key=self.request_key)
        exchange = bootstrap_core.process_migration_check_request(
            self._headers("10133000"),
            body,
            servertime=1_700_000_000,
            dynamic_key=self.response_key,
        )
        self.assertEqual(exchange.request, self.request)
        self.assertEqual(exchange.response["data_headers"]["result_code"], 1)
        self.assertEqual(exchange.response["data_headers"]["sid"], "synthetic-sid")
        self.assertEqual(exchange.response["data"], {"transition": 0})
        self.assertEqual(cgss_codec.decode_body(exchange.response_body, self.udid), exchange.response)

    def test_complete_success_exchange(self) -> None:
        body = cgss_codec.encode_body(self.request, self.udid, dynamic_key=self.request_key)
        exchange = bootstrap_core.process_load_check_request(
            self._headers("10133800"),
            body,
            final_res_ver="10133800",
            servertime=1_700_000_000,
            dynamic_key=self.response_key,
        )
        self.assertEqual(exchange.response["data_headers"]["result_code"], 1)
        self.assertNotIn("required_res_ver", exchange.response["data_headers"])


if __name__ == "__main__":
    unittest.main()
