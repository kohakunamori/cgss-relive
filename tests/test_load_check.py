from __future__ import annotations

import unittest

from server import cgss_codec
from server import load_check


class LoadCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.udid = "00112233-4455-6677-8899-aabbccddeeff"
        self.key = b"0123456789abcdefghijklmnopqrstuv"
        self.sid = "synthetic-session-id"

    def test_resource_mismatch_negotiates_final_version(self) -> None:
        payload = load_check.build_load_check_payload(
            "10133000",
            final_res_ver="10133800",
            sid=self.sid,
            servertime=1_700_000_000,
        )
        headers = payload["data_headers"]
        self.assertEqual(headers["result_code"], load_check.RESULT_RES_VERSION_ERROR)
        self.assertEqual(headers["required_res_ver"], "10133800")
        self.assertEqual(headers["sid"], self.sid)
        self.assertEqual(headers["servertime"], 1_700_000_000)
        self.assertEqual(payload["data"], {})

    def test_final_resource_version_returns_success(self) -> None:
        payload = load_check.build_load_check_payload(
            "10133800",
            final_res_ver="10133800",
            servertime=1_700_000_000,
        )
        headers = payload["data_headers"]
        self.assertEqual(headers["result_code"], load_check.RESULT_SUCCESS)
        self.assertNotIn("required_res_ver", headers)

    def test_minimal_response_can_omit_data(self) -> None:
        payload = load_check.build_load_check_payload(
            "10133800",
            include_empty_data=False,
            servertime=1_700_000_000,
        )
        self.assertEqual(set(payload), {"data_headers"})

    def test_wire_response_round_trips_through_final_envelope(self) -> None:
        response = load_check.encode_load_check_response(
            self.udid,
            "10133000",
            final_res_ver="10133800",
            sid=self.sid,
            servertime=1_700_000_000,
            dynamic_key=self.key,
        )
        decoded = cgss_codec.decode_body(response.body, self.udid)
        self.assertEqual(decoded, response.payload)
        self.assertEqual(decoded["data_headers"]["result_code"], 214)
        self.assertEqual(decoded["data_headers"]["required_res_ver"], "10133800")

    def test_final_client_result_constants(self) -> None:
        self.assertEqual(load_check.RESULT_SUCCESS, 1)
        self.assertEqual(load_check.RESULT_SESSION_ERROR, 201)
        self.assertEqual(load_check.RESULT_APP_VERSION_ERROR, 204)
        self.assertEqual(load_check.RESULT_RES_VERSION_ERROR, 214)


if __name__ == "__main__":
    unittest.main()
