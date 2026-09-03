from __future__ import annotations

import http.client
import threading
import unittest

from server import cgss_codec
from server.bootstrap_core import process_load_check_request
from server.header_codec import decode_header_value
from server.http_server import create_server
from server.load_check import build_load_check_payload


def synthetic_header_encode(value: str) -> str:
    groups = "".join("12" + chr(ord(ch) + 10) + "3" for ch in value)
    return f"{len(value):04x}" + groups + ("7" * 32)


class LoadCheckPolicyTests(unittest.TestCase):
    def test_direct_success_advances_res_ver_without_214(self) -> None:
        payload = build_load_check_payload(
            "10133000",
            final_res_ver="10133800",
            servertime=1,
            is_s3=False,
            accept_old_resource_version=True,
        )
        self.assertEqual(payload["data_headers"]["result_code"], 1)
        self.assertEqual(payload["data_headers"]["required_res_ver"], "10133800")
        self.assertEqual(payload["data"], {"isS3": False})

    def test_native_policy_keeps_214_but_exposes_storage_selector(self) -> None:
        payload = build_load_check_payload(
            "10133000",
            final_res_ver="10133800",
            servertime=1,
            is_s3=False,
        )
        self.assertEqual(payload["data_headers"]["result_code"], 214)
        self.assertEqual(payload["data_headers"]["required_res_ver"], "10133800")
        self.assertEqual(payload["data"], {"isS3": False})

    def test_bootstrap_core_direct_success_round_trip(self) -> None:
        udid = "00112233-4455-6677-8899-aabbccddeeff"
        request = {"viewer_id": "opaque"}
        body = cgss_codec.encode_body(
            request,
            udid,
            dynamic_key=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        )
        exchange = process_load_check_request(
            {
                "UDID": synthetic_header_encode(udid),
                "RES-VER": "10133000",
                "SID": "synthetic-sid",
            },
            body,
            final_res_ver="10133800",
            servertime=1,
            dynamic_key=b"0123456789abcdefghijklmnopqrstuv",
            accept_old_resource_version=True,
        )
        self.assertEqual(exchange.response["data_headers"]["result_code"], 1)
        self.assertEqual(exchange.response["data_headers"]["required_res_ver"], "10133800")
        self.assertEqual(exchange.response["data"], {"isS3": False})
        self.assertEqual(cgss_codec.decode_body(exchange.response_body, udid), exchange.response)

    def test_http_direct_success_mode(self) -> None:
        udid = "00112233-4455-6677-8899-aabbccddeeff"
        server = create_server(
            "127.0.0.1",
            0,
            final_res_ver="10133800",
            accept_old_resource_version=True,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address[:2]
        try:
            body = cgss_codec.encode_body(
                {"viewer_id": "opaque"},
                udid,
                dynamic_key=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
            )
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request(
                "POST",
                "/load/check",
                body=body,
                headers={
                    "UDID": synthetic_header_encode(udid),
                    "RES-VER": "10133000",
                    "SID": "synthetic-sid",
                },
            )
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            decoded = cgss_codec.decode_body(response.read(), udid)
            conn.close()
            self.assertEqual(decoded["data_headers"]["result_code"], 1)
            self.assertEqual(decoded["data_headers"]["required_res_ver"], "10133800")
            self.assertEqual(decoded["data"], {"isS3": False})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
