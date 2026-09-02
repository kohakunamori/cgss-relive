from __future__ import annotations

import http.client
import json
import pathlib
import tempfile
import threading
import unittest

from server import cgss_codec
from server.api_registry import ApiEndpoint
from server.http_server import create_server


def synthetic_header_encode(value: str) -> str:
    groups = "".join("12" + chr(ord(ch) + 10) + "3" for ch in value)
    return f"{len(value):04x}" + groups + ("7" * 32)


class HTTPBootstrapServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.udid = "00112233-4455-6677-8899-aabbccddeeff"
        self.server = create_server("127.0.0.1", 0, final_res_ver="10133800")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _request_body(self) -> bytes:
        request = {
            "campaign_data": "",
            "campaign_user": 0,
            "campaign_sign": "",
            "app_type": 0,
            "viewer_id": "opaque-viewer-id",
            "timezone": "+09:00:00",
        }
        return cgss_codec.encode_body(
            request,
            self.udid,
            dynamic_key=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        )

    def _headers(self, res_ver: str = "10133800") -> dict[str, str]:
        return {
            "Content-Type": "application/octet-stream",
            "UDID": synthetic_header_encode(self.udid),
            "RES-VER": res_ver,
            "SID": "synthetic-sid",
            "APP-VER": "11.6.3",
        }

    def _post_route(self, route: str, *, res_ver: str = "10133800") -> tuple[int, bytes]:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        conn.request("POST", route, body=self._request_body(), headers=self._headers(res_ver))
        response = conn.getresponse()
        payload = response.read()
        status = response.status
        conn.close()
        return status, payload

    def test_real_http_mismatch_exchange(self) -> None:
        status, body = self._post_route("/load/check", res_ver="10133000")
        self.assertEqual(status, 200)
        decoded = cgss_codec.decode_body(body, self.udid)
        self.assertEqual(decoded["data_headers"]["result_code"], 214)
        self.assertEqual(decoded["data_headers"]["required_res_ver"], "10133800")

    def test_real_http_success_exchange(self) -> None:
        status, body = self._post_route("/load/check")
        self.assertEqual(status, 200)
        decoded = cgss_codec.decode_body(body, self.udid)
        self.assertEqual(decoded["data_headers"]["result_code"], 1)
        self.assertNotIn("required_res_ver", decoded["data_headers"])

    def test_real_http_title_exchange(self) -> None:
        status, body = self._post_route("/load/title")
        self.assertEqual(status, 200)
        decoded = cgss_codec.decode_body(body, self.udid)
        self.assertEqual(decoded["data_headers"]["result_code"], 1)
        self.assertEqual(decoded["data_headers"]["sid"], "synthetic-sid")
        self.assertEqual(decoded["data"], {})

    def test_auxiliary_load_routes_return_common_success(self) -> None:
        for route in ("/load/set_cache_clear_flg", "/load/update_agreement_status"):
            with self.subTest(route=route):
                status, body = self._post_route(route)
                self.assertEqual(status, 200)
                decoded = cgss_codec.decode_body(body, self.udid)
                self.assertEqual(decoded["data_headers"]["result_code"], 1)
                self.assertEqual(decoded["data_headers"]["sid"], "synthetic-sid")
                self.assertEqual(decoded["data"], {})

    def test_load_index_requires_configured_profile(self) -> None:
        status, body = self._post_route("/load/index")
        self.assertEqual(status, 503)
        self.assertIn(b"profile is not configured", body)

    def test_real_http_load_index_exchange_with_profile(self) -> None:
        profile = {
            "common_define": {"expanding_count": 5},
            "user_info": {"tutorial_flag": 1000},
            "user_card_list": [],
        }
        server = create_server(
            "127.0.0.1",
            0,
            final_res_ver="10133800",
            load_index_data=profile,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address[:2]
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("POST", "/load/index", body=self._request_body(), headers=self._headers())
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
            conn.close()
            decoded = cgss_codec.decode_body(body, self.udid)
            self.assertEqual(decoded["data_headers"]["result_code"], 1)
            self.assertEqual(decoded["data"], profile)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_unknown_known_api_route_is_annotated_safely(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            event_path = pathlib.Path(directory) / "events.jsonl"
            api_index = {
                "/bn_consent/get_state": (
                    ApiEndpoint("A", "BnContentGetState", 14, "bn_consent/get_state", 23438),
                )
            }
            server = create_server(
                "127.0.0.1",
                0,
                event_log=event_path,
                api_index=api_index,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address[:2]
            try:
                conn = http.client.HTTPConnection(host, port, timeout=5)
                conn.request("POST", "/bn_consent/get_state", body=b"", headers={"Content-Length": "0"})
                response = conn.getresponse()
                self.assertEqual(response.status, 404)
                response.read()
                conn.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            event = json.loads(event_path.read_text(encoding="utf-8").strip())
            self.assertEqual(event["error"], "endpoint_not_implemented")
            self.assertEqual(
                event["api_candidates"],
                [{"group": "A", "key": 14, "name": "BnContentGetState", "literal_index": 23438}],
            )

    def test_health_and_unknown_route(self) -> None:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        conn.request("GET", "/healthz")
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"ok\n")
        conn.close()

        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        conn.request("POST", "/load/unknown", body=b"", headers={"Content-Length": "0"})
        response = conn.getresponse()
        self.assertEqual(response.status, 404)
        response.read()
        conn.close()


if __name__ == "__main__":
    unittest.main()
