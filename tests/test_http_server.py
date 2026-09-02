from __future__ import annotations

import http.client
import threading
import unittest

from server import cgss_codec
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

    def _post(self, res_ver: str) -> tuple[int, bytes]:
        request = {
            "campaign_data": "",
            "campaign_user": 0,
            "campaign_sign": "",
            "app_type": 0,
            "viewer_id": "opaque-viewer-id",
            "timezone": "+09:00:00",
        }
        body = cgss_codec.encode_body(
            request,
            self.udid,
            dynamic_key=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        )
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        conn.request(
            "POST",
            "/load/check",
            body=body,
            headers={
                "Content-Type": "application/octet-stream",
                "UDID": synthetic_header_encode(self.udid),
                "RES-VER": res_ver,
                "SID": "synthetic-sid",
                "APP-VER": "11.6.3",
            },
        )
        response = conn.getresponse()
        payload = response.read()
        status = response.status
        conn.close()
        return status, payload

    def test_real_http_mismatch_exchange(self) -> None:
        status, body = self._post("10133000")
        self.assertEqual(status, 200)
        decoded = cgss_codec.decode_body(body, self.udid)
        self.assertEqual(decoded["data_headers"]["result_code"], 214)
        self.assertEqual(decoded["data_headers"]["required_res_ver"], "10133800")

    def test_real_http_success_exchange(self) -> None:
        status, body = self._post("10133800")
        self.assertEqual(status, 200)
        decoded = cgss_codec.decode_body(body, self.udid)
        self.assertEqual(decoded["data_headers"]["result_code"], 1)
        self.assertNotIn("required_res_ver", decoded["data_headers"])

    def test_health_and_unknown_route(self) -> None:
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        conn.request("GET", "/healthz")
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"ok\n")
        conn.close()

        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        conn.request("POST", "/load/title", body=b"", headers={"Content-Length": "0"})
        response = conn.getresponse()
        self.assertEqual(response.status, 404)
        response.read()
        conn.close()


if __name__ == "__main__":
    unittest.main()
