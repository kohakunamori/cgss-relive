from __future__ import annotations

import http.client
import threading
import unittest

from server import cgss_codec
from server.http_server import create_server
from server.minimal_profile import (
    HOME_CANDIDATE_EMPTY_LIST_SECTIONS,
    build_home_candidate_load_index_data,
)


def synthetic_header_encode(value: str) -> str:
    groups = "".join("12" + chr(ord(ch) + 10) + "3" for ch in value)
    return f"{len(value):04x}" + groups + ("7" * 32)


class HomeCandidateHTTPTests(unittest.TestCase):
    def test_home_candidate_survives_wire_round_trip(self) -> None:
        udid = "00112233-4455-6677-8899-aabbccddeeff"
        profile = build_home_candidate_load_index_data(
            viewer_id=123,
            producer_name="Relive Home",
            now=456,
        )
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
                udid,
                dynamic_key=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
            )
            headers = {
                "Content-Type": "application/octet-stream",
                "UDID": synthetic_header_encode(udid),
                "RES-VER": "10133800",
                "SID": "synthetic-sid",
                "APP-VER": "11.6.3",
            }
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("POST", "/load/index", body=body, headers=headers)
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            decoded = cgss_codec.decode_body(response.read(), udid)
            conn.close()

            self.assertEqual(decoded["data_headers"]["result_code"], 1)
            self.assertEqual(decoded["data_headers"]["sid"], "synthetic-sid")
            self.assertEqual(decoded["data"]["user_info"]["tutorial_flag"], 100)
            for section in HOME_CANDIDATE_EMPTY_LIST_SECTIONS:
                self.assertEqual(decoded["data"][section], [])
            self.assertEqual(decoded["data"]["music_list"], {"normal": []})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
