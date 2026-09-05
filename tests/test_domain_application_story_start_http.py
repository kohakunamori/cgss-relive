from __future__ import annotations

import http.client
import threading
import unittest

from server import cgss_codec
from server.application import StoryStartController
from server.application_http import create_application_server


def synthetic_header_encode(value: str) -> str:
    groups = "".join("12" + chr(ord(ch) + 10) + "3" for ch in value)
    return f"{len(value):04x}" + groups + ("7" * 32)


class StoryStartHTTPIntegrationTests(unittest.TestCase):
    def test_encrypted_story_start_uses_exact_story_id_and_parser_safe_empty_data(self) -> None:
        server = create_application_server(
            "127.0.0.1",
            0,
            application_handlers={"/story/start": StoryStartController()},
            final_res_ver="10133800",
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address[:2]
        udid = "00112233-4455-6677-8899-aabbccddeeff"
        headers = {
            "Content-Type": "application/octet-stream",
            "UDID": synthetic_header_encode(udid),
            "RES-VER": "10133800",
            "SID": "synthetic-sid",
            "APP-VER": "11.6.3",
        }

        def encode(request: dict) -> bytes:
            return cgss_codec.encode_body(
                request,
                udid,
                dynamic_key=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
            )

        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("POST", "/story/start", body=encode({"story_id": 123}), headers=headers)
            response = conn.getresponse()
            payload = response.read()
            self.assertEqual(response.status, 200, payload)
            decoded = cgss_codec.decode_body(payload, udid)
            conn.close()

            self.assertEqual(decoded["data_headers"]["result_code"], 1)
            self.assertEqual(decoded["data"], {})

            # Managed/native evidence proves an Int32 story_id.  A string must fail
            # before any compatibility response is emitted.
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("POST", "/story/start", body=encode({"story_id": "123"}), headers=headers)
            response = conn.getresponse()
            payload = response.read()
            self.assertEqual(response.status, 400, payload)
            conn.close()

            # Missing story_id is likewise not silently normalized or defaulted.
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("POST", "/story/start", body=encode({}), headers=headers)
            response = conn.getresponse()
            payload = response.read()
            self.assertEqual(response.status, 400, payload)
            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
