from __future__ import annotations

import http.client
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from server.tls_mux import Backend, create_server, normalized_host, parse_backend


class _BackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    label = b"backend"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _reply(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._reply(self.label + b":" + self.headers.get("Host", "").encode())

    def do_HEAD(self) -> None:  # noqa: N802
        self._reply(b"head")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self._reply(self.label + b":" + body)


class TLSMuxTests(unittest.TestCase):
    def setUp(self) -> None:
        class APIHandler(_BackendHandler):
            label = b"api"

        class ResourceHandler(_BackendHandler):
            label = b"resource"

        self.api = ThreadingHTTPServer(("127.0.0.1", 0), APIHandler)
        self.resource = ThreadingHTTPServer(("127.0.0.1", 0), ResourceHandler)
        self.api.daemon_threads = True
        self.resource.daemon_threads = True
        self.api_thread = threading.Thread(target=self.api.serve_forever, daemon=True)
        self.resource_thread = threading.Thread(target=self.resource.serve_forever, daemon=True)
        self.api_thread.start()
        self.resource_thread.start()

        routes = {
            "apis.game.starlight-stage.jp": Backend("127.0.0.1", self.api.server_port),
            "storages.game.starlight-stage.jp": Backend("127.0.0.1", self.resource.server_port),
        }
        self.mux = create_server("127.0.0.1", 0, routes)
        self.mux_thread = threading.Thread(target=self.mux.serve_forever, daemon=True)
        self.mux_thread.start()

    def tearDown(self) -> None:
        for server in (self.mux, self.api, self.resource):
            server.shutdown()
            server.server_close()
        for thread in (self.mux_thread, self.api_thread, self.resource_thread):
            thread.join(timeout=2)

    def request(
        self,
        method: str,
        host: str,
        *,
        body: bytes | None = None,
    ) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.mux.server_port, timeout=5)
        headers = {"Host": host}
        if body is not None:
            headers["Content-Length"] = str(len(body))
        connection.request(method, "/opaque-test-path", body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        connection.close()
        return status, payload

    def test_routes_api_host_and_preserves_original_host(self) -> None:
        status, body = self.request("GET", "apis.game.starlight-stage.jp")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"api:apis.game.starlight-stage.jp")

    def test_routes_resource_host_with_port_suffix(self) -> None:
        status, body = self.request("GET", "storages.game.starlight-stage.jp:443")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"resource:storages.game.starlight-stage.jp:443")

    def test_forwards_post_body_without_interpreting_it(self) -> None:
        status, body = self.request("POST", "apis.game.starlight-stage.jp", body=b"encrypted-body")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"api:encrypted-body")

    def test_unknown_host_is_rejected(self) -> None:
        status, body = self.request("GET", "example.invalid")
        self.assertEqual(status, 421)
        self.assertEqual(body, b"unknown host\n")

    def test_backend_and_host_parsers(self) -> None:
        self.assertEqual(parse_backend("127.0.0.1:8080"), Backend("127.0.0.1", 8080))
        self.assertEqual(normalized_host("Example.COM:443"), "example.com")
        with self.assertRaises(ValueError):
            parse_backend("missing-port")
        with self.assertRaises(ValueError):
            parse_backend("localhost:99999")


if __name__ == "__main__":
    unittest.main()