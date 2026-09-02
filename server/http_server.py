"""Minimal HTTP/TLS front end for the CGSS preservation bootstrap.

Early bootstrap routes are deliberately thin adapters over :mod:`bootstrap_core`
so socket/TLS choices remain independent from reconstructed CGSS contracts.
"""
from __future__ import annotations

import argparse
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Type

from .bootstrap_core import (
    process_load_check_request,
    process_load_index_request,
    process_load_title_request,
)
from .load_check import FINAL_RESOURCE_VERSION

MAX_REQUEST_BODY = 8 * 1024 * 1024


def make_handler(
    final_res_ver: str = FINAL_RESOURCE_VERSION,
    load_index_data: Mapping[str, Any] | None = None,
) -> Type[BaseHTTPRequestHandler]:
    class CGSSBootstrapHandler(BaseHTTPRequestHandler):
        server_version = "cgss-relive/0.1"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args: object) -> None:
            super().log_message(fmt, *args)

        def _send_bytes(self, status: int, body: bytes, content_type: str = "application/octet-stream") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                self._send_bytes(200, b"ok\n", "text/plain; charset=utf-8")
                return
            self._send_bytes(404, b"not found\n", "text/plain; charset=utf-8")

        def do_POST(self) -> None:  # noqa: N802
            route = self.path.split("?", 1)[0]
            if route not in {"/load/check", "/load/index", "/load/title"}:
                self._send_bytes(404, b"not found\n", "text/plain; charset=utf-8")
                return
            if route == "/load/index" and load_index_data is None:
                self._send_bytes(503, b"load/index profile is not configured\n", "text/plain; charset=utf-8")
                return

            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                self._send_bytes(411, b"content-length required\n", "text/plain; charset=utf-8")
                return
            try:
                length = int(raw_length)
            except ValueError:
                self._send_bytes(400, b"invalid content-length\n", "text/plain; charset=utf-8")
                return
            if length < 0 or length > MAX_REQUEST_BODY:
                self._send_bytes(413, b"request body too large\n", "text/plain; charset=utf-8")
                return

            body = self.rfile.read(length)
            headers = {key: value for key, value in self.headers.items()}
            try:
                if route == "/load/check":
                    exchange = process_load_check_request(
                        headers,
                        body,
                        final_res_ver=final_res_ver,
                    )
                elif route == "/load/title":
                    exchange = process_load_title_request(headers, body)
                else:
                    assert load_index_data is not None
                    exchange = process_load_index_request(headers, body, data=load_index_data)
            except (ValueError, UnicodeError) as exc:
                message = f"invalid CGSS {route.lstrip('/')} request: {type(exc).__name__}\n".encode("ascii")
                self._send_bytes(400, message, "text/plain; charset=utf-8")
                return

            self._send_bytes(200, exchange.response_body)

    return CGSSBootstrapHandler


def create_server(
    host: str,
    port: int,
    *,
    final_res_ver: str = FINAL_RESOURCE_VERSION,
    load_index_data: Mapping[str, Any] | None = None,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(final_res_ver, load_index_data))
    server.daemon_threads = True
    return server


def _load_profile(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("load/index profile JSON must contain an object at its root")
    # Accept either the data map itself or a complete captured/synthetic response.
    if "data_headers" in value and "data" in value:
        data = value["data"]
        if not isinstance(data, dict):
            raise ValueError("load/index profile response has a non-object data field")
        return data
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the cgss-relive bootstrap endpoints")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--final-res-ver", default=FINAL_RESOURCE_VERSION)
    parser.add_argument(
        "--load-index-profile",
        type=Path,
        help="local JSON object used as /load/index data; proprietary profiles must stay uncommitted",
    )
    parser.add_argument("--cert", help="PEM certificate chain for HTTPS")
    parser.add_argument("--key", help="PEM private key for HTTPS")
    args = parser.parse_args()

    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be supplied together")

    load_index_data = None
    if args.load_index_profile:
        try:
            load_index_data = _load_profile(args.load_index_profile)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(f"failed to load --load-index-profile: {exc}")

    httpd = create_server(
        args.host,
        args.port,
        final_res_ver=args.final_res_ver,
        load_index_data=load_index_data,
    )
    scheme = "http"
    if args.cert and args.key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    bound_host, bound_port = httpd.server_address[:2]
    print(f"cgss-relive bootstrap listening on {scheme}://{bound_host}:{bound_port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
