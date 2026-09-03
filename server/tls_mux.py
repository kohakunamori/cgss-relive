"""Single-port TLS reverse proxy for rooted final-client integration.

The untouched Android client reaches multiple original HTTPS hostnames on port
443. ``adb reverse tcp:443`` can expose only one host destination, so this helper
terminates one multi-SAN test certificate and dispatches by the original HTTP
Host header to local plain-HTTP control/resource backends.

The mux intentionally does not log request paths, headers, bodies, query strings,
or backend response bodies. Sanitized runtime evidence remains the responsibility
of the control/resource servers themselves.
"""
from __future__ import annotations

import argparse
import http.client
import ssl
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Mapping, Type

DEFAULT_API_HOST = "apis.game.starlight-stage.jp"
DEFAULT_RESOURCE_HOST = "storages.game.starlight-stage.jp"
_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_COPY_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class Backend:
    host: str
    port: int


def parse_backend(value: str) -> Backend:
    host, separator, raw_port = value.rpartition(":")
    if not separator or not host or not raw_port:
        raise ValueError("backend must be HOST:PORT")
    try:
        port = int(raw_port)
    except ValueError as exc:
        raise ValueError("backend port must be an integer") from exc
    if port < 1 or port > 65535:
        raise ValueError("backend port out of range")
    return Backend(host, port)


def normalized_host(value: str | None) -> str | None:
    if not value:
        return None
    host = value.strip().lower()
    if host.startswith("["):
        closing = host.find("]")
        if closing < 0:
            return None
        return host[1:closing]
    if ":" in host:
        host = host.split(":", 1)[0]
    return host or None


def _forward_headers(headers: Mapping[str, str]) -> dict[str, str]:
    forwarded: dict[str, str] = {}
    for name, value in headers.items():
        if name.lower() in _HOP_BY_HOP:
            continue
        forwarded[name] = value
    forwarded["Connection"] = "close"
    return forwarded


def make_handler(routes: Mapping[str, Backend]) -> Type[BaseHTTPRequestHandler]:
    normalized_routes = {host.lower(): backend for host, backend in routes.items()}

    class TLSMuxHandler(BaseHTTPRequestHandler):
        server_version = "cgss-relive-tls-mux/0.1"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:
            # Paths and header/body values may contain sensitive or proprietary
            # material. The backend sanitized logs are the runtime evidence.
            return

        def _send_error_without_path(self, status: int, message: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(message)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(message)
            self.close_connection = True

        def _proxy(self) -> None:
            host = normalized_host(self.headers.get("Host"))
            if host is None or host not in normalized_routes:
                self._send_error_without_path(421, b"unknown host\n")
                return

            transfer_encoding = self.headers.get("Transfer-Encoding")
            if transfer_encoding and transfer_encoding.lower() != "identity":
                self._send_error_without_path(501, b"chunked request body not supported\n")
                return

            raw_length = self.headers.get("Content-Length")
            body: bytes | None = None
            if raw_length is not None:
                try:
                    length = int(raw_length)
                except ValueError:
                    self._send_error_without_path(400, b"invalid content length\n")
                    return
                if length < 0:
                    self._send_error_without_path(400, b"invalid content length\n")
                    return
                body = self.rfile.read(length) if length else b""

            backend = normalized_routes[host]
            connection = http.client.HTTPConnection(backend.host, backend.port, timeout=60)
            try:
                connection.request(
                    self.command,
                    self.path,
                    body=body,
                    headers=_forward_headers(dict(self.headers.items())),
                )
                response = connection.getresponse()
                self.send_response(response.status, response.reason)
                saw_content_length = False
                for name, value in response.getheaders():
                    lower = name.lower()
                    if lower in _HOP_BY_HOP:
                        continue
                    if lower == "content-length":
                        saw_content_length = True
                    self.send_header(name, value)
                if not saw_content_length and self.command == "HEAD":
                    self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()

                if self.command != "HEAD":
                    while True:
                        chunk = response.read(_COPY_CHUNK_SIZE)
                        if not chunk:
                            break
                        self.wfile.write(chunk)
            except (OSError, http.client.HTTPException):
                if not self.wfile.closed:
                    # If headers have already been sent this connection will just
                    # terminate; otherwise provide a generic path-free 502.
                    try:
                        self._send_error_without_path(502, b"backend unavailable\n")
                    except OSError:
                        pass
            finally:
                connection.close()
                self.close_connection = True

        def do_GET(self) -> None:  # noqa: N802
            self._proxy()

        def do_HEAD(self) -> None:  # noqa: N802
            self._proxy()

        def do_POST(self) -> None:  # noqa: N802
            self._proxy()

    return TLSMuxHandler


def create_server(host: str, port: int, routes: Mapping[str, Backend]) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(routes))
    server.daemon_threads = True
    return server


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Terminate one multi-SAN TLS socket and route CGSS original hosts to local backends"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8445)
    parser.add_argument("--cert", required=True, help="multi-SAN PEM certificate chain")
    parser.add_argument("--key", required=True, help="PEM private key")
    parser.add_argument("--api-host", default=DEFAULT_API_HOST)
    parser.add_argument("--resource-host", default=DEFAULT_RESOURCE_HOST)
    parser.add_argument("--api-backend", default="127.0.0.1:8080")
    parser.add_argument("--resource-backend", default="127.0.0.1:8081")
    args = parser.parse_args()

    try:
        routes = {
            args.api_host.lower(): parse_backend(args.api_backend),
            args.resource_host.lower(): parse_backend(args.resource_backend),
        }
    except ValueError as exc:
        parser.error(str(exc))
    if len(routes) != 2:
        parser.error("API and resource hostnames must be distinct")

    server = create_server(args.host, args.port, routes)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    bound_host, bound_port = server.server_address[:2]
    print(f"cgss-relive TLS host mux listening on https://{bound_host}:{bound_port}")
    print(f"{args.api_host} -> http://{routes[args.api_host.lower()].host}:{routes[args.api_host.lower()].port}")
    print(
        f"{args.resource_host} -> "
        f"http://{routes[args.resource_host.lower()].host}:{routes[args.resource_host.lower()].port}"
    )
    print("request paths/headers/bodies are not logged by the mux")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())