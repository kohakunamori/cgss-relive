"""Read-only HTTP/TLS server for the frozen CGSS content-addressed resource archive.

The server intentionally exposes only final resource object URLs of the form::

    /dl/resources/<Category>/<hh>/<md5>

and maps them to the preservation archive layout::

    <root>/objects/<hh>/<md5>

It does not synthesize manifest/bootstrap responses.  Redirecting the production
asset hostname should remain a runtime-driven integration step.
"""
from __future__ import annotations

import argparse
import re
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Type
from urllib.parse import urlsplit

RESOURCE_CATEGORIES = ("AssetBundles", "Sound", "Movie", "Generic")
_RESOURCE_ROUTE_RE = re.compile(
    r"^/dl/resources/(AssetBundles|Sound|Movie|Generic)/([0-9A-Fa-f]{2})/([0-9A-Fa-f]{32})$"
)
_COPY_CHUNK_SIZE = 1024 * 1024


class RangeNotSatisfiable(ValueError):
    """Raised when a single HTTP byte-range cannot be satisfied."""


def object_path(root: Path, digest: str) -> Path:
    digest = digest.lower()
    return root / "objects" / digest[:2] / digest


def resolve_resource_request(root: Path, request_path: str) -> tuple[Path, str] | None:
    """Resolve one canonical CGSS resource URL to its local archive object."""
    path = urlsplit(request_path).path
    match = _RESOURCE_ROUTE_RE.fullmatch(path)
    if match is None:
        return None
    _category, prefix, digest = match.groups()
    digest = digest.lower()
    if prefix.lower() != digest[:2]:
        return None
    return object_path(root, digest), digest


def parse_single_range(value: str | None, size: int) -> tuple[int, int] | None:
    """Parse a single RFC 7233-style ``bytes`` range.

    Returns an inclusive ``(start, end)`` pair, ``None`` for no range, and raises
    :class:`RangeNotSatisfiable` for malformed, multiple, or out-of-bounds ranges.
    """
    if value is None:
        return None
    if size <= 0 or not value.startswith("bytes="):
        raise RangeNotSatisfiable(value)
    spec = value[6:].strip()
    if not spec or "," in spec or "-" not in spec:
        raise RangeNotSatisfiable(value)
    first, last = spec.split("-", 1)
    try:
        if not first:
            suffix = int(last)
            if suffix <= 0:
                raise RangeNotSatisfiable(value)
            length = min(suffix, size)
            return size - length, size - 1
        start = int(first)
        if start < 0 or start >= size:
            raise RangeNotSatisfiable(value)
        if not last:
            return start, size - 1
        end = int(last)
        if end < start:
            raise RangeNotSatisfiable(value)
        return start, min(end, size - 1)
    except ValueError as exc:
        if isinstance(exc, RangeNotSatisfiable):
            raise
        raise RangeNotSatisfiable(value) from exc


def make_handler(root: Path) -> Type[BaseHTTPRequestHandler]:
    archive_root = Path(root)

    class CGSSResourceHandler(BaseHTTPRequestHandler):
        server_version = "cgss-relive-resource/0.1"
        protocol_version = "HTTP/1.1"

        def _send_plain(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            self.close_connection = True

        def _serve_resource(self, *, send_body: bool) -> None:
            resolved = resolve_resource_request(archive_root, self.path)
            if resolved is None:
                self._send_plain(404, b"not found\n")
                return
            path, digest = resolved
            if not path.is_file():
                self._send_plain(404, b"not found\n")
                return

            size = path.stat().st_size
            try:
                byte_range = parse_single_range(self.headers.get("Range"), size)
            except RangeNotSatisfiable:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{size}")
                self.send_header("Content-Length", "0")
                self.send_header("Accept-Ranges", "bytes")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                return

            status = 200
            start = 0
            end = size - 1
            if byte_range is not None:
                status = 206
                start, end = byte_range
            length = 0 if size == 0 else end - start + 1

            self.send_response(status)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(length))
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("ETag", f'"{digest}"')
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
            if byte_range is not None:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.send_header("Connection", "close")
            self.end_headers()

            if send_body and length:
                remaining = length
                with path.open("rb") as stream:
                    stream.seek(start)
                    while remaining:
                        chunk = stream.read(min(_COPY_CHUNK_SIZE, remaining))
                        if not chunk:
                            break
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
            self.close_connection = True

        def do_GET(self) -> None:  # noqa: N802
            if urlsplit(self.path).path == "/healthz":
                self._send_plain(200, b"ok\n")
                return
            self._serve_resource(send_body=True)

        def do_HEAD(self) -> None:  # noqa: N802
            if urlsplit(self.path).path == "/healthz":
                self._send_plain(200, b"ok\n")
                return
            self._serve_resource(send_body=False)

    return CGSSResourceHandler


def create_server(host: str, port: int, *, root: Path) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), make_handler(Path(root)))
    server.daemon_threads = True
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve archived CGSS resource objects read-only")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("resource-cache/10133800"),
        help="archive root containing objects/<hh>/<md5>",
    )
    parser.add_argument("--cert", help="PEM certificate chain for HTTPS")
    parser.add_argument("--key", help="PEM private key for HTTPS")
    args = parser.parse_args()

    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be supplied together")

    httpd = create_server(args.host, args.port, root=args.root)
    scheme = "http"
    if args.cert and args.key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    bound_host, bound_port = httpd.server_address[:2]
    print(f"cgss-relive resource archive listening on {scheme}://{bound_host}:{bound_port}")
    print(f"archive root: {args.root}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
