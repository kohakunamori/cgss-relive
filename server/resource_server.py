"""Read-only HTTP/TLS server for a frozen CGSS resource archive.

The archive itself stays content-addressed::

    <root>/objects/<hh>/<md5>

while the HTTP front end accepts the URL families reconstructed from the final
Android 11.6.3 client.  Hash-addressed requests can be resolved without a
manifest database.  Filename-addressed storage URLs require an optional local
final manifest SQLite database; that database remains uncommitted/proprietary.

Verified bootstrap manifest files may optionally be placed under::

    <root>/manifests/<filename>

and are exposed as ``/dl/<version>/manifests/<filename>`` only for the configured
frozen resource version.
"""
from __future__ import annotations

import argparse
import re
import sqlite3
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Mapping, Type
from urllib.parse import unquote, urlsplit

RESOURCE_CATEGORIES = ("AssetBundles", "Sound", "Movie", "Generic")
_HEX32_RE = re.compile(r"^[0-9A-Fa-f]{32}$")
_COPY_CHUNK_SIZE = 1024 * 1024

# Final-client URL families reconstructed from CustomPreference/AssetHandle.
# The path matcher is deliberately structural rather than a single CDN layout.
_RESOURCE_PATH_RE = re.compile(
    r"^/dl/(?:(?P<version>[0-9]+)/)?(?P<resources>resources/)?"
    r"(?:(?P<quality>Low|High)/)?"
    r"(?P<category>AssetBundles|Sound|Movie|Generic)/(?P<tail>.+)$"
)
_MANIFEST_PATH_RE = re.compile(r"^/dl/(?P<version>[0-9]+)/manifests/(?P<name>[^/]+)$")


class RangeNotSatisfiable(ValueError):
    """Raised when a single HTTP byte-range cannot be satisfied."""


def object_path(root: Path, digest: str) -> Path:
    digest = digest.lower()
    return root / "objects" / digest[:2] / digest


def load_manifest_name_index(path: Path) -> dict[str, str]:
    """Load ``name -> compressed md5`` from a final manifest SQLite database."""
    uri = f"file:{Path(path).resolve().as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        rows = conn.execute("SELECT name, hash FROM manifests").fetchall()
    index: dict[str, str] = {}
    for name, digest in rows:
        if not isinstance(name, str) or not isinstance(digest, str) or not _HEX32_RE.fullmatch(digest):
            raise ValueError("manifest contains an invalid name/hash row")
        previous = index.setdefault(name, digest.lower())
        if previous != digest.lower():
            raise ValueError(f"manifest name maps to multiple hashes: {name}")
    return index


def _digest_from_tail(tail: str, manifest_index: Mapping[str, str] | None) -> str | None:
    """Resolve a BuildURL tail to a compressed archive digest.

    Final CDN forms may contain ``<prefix>/<hash>``.  Storage forms may use a
    bare hash or a manifest filename; compressed filename forms may append
    ``.lz4``.  Filename resolution is intentionally unavailable without a local
    manifest index.
    """
    parts = [unquote(part) for part in tail.split("/") if part]
    if not parts:
        return None
    leaf = parts[-1]
    candidates = [leaf]
    if leaf.endswith(".lz4"):
        candidates.append(leaf[:-4])

    for candidate in candidates:
        if _HEX32_RE.fullmatch(candidate):
            digest = candidate.lower()
            if len(parts) >= 2 and _HEX32_RE.fullmatch(parts[-2]) is None and re.fullmatch(r"[0-9A-Fa-f]{2}", parts[-2]):
                if parts[-2].lower() != digest[:2]:
                    return None
            return digest

    if manifest_index is None:
        return None
    for candidate in candidates:
        digest = manifest_index.get(candidate)
        if digest is not None and _HEX32_RE.fullmatch(digest):
            return digest.lower()
    return None


def resolve_resource_request(
    root: Path,
    request_path: str,
    *,
    version: str = "10133800",
    manifest_index: Mapping[str, str] | None = None,
) -> tuple[Path, str | None] | None:
    """Resolve one statically-supported final-client resource URL."""
    path = urlsplit(request_path).path

    manifest_match = _MANIFEST_PATH_RE.fullmatch(path)
    if manifest_match is not None:
        if manifest_match.group("version") != str(version):
            return None
        name = unquote(manifest_match.group("name"))
        if name in {".", ".."} or "/" in name or "\\" in name:
            return None
        candidate = root / "manifests" / name
        return candidate, None

    match = _RESOURCE_PATH_RE.fullmatch(path)
    if match is None:
        return None
    request_version = match.group("version")
    uses_resources = match.group("resources") is not None
    category = match.group("category")

    # Versioned regular forms must match the frozen archive.  The final client's
    # Movie and hush/resource forms intentionally omit a version segment.
    if request_version is not None and request_version != str(version):
        return None
    if request_version is None and not uses_resources:
        return None

    # Statistically impossible combinations are rejected rather than silently
    # broadening the server into an arbitrary file oracle.
    if category == "Movie" and request_version is not None:
        return None

    digest = _digest_from_tail(match.group("tail"), manifest_index)
    if digest is None:
        return None
    return object_path(root, digest), digest


def parse_single_range(value: str | None, size: int) -> tuple[int, int] | None:
    """Parse a single RFC 7233-style ``bytes`` range."""
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


def make_handler(
    root: Path,
    *,
    version: str = "10133800",
    manifest_index: Mapping[str, str] | None = None,
) -> Type[BaseHTTPRequestHandler]:
    archive_root = Path(root)
    frozen_version = str(version)
    name_index = dict(manifest_index or {})

    class CGSSResourceHandler(BaseHTTPRequestHandler):
        server_version = "cgss-relive-resource/0.2"
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
            resolved = resolve_resource_request(
                archive_root,
                self.path,
                version=frozen_version,
                manifest_index=name_index,
            )
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
            if digest is not None:
                self.send_header("ETag", f'"{digest}"')
                self.send_header("Cache-Control", "public, max-age=31536000, immutable")
            else:
                self.send_header("Cache-Control", "no-cache")
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


def create_server(
    host: str,
    port: int,
    *,
    root: Path,
    version: str = "10133800",
    manifest_index: Mapping[str, str] | None = None,
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(
        (host, port),
        make_handler(Path(root), version=version, manifest_index=manifest_index),
    )
    server.daemon_threads = True
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="Serve archived CGSS resources read-only")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--version", default="10133800")
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("resource-cache/10133800"),
        help="archive root containing objects/<hh>/<md5> and optional manifests/",
    )
    parser.add_argument(
        "--manifest-db",
        type=Path,
        help="optional final manifest SQLite DB for filename-addressed storages URLs; keep it uncommitted",
    )
    parser.add_argument("--cert", help="PEM certificate chain for HTTPS")
    parser.add_argument("--key", help="PEM private key for HTTPS")
    args = parser.parse_args()

    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be supplied together")
    manifest_index = None
    if args.manifest_db:
        try:
            manifest_index = load_manifest_name_index(args.manifest_db)
        except (OSError, sqlite3.Error, ValueError) as exc:
            parser.error(f"failed to load --manifest-db: {exc}")

    httpd = create_server(
        args.host,
        args.port,
        root=args.root,
        version=args.version,
        manifest_index=manifest_index,
    )
    scheme = "http"
    if args.cert and args.key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    bound_host, bound_port = httpd.server_address[:2]
    print(f"cgss-relive resource archive listening on {scheme}://{bound_host}:{bound_port}")
    print(f"archive root: {args.root}")
    print(f"frozen resource version: {args.version}")
    if args.manifest_db:
        print(f"filename index: {args.manifest_db}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
