#!/usr/bin/env python3
"""Fetch and verify the CGSS resource manifest and master database.

The downloaded game databases are proprietary artifacts and are written under work/
by default. They are not intended to be committed to this repository.

This implements the currently documented CGSS resource bootstrap flow:
  all_dbmanifest -> Android_AHigh_SHigh -> manifest SQLite -> master.mdb
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import struct
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

CDN_BASE = "https://asset-starlight-stage.akamaized.net"
INFO_URL = "https://starlight.kirara.ca/api/v1/info"
DEFAULT_RESOURCE_VERSION = 10133800
UNITY_VERSION = "2022.3.56f1"  # current community-observed resource request UA; verify against APK
USER_AGENT = f"UnityPlayer/{UNITY_VERSION} (UnityWebRequest/1.0, libcurl/8.10.1-DEV)"

ANDROID_MANIFEST_NAME = "Android_AHigh_SHigh"
SQLITE_MAGIC = b"SQLite format 3\x00"


class BootstrapError(RuntimeError):
    pass


def request(url: str, *, unity_headers: bool = True) -> urllib.request.Request:
    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if unity_headers:
        headers["User-Agent"] = USER_AGENT
        headers["X-Unity-Version"] = UNITY_VERSION
    else:
        headers["User-Agent"] = "cgss-relive-resource-bootstrap/0.1"
    return urllib.request.Request(url, headers=headers, method="GET")


def fetch_bytes(url: str, *, unity_headers: bool = True, timeout: int = 60) -> bytes:
    try:
        with urllib.request.urlopen(request(url, unity_headers=unity_headers), timeout=timeout) as r:
            if getattr(r, "status", 200) != 200:
                raise BootstrapError(f"HTTP {r.status}: {url}")
            return r.read()
    except urllib.error.URLError as exc:
        raise BootstrapError(f"request failed: {url}: {exc}") from exc


def fetch_latest_resource_version(timeout: int = 30) -> int:
    payload = fetch_bytes(INFO_URL, unity_headers=False, timeout=timeout)
    try:
        obj = json.loads(payload.decode("utf-8"))
        version = int(obj["truth_version"])
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise BootstrapError("could not parse truth_version from Starlight Database info API") from exc
    if version <= 0:
        raise BootstrapError(f"invalid truth_version: {version}")
    return version


def parse_android_manifest_md5(data: bytes) -> str:
    # all_dbmanifest is a small comma-separated text index. Match the current
    # Android high-quality manifest entry and capture its 32-hex-digit MD5.
    text = data.decode("utf-8", errors="replace")
    pattern = rf"(?:^|\r?\n){re.escape(ANDROID_MANIFEST_NAME)},([0-9a-fA-F]{{32}}),"
    match = re.search(pattern, text)
    if not match:
        # Be tolerant of an index that does not begin entries at a line boundary.
        match = re.search(rf"{re.escape(ANDROID_MANIFEST_NAME)},([0-9a-fA-F]{{32}}),", text)
    if not match:
        raise BootstrapError(f"{ANDROID_MANIFEST_NAME} hash not found in all_dbmanifest")
    return match.group(1).lower()


def cgss_lz4_decompress(raw: bytes) -> bytes:
    """Decode the CGSS 16-byte wrapper plus a raw LZ4 block.

    The uncompressed size is a little-endian uint32 at offset 4 and the raw
    LZ4 block starts at offset 16.
    """
    if len(raw) < 16:
        raise BootstrapError("CGSS LZ4 payload is shorter than 16-byte wrapper")

    expected_size = struct.unpack_from("<I", raw, 4)[0]
    src = memoryview(raw)[16:]
    pos = 0
    out = bytearray()

    def read_length(base: int) -> int:
        nonlocal pos
        length = base
        if base == 15:
            while True:
                if pos >= len(src):
                    raise BootstrapError("truncated LZ4 extended length")
                value = int(src[pos])
                pos += 1
                length += value
                if value != 255:
                    break
        return length

    while pos < len(src):
        token = int(src[pos])
        pos += 1

        literal_length = read_length(token >> 4)
        if pos + literal_length > len(src):
            raise BootstrapError("truncated LZ4 literal run")
        out.extend(src[pos : pos + literal_length])
        pos += literal_length

        # Final sequence can consist only of literals.
        if pos == len(src):
            break
        if pos + 2 > len(src):
            raise BootstrapError("truncated LZ4 match offset")

        offset = int(src[pos]) | (int(src[pos + 1]) << 8)
        pos += 2
        if offset <= 0 or offset > len(out):
            raise BootstrapError(f"invalid LZ4 match offset: {offset}")

        match_length = read_length(token & 0x0F) + 4
        for _ in range(match_length):
            # Byte-wise copy intentionally supports overlapping match ranges.
            out.append(out[-offset])
            if len(out) > expected_size:
                raise BootstrapError("LZ4 output exceeded wrapper-declared size")

    if len(out) != expected_size:
        raise BootstrapError(
            f"LZ4 size mismatch: wrapper={expected_size}, decoded={len(out)}"
        )
    return bytes(out)


def hash_file(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_file(url: str, dest: Path, *, timeout: int = 90) -> tuple[int, str]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    md5 = hashlib.md5()
    total = 0
    try:
        with urllib.request.urlopen(request(url), timeout=timeout) as r, dest.open("wb") as f:
            if getattr(r, "status", 200) != 200:
                raise BootstrapError(f"HTTP {r.status}: {url}")
            while True:
                chunk = r.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                md5.update(chunk)
                total += len(chunk)
    except urllib.error.URLError as exc:
        dest.unlink(missing_ok=True)
        raise BootstrapError(f"download failed: {url}: {exc}") from exc
    return total, md5.hexdigest()


def verify_sqlite(path: Path) -> None:
    with path.open("rb") as f:
        magic = f.read(len(SQLITE_MAGIC))
    if magic != SQLITE_MAGIC:
        raise BootstrapError(f"decoded file is not SQLite: {path}")
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
            result = db.execute("PRAGMA quick_check").fetchone()
            if not result or result[0] != "ok":
                raise BootstrapError(f"SQLite quick_check failed for {path}: {result}")
    except sqlite3.DatabaseError as exc:
        raise BootstrapError(f"SQLite validation failed for {path}: {exc}") from exc


def decode_verified_payload(compressed: Path, expected_md5: str, output: Path) -> dict:
    actual_md5 = hash_file(compressed, "md5")
    if actual_md5.lower() != expected_md5.lower():
        raise BootstrapError(
            f"MD5 mismatch for {compressed.name}: expected={expected_md5}, actual={actual_md5}"
        )

    raw = compressed.read_bytes()
    decoded = cgss_lz4_decompress(raw)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("wb", dir=output.parent, delete=False) as tmp:
        tmp.write(decoded)
        tmp_path = Path(tmp.name)
    try:
        verify_sqlite(tmp_path)
        tmp_path.replace(output)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    return {
        "compressed_size": len(raw),
        "compressed_md5": actual_md5.lower(),
        "decoded_size": len(decoded),
        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
    }


def get_master_hash(manifest_db: Path) -> str:
    try:
        with sqlite3.connect(f"file:{manifest_db}?mode=ro", uri=True) as db:
            row = db.execute(
                "SELECT hash FROM manifests WHERE name = ? LIMIT 1", ("master.mdb",)
            ).fetchone()
    except sqlite3.DatabaseError as exc:
        raise BootstrapError(f"failed to query {manifest_db}: {exc}") from exc
    if not row or not row[0]:
        raise BootstrapError("master.mdb was not found in manifests table")
    value = str(row[0]).lower()
    if not re.fullmatch(r"[0-9a-f]{32}", value):
        raise BootstrapError(f"unexpected master.mdb hash: {value!r}")
    return value


def fetch_bootstrap(version: int, output_dir: Path, *, include_master: bool = True, force: bool = False) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    index_url = f"{CDN_BASE}/dl/{version}/manifests/all_dbmanifest"
    manifest_url = f"{CDN_BASE}/dl/{version}/manifests/{ANDROID_MANIFEST_NAME}"

    print(f"[1/4] Fetching all_dbmanifest for resource version {version}")
    index = fetch_bytes(index_url)
    index_path = output_dir / "all_dbmanifest.txt"
    index_path.write_bytes(index)
    manifest_md5 = parse_android_manifest_md5(index)
    print(f"      {ANDROID_MANIFEST_NAME} MD5: {manifest_md5}")

    manifest_db = output_dir / f"manifest_{version}.db"
    manifest_compressed = output_dir / f"manifest_{version}.db.lz4"
    if force or not manifest_db.exists():
        print("[2/4] Downloading and validating resource manifest")
        _, downloaded_md5 = download_file(manifest_url, manifest_compressed)
        if downloaded_md5.lower() != manifest_md5:
            raise BootstrapError(
                f"manifest download MD5 mismatch: expected={manifest_md5}, actual={downloaded_md5}"
            )
        manifest_meta = decode_verified_payload(manifest_compressed, manifest_md5, manifest_db)
        manifest_compressed.unlink(missing_ok=True)
    else:
        print(f"[2/4] Reusing existing {manifest_db.name}")
        verify_sqlite(manifest_db)
        manifest_meta = {
            "compressed_md5": manifest_md5,
            "decoded_size": manifest_db.stat().st_size,
            "decoded_sha256": hash_file(manifest_db, "sha256"),
            "reused": True,
        }

    master_md5 = get_master_hash(manifest_db)
    master_url = f"{CDN_BASE}/dl/resources/Generic/{master_md5[:2]}/{master_md5}"
    master_db = output_dir / "master.mdb"
    master_meta = None

    if include_master:
        master_compressed = output_dir / "master.mdb.lz4"
        if force or not master_db.exists():
            print("[3/4] Downloading and validating master.mdb")
            _, downloaded_md5 = download_file(master_url, master_compressed)
            if downloaded_md5.lower() != master_md5:
                raise BootstrapError(
                    f"master download MD5 mismatch: expected={master_md5}, actual={downloaded_md5}"
                )
            master_meta = decode_verified_payload(master_compressed, master_md5, master_db)
            master_compressed.unlink(missing_ok=True)
        else:
            print("[3/4] Reusing existing master.mdb")
            verify_sqlite(master_db)
            master_meta = {
                "compressed_md5": master_md5,
                "decoded_size": master_db.stat().st_size,
                "decoded_sha256": hash_file(master_db, "sha256"),
                "reused": True,
            }
    else:
        print("[3/4] master.mdb download skipped")

    report = {
        "schema": 1,
        "resource_version": version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "unity_version_header": UNITY_VERSION,
        "cdn_base": CDN_BASE,
        "index": {
            "url": index_url,
            "size": len(index),
            "sha256": hashlib.sha256(index).hexdigest(),
        },
        "manifest": {
            "name": ANDROID_MANIFEST_NAME,
            "url": manifest_url,
            "expected_compressed_md5": manifest_md5,
            "path": str(manifest_db),
            **manifest_meta,
        },
        "master": {
            "url": master_url,
            "expected_compressed_md5": master_md5,
            "path": str(master_db),
            **(master_meta or {"downloaded": False}),
        },
    }

    report_path = output_dir / "resource-bootstrap.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[4/4] Wrote {report_path}")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch CGSS manifest/master bootstrap data with verification")
    version_group = parser.add_mutually_exclusive_group()
    version_group.add_argument(
        "--version",
        type=int,
        default=DEFAULT_RESOURCE_VERSION,
        help=f"resource version (default: {DEFAULT_RESOURCE_VERSION})",
    )
    version_group.add_argument(
        "--latest",
        action="store_true",
        help="query starlight.kirara.ca for truth_version instead of using the frozen default",
    )
    parser.add_argument("-o", "--output", type=Path, default=Path("work/resources"))
    parser.add_argument("--manifest-only", action="store_true", help="do not download master.mdb")
    parser.add_argument("--force", action="store_true", help="redownload existing databases")
    args = parser.parse_args()

    try:
        version = fetch_latest_resource_version() if args.latest else args.version
        if version <= 0:
            raise BootstrapError(f"invalid resource version: {version}")
        fetch_bootstrap(
            version,
            args.output,
            include_master=not args.manifest_only,
            force=args.force,
        )
        return 0
    except BootstrapError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
