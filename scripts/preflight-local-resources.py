#!/usr/bin/env python3
"""Preflight a local final 10133800 resource cache without exposing game data.

The report contains only invariant/count/status information. It never emits
resource names, hashes, manifest rows, database contents, or object bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import struct
from pathlib import Path

FINAL_RESOURCE_VERSION = "10133800"
EXPECTED_MANIFEST_ROWS = 220837
EXPECTED_UNIQUE_HASHES = 220803
WIRE_MANIFESTS = ("all_dbmanifest", "Android_AHigh_SHigh")
ANDROID_MANIFEST_NAME = "Android_AHigh_SHigh"
MASTER_MANIFEST_NAME = "master.mdb"
SQLITE_MAGIC = b"SQLite format 3\x00"


class WireManifestError(ValueError):
    """Raised when the frozen bootstrap wire chain is malformed."""


def open_manifest_readonly(path: Path) -> sqlite3.Connection:
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def inspect_manifest(path: Path) -> tuple[list[str], int, list[str]]:
    with open_manifest_readonly(path) as connection:
        quick_check = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
        row_count = int(connection.execute("SELECT COUNT(*) FROM manifests").fetchone()[0])
        hashes = [str(row[0]).lower() for row in connection.execute("SELECT DISTINCT hash FROM manifests")]
    return quick_check, row_count, hashes


def read_manifest_hash(path: Path, name: str) -> str | None:
    with open_manifest_readonly(path) as connection:
        row = connection.execute(
            "SELECT hash FROM manifests WHERE name = ? LIMIT 1",
            (name,),
        ).fetchone()
    return str(row[0]).lower() if row else None


def validate_hash(value: str) -> bool:
    if len(value) != 32:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def parse_android_manifest_md5(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    pattern = rf"(?:^|\r?\n){re.escape(ANDROID_MANIFEST_NAME)},([0-9a-fA-F]{{32}}),"
    match = re.search(pattern, text)
    if not match:
        match = re.search(rf"{re.escape(ANDROID_MANIFEST_NAME)},([0-9a-fA-F]{{32}}),", text)
    if not match:
        raise WireManifestError("android manifest entry missing from wire index")
    return match.group(1).lower()


def cgss_lz4_decompress(raw: bytes) -> bytes:
    if len(raw) < 16:
        raise WireManifestError("wire manifest is shorter than CGSS wrapper")

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
                    raise WireManifestError("truncated LZ4 extended length")
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
            raise WireManifestError("truncated LZ4 literal run")
        out.extend(src[pos : pos + literal_length])
        pos += literal_length

        if pos == len(src):
            break
        if pos + 2 > len(src):
            raise WireManifestError("truncated LZ4 match offset")
        offset = int(src[pos]) | (int(src[pos + 1]) << 8)
        pos += 2
        if offset <= 0 or offset > len(out):
            raise WireManifestError("invalid LZ4 match offset")

        match_length = read_length(token & 0x0F) + 4
        for _ in range(match_length):
            out.append(out[-offset])
            if len(out) > expected_size:
                raise WireManifestError("LZ4 output exceeded wrapper-declared size")

    if len(out) != expected_size:
        raise WireManifestError("LZ4 decoded size does not match wrapper")
    return bytes(out)


def hash_file(path: Path, algorithm: str) -> bytes:
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()


def verify_wire_manifest_chain(wire_dir: Path, manifest_db: Path) -> tuple[dict[str, bool], list[str]]:
    status = {
        "index_parsed": False,
        "android_wire_md5_matches_index": False,
        "android_wire_decodes": False,
        "decoded_is_sqlite": False,
        "decoded_matches_manifest_db": False,
    }
    failures: list[str] = []
    index_path = wire_dir / WIRE_MANIFESTS[0]
    android_path = wire_dir / WIRE_MANIFESTS[1]
    if not index_path.is_file() or not android_path.is_file() or not manifest_db.is_file():
        return status, failures

    try:
        expected_md5 = parse_android_manifest_md5(index_path.read_bytes())
    except (OSError, WireManifestError):
        failures.append("wire_index_invalid")
        return status, failures
    status["index_parsed"] = True

    try:
        compressed = android_path.read_bytes()
    except OSError:
        failures.append("wire_android_manifest_unreadable")
        return status, failures
    actual_md5 = hashlib.md5(compressed).hexdigest()
    if actual_md5.lower() != expected_md5:
        failures.append("wire_android_manifest_md5_mismatch")
        return status, failures
    status["android_wire_md5_matches_index"] = True

    try:
        decoded = cgss_lz4_decompress(compressed)
    except WireManifestError:
        failures.append("wire_android_manifest_decode_failed")
        return status, failures
    status["android_wire_decodes"] = True

    if not decoded.startswith(SQLITE_MAGIC):
        failures.append("wire_android_manifest_not_sqlite")
        return status, failures
    status["decoded_is_sqlite"] = True

    try:
        matches = hashlib.sha256(decoded).digest() == hash_file(manifest_db, "sha256")
    except OSError:
        failures.append("manifest_db_unreadable")
        return status, failures
    if not matches:
        failures.append("wire_manifest_db_mismatch")
        return status, failures
    status["decoded_matches_manifest_db"] = True
    return status, failures


def verify_master_object(root: Path, manifest_db: Path) -> tuple[dict[str, bool], list[str]]:
    status = {
        "manifest_entry_present": False,
        "object_present": False,
        "md5_matches_manifest": False,
    }
    failures: list[str] = []
    if not manifest_db.is_file():
        return status, failures

    try:
        digest = read_manifest_hash(manifest_db, MASTER_MANIFEST_NAME)
    except (sqlite3.Error, OSError):
        failures.append("manifest_db_unreadable")
        return status, failures
    if digest is None or not validate_hash(digest):
        failures.append("master_manifest_entry_invalid")
        return status, failures
    status["manifest_entry_present"] = True

    path = root / "objects" / digest[:2] / digest
    if not path.is_file():
        failures.append("master_object_missing")
        return status, failures
    status["object_present"] = True

    try:
        matches = hash_file(path, "md5").hex() == digest
    except OSError:
        failures.append("master_object_unreadable")
        return status, failures
    if not matches:
        failures.append("master_object_md5_mismatch")
        return status, failures
    status["md5_matches_manifest"] = True
    return status, failures


def run_preflight(root: Path, manifest_db: Path, *, version: str) -> dict[str, object]:
    root = root.resolve()
    manifest_db = manifest_db.resolve()
    report: dict[str, object] = {
        "schema": 3,
        "resource_version": str(version),
        "expected": {
            "manifest_rows": EXPECTED_MANIFEST_ROWS,
            "unique_hashes": EXPECTED_UNIQUE_HASHES,
            "wire_manifests": len(WIRE_MANIFESTS),
        },
    }
    failures: list[str] = []

    if str(version) != FINAL_RESOURCE_VERSION:
        failures.append("resource_version_mismatch")

    manifest_exists = manifest_db.is_file()
    report["manifest_db_present"] = manifest_exists
    hashes: list[str] = []
    quick_check: list[str] = []
    row_count = 0
    if not manifest_exists:
        failures.append("manifest_db_missing")
    else:
        try:
            quick_check, row_count, hashes = inspect_manifest(manifest_db)
        except (sqlite3.Error, OSError):
            failures.append("manifest_db_unreadable")
        else:
            if quick_check != ["ok"]:
                failures.append("manifest_db_quick_check_failed")
            if row_count != EXPECTED_MANIFEST_ROWS:
                failures.append("manifest_row_count_mismatch")
            if len(hashes) != EXPECTED_UNIQUE_HASHES:
                failures.append("manifest_unique_hash_count_mismatch")
            if any(not validate_hash(value) for value in hashes):
                failures.append("manifest_contains_invalid_hash")

    report["manifest"] = {
        "quick_check": quick_check,
        "rows": row_count,
        "unique_hashes": len(hashes),
    }

    wire_dir = root / "manifests"
    wire_present = sum(1 for name in WIRE_MANIFESTS if (wire_dir / name).is_file())
    report["wire_manifests_present"] = wire_present
    if wire_present != len(WIRE_MANIFESTS):
        failures.append("wire_manifest_missing")
    wire_chain, wire_failures = verify_wire_manifest_chain(wire_dir, manifest_db)
    report["wire_chain"] = wire_chain
    failures.extend(wire_failures)

    object_root = root / "objects"
    missing_objects = 0
    zero_length_objects = 0
    present_objects = 0
    if hashes:
        for digest in hashes:
            if not validate_hash(digest):
                continue
            path = object_root / digest[:2] / digest
            try:
                stat = path.stat()
            except OSError:
                missing_objects += 1
                continue
            if not path.is_file():
                missing_objects += 1
                continue
            present_objects += 1
            if stat.st_size <= 0:
                zero_length_objects += 1
    elif manifest_exists:
        failures.append("object_check_skipped_no_hashes")

    report["objects"] = {
        "expected": len(hashes),
        "present": present_objects,
        "missing": missing_objects,
        "zero_length": zero_length_objects,
    }
    if missing_objects:
        failures.append("resource_objects_missing")
    if zero_length_objects:
        failures.append("resource_objects_zero_length")
    if hashes and present_objects != len(hashes):
        failures.append("resource_object_count_mismatch")

    master_status, master_failures = verify_master_object(root, manifest_db)
    report["master_object"] = master_status
    failures.extend(master_failures)

    report["failures"] = sorted(set(failures))
    report["ready"] = not failures
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the local final CGSS resource cache before rooted-device integration"
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest-db", type=Path, required=True)
    parser.add_argument("--version", default=FINAL_RESOURCE_VERSION)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    report = run_preflight(args.root, args.manifest_db, version=args.version)
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
