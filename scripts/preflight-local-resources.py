#!/usr/bin/env python3
"""Preflight a local final 10133800 resource cache without exposing game data.

The report contains only invariant/count/status information. It never emits
resource names, hashes, manifest rows, database contents, or object bytes.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

FINAL_RESOURCE_VERSION = "10133800"
EXPECTED_MANIFEST_ROWS = 220837
EXPECTED_UNIQUE_HASHES = 220803
WIRE_MANIFESTS = ("all_dbmanifest", "Android_AHigh_SHigh")


def open_manifest_readonly(path: Path) -> sqlite3.Connection:
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    return sqlite3.connect(uri, uri=True)


def inspect_manifest(path: Path) -> tuple[list[str], int, list[str]]:
    with open_manifest_readonly(path) as connection:
        quick_check = [str(row[0]) for row in connection.execute("PRAGMA quick_check")]
        row_count = int(connection.execute("SELECT COUNT(*) FROM manifests").fetchone()[0])
        hashes = [str(row[0]).lower() for row in connection.execute("SELECT DISTINCT hash FROM manifests")]
    return quick_check, row_count, hashes


def validate_hash(value: str) -> bool:
    if len(value) != 32:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def run_preflight(root: Path, manifest_db: Path, *, version: str) -> dict[str, object]:
    root = root.resolve()
    manifest_db = manifest_db.resolve()
    report: dict[str, object] = {
        "schema": 1,
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
