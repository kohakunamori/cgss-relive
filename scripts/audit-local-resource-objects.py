#!/usr/bin/env python3
"""Full integrity audit for a local content-addressed CGSS resource archive.

Unlike the fast rooted-device preflight, this command computes MD5 for every
unique object referenced by the supplied manifest DB. Output is aggregate only:
no manifest names, object hashes, paths, or resource bytes are emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

FINAL_RESOURCE_VERSION = "10133800"
EXPECTED_UNIQUE_HASHES = 220803


def valid_md5(value: str) -> bool:
    if len(value) != 32:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def iter_unique_hashes(manifest_db: Path):
    uri = f"file:{manifest_db.resolve().as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as connection:
        for row in connection.execute("SELECT DISTINCT lower(hash) FROM manifests ORDER BY lower(hash)"):
            yield str(row[0])


def md5_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit(root: Path, manifest_db: Path, *, expected_unique_hashes: int) -> dict[str, object]:
    root = root.resolve()
    manifest_db = manifest_db.resolve()
    report: dict[str, object] = {
        "schema": 1,
        "resource_version": FINAL_RESOURCE_VERSION,
        "expected_unique_hashes": int(expected_unique_hashes),
    }
    failures: list[str] = []
    checked = 0
    missing = 0
    unreadable = 0
    mismatched = 0
    invalid_manifest_hashes = 0

    if not manifest_db.is_file():
        failures.append("manifest_db_missing")
        hashes: list[str] = []
    else:
        try:
            hashes = list(iter_unique_hashes(manifest_db))
        except (sqlite3.Error, OSError):
            failures.append("manifest_db_unreadable")
            hashes = []

    if len(hashes) != expected_unique_hashes:
        failures.append("unique_hash_count_mismatch")

    for digest in hashes:
        if not valid_md5(digest):
            invalid_manifest_hashes += 1
            continue
        path = root / "objects" / digest[:2] / digest
        if not path.is_file():
            missing += 1
            continue
        try:
            actual = md5_file(path)
        except OSError:
            unreadable += 1
            continue
        checked += 1
        if actual != digest:
            mismatched += 1

    if invalid_manifest_hashes:
        failures.append("invalid_manifest_hash")
    if missing:
        failures.append("objects_missing")
    if unreadable:
        failures.append("objects_unreadable")
    if mismatched:
        failures.append("object_hash_mismatch")
    if hashes and checked + missing + unreadable + invalid_manifest_hashes != len(hashes):
        failures.append("audit_accounting_mismatch")

    report["objects"] = {
        "manifest_unique": len(hashes),
        "checked": checked,
        "missing": missing,
        "unreadable": unreadable,
        "mismatched": mismatched,
        "invalid_manifest_hashes": invalid_manifest_hashes,
    }
    report["failures"] = sorted(set(failures))
    report["complete"] = not failures
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compute MD5 for every object in a frozen local CGSS resource archive"
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest-db", type=Path, required=True)
    parser.add_argument("--version", default=FINAL_RESOURCE_VERSION)
    parser.add_argument("--expected-unique-hashes", type=int, default=EXPECTED_UNIQUE_HASHES)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    if str(args.version) != FINAL_RESOURCE_VERSION:
        report = {
            "schema": 1,
            "resource_version": str(args.version),
            "expected_unique_hashes": int(args.expected_unique_hashes),
            "objects": {
                "manifest_unique": 0,
                "checked": 0,
                "missing": 0,
                "unreadable": 0,
                "mismatched": 0,
                "invalid_manifest_hashes": 0,
            },
            "failures": ["resource_version_mismatch"],
            "complete": False,
        }
    else:
        report = audit(
            args.root,
            args.manifest_db,
            expected_unique_hashes=max(int(args.expected_unique_hashes), 0),
        )

    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
