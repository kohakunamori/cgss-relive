#!/usr/bin/env python3
"""Inspect a CGSS resource-manifest SQLite database without downloading assets.

The report is designed for preservation work: it verifies SQLite integrity,
checks the ``manifests`` schema, classifies the CDN category for extensions whose
current final-resource routing has been independently observed, and reports every
unclassified suffix rather than silently guessing a URL.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")

CATEGORY_BY_SUFFIX = {
    ".unity3d": "AssetBundles",
    ".acb": "Sound",
    ".usm": "Movie",
    ".bdb": "Generic",
    ".mdb": "Generic",
}


def suffix_for_name(name: str) -> str:
    lower = name.lower()
    for suffix in sorted(CATEGORY_BY_SUFFIX, key=len, reverse=True):
        if lower.endswith(suffix):
            return suffix
    base = name.rsplit("/", 1)[-1]
    if "." not in base:
        return "<none>"
    return "." + base.rsplit(".", 1)[-1].lower()


def category_for_name(name: str) -> str | None:
    return CATEGORY_BY_SUFFIX.get(suffix_for_name(name))


def resource_path(name: str, digest: str) -> str | None:
    category = category_for_name(name)
    if category is None or not HASH_RE.fullmatch(digest):
        return None
    digest = digest.lower()
    return f"/dl/resources/{category}/{digest[:2]}/{digest}"


def inspect_manifest(path: Path, *, unknown_examples: int = 50) -> dict[str, Any]:
    raw_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        quick_check = [row[0] for row in conn.execute("PRAGMA quick_check")]
        tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        if "manifests" not in tables:
            raise ValueError("SQLite database does not contain a manifests table")

        columns = [
            {"cid": row[0], "name": row[1], "type": row[2], "notnull": bool(row[3]), "pk": bool(row[5])}
            for row in conn.execute("PRAGMA table_info(manifests)")
        ]
        column_names = {column["name"] for column in columns}
        if not {"name", "hash"}.issubset(column_names):
            raise ValueError("manifests table is missing required name/hash columns")

        suffix_counts: collections.Counter[str] = collections.Counter()
        category_counts: collections.Counter[str] = collections.Counter()
        invalid_hashes: list[dict[str, str]] = []
        unknown: list[dict[str, str]] = []
        total = 0
        unique_names: set[str] = set()
        unique_hashes: set[str] = set()

        for name, digest in conn.execute("SELECT name, hash FROM manifests ORDER BY name"):
            name = str(name)
            digest = str(digest)
            total += 1
            unique_names.add(name)
            unique_hashes.add(digest.lower())
            suffix = suffix_for_name(name)
            suffix_counts[suffix] += 1
            category = category_for_name(name)
            category_counts[category or "<unknown>"] += 1
            if not HASH_RE.fullmatch(digest) and len(invalid_hashes) < unknown_examples:
                invalid_hashes.append({"name": name, "hash": digest})
            if category is None and len(unknown) < unknown_examples:
                unknown.append({"name": name, "hash": digest, "suffix": suffix})

        duplicate_names = conn.execute(
            "SELECT COUNT(*) FROM (SELECT name FROM manifests GROUP BY name HAVING COUNT(*) > 1)"
        ).fetchone()[0]
        duplicate_hash_groups = conn.execute(
            "SELECT COUNT(*) FROM (SELECT hash FROM manifests GROUP BY hash HAVING COUNT(*) > 1)"
        ).fetchone()[0]

        master = conn.execute("SELECT hash FROM manifests WHERE name='master.mdb' LIMIT 1").fetchone()
        master_hash = str(master[0]).lower() if master else None

        return {
            "database": str(path),
            "sha256": raw_sha256,
            "quick_check": quick_check,
            "tables": tables,
            "manifests_columns": columns,
            "rows": total,
            "unique_names": len(unique_names),
            "unique_hashes": len(unique_hashes),
            "duplicate_name_groups": int(duplicate_names),
            "duplicate_hash_groups": int(duplicate_hash_groups),
            "master_mdb": {
                "hash": master_hash,
                "resource_path": resource_path("master.mdb", master_hash) if master_hash else None,
            },
            "suffix_counts": dict(sorted(suffix_counts.items(), key=lambda item: (-item[1], item[0]))),
            "category_counts": dict(sorted(category_counts.items())),
            "invalid_hash_examples": invalid_hashes,
            "unknown_category_examples": unknown,
        }
    finally:
        conn.close()


def write_catalog(db_path: Path, catalog_path: Path) -> int:
    """Write one normalized manifest entry per JSONL line."""
    catalog_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)
    count = 0
    try:
        with catalog_path.open("w", encoding="utf-8") as output:
            for name, digest in conn.execute("SELECT name, hash FROM manifests ORDER BY name"):
                name = str(name)
                digest = str(digest).lower()
                row = {
                    "name": name,
                    "hash": digest,
                    "suffix": suffix_for_name(name),
                    "category": category_for_name(name),
                    "resource_path": resource_path(name, digest),
                }
                output.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                count += 1
    finally:
        conn.close()
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect a CGSS resource manifest SQLite database")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--catalog", type=Path, help="optional normalized JSONL catalog output")
    parser.add_argument("--unknown-examples", type=int, default=50)
    args = parser.parse_args()

    report = inspect_manifest(args.manifest, unknown_examples=max(args.unknown_examples, 0))
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    if args.catalog:
        count = write_catalog(args.manifest, args.catalog)
        print(f"catalog rows: {count} -> {args.catalog}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
