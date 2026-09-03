#!/usr/bin/env python3
"""Inspect a CGSS resource-manifest SQLite database without downloading assets.

The report verifies SQLite integrity, checks the ``manifests`` schema, classifies
CDN categories only for extensions backed by current-final evidence, and reports
any still-unclassified suffix instead of silently guessing a URL.

When the manifest contains a ``category`` column, suffix x declared-category
counts are also recorded. Those values are delivery groups (for example
``every``/``common``), not CDN directory names.

The report also records only aggregate path-shape facts for ``manifests.name``.
It never emits path examples for this purpose. These counts allow the local
resource resolver to prove whether basename-only lookup is sufficient or whether
relative-path suffix matching is required.
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
    ".awb": "Sound",
    ".bytes": "Sound",
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


def _declared_category_key(value: Any) -> str:
    if value is None:
        return "<null>"
    return str(value)


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
        has_declared_category = "category" in column_names

        suffix_counts: collections.Counter[str] = collections.Counter()
        category_counts: collections.Counter[str] = collections.Counter()
        declared_category_counts: collections.Counter[str] = collections.Counter()
        suffix_declared: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
        invalid_hashes: list[dict[str, str]] = []
        unknown: list[dict[str, str]] = []
        total = 0
        unique_names: set[str] = set()
        unique_hashes: set[str] = set()
        names_with_slash = 0
        basename_names: dict[str, set[str]] = collections.defaultdict(set)
        basename_hashes: dict[str, set[str]] = collections.defaultdict(set)

        query = "SELECT name, hash, category FROM manifests ORDER BY name" if has_declared_category else "SELECT name, hash, NULL FROM manifests ORDER BY name"
        for name, digest, declared_category in conn.execute(query):
            name = str(name)
            digest = str(digest)
            total += 1
            unique_names.add(name)
            unique_hashes.add(digest.lower())
            normalized_name = name.replace("\\", "/")
            if "/" in normalized_name:
                names_with_slash += 1
            basename = normalized_name.rsplit("/", 1)[-1]
            basename_names[basename].add(normalized_name)
            basename_hashes[basename].add(digest.lower())
            suffix = suffix_for_name(name)
            suffix_counts[suffix] += 1
            category = category_for_name(name)
            category_counts[category or "<unknown>"] += 1
            if has_declared_category:
                declared_key = _declared_category_key(declared_category)
                declared_category_counts[declared_key] += 1
                suffix_declared[suffix][declared_key] += 1
            if not HASH_RE.fullmatch(digest) and len(invalid_hashes) < unknown_examples:
                invalid_hashes.append({"name": name, "hash": digest})
            if category is None and len(unknown) < unknown_examples:
                example = {"name": name, "hash": digest, "suffix": suffix}
                if has_declared_category:
                    example["declared_category"] = _declared_category_key(declared_category)
                unknown.append(example)

        duplicate_names = conn.execute(
            "SELECT COUNT(*) FROM (SELECT name FROM manifests GROUP BY name HAVING COUNT(*) > 1)"
        ).fetchone()[0]
        duplicate_hash_groups = conn.execute(
            "SELECT COUNT(*) FROM (SELECT hash FROM manifests GROUP BY hash HAVING COUNT(*) > 1)"
        ).fetchone()[0]

        basename_collision_groups = sum(1 for names in basename_names.values() if len(names) > 1)
        basename_hash_conflict_groups = sum(1 for hashes in basename_hashes.values() if len(hashes) > 1)

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
            "name_shape": {
                "names_with_slash": names_with_slash,
                "unique_basenames": len(basename_names),
                "basename_collision_groups": basename_collision_groups,
                "basename_hash_conflict_groups": basename_hash_conflict_groups,
            },
            "master_mdb": {
                "hash": master_hash,
                "resource_path": resource_path("master.mdb", master_hash) if master_hash else None,
            },
            "suffix_counts": dict(sorted(suffix_counts.items(), key=lambda item: (-item[1], item[0]))),
            "category_counts": dict(sorted(category_counts.items())),
            "has_declared_category": has_declared_category,
            "declared_category_counts": dict(sorted(declared_category_counts.items())),
            "suffix_declared_category_counts": {
                suffix: dict(sorted(counter.items()))
                for suffix, counter in sorted(suffix_declared.items())
            },
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
        columns = {row[1] for row in conn.execute("PRAGMA table_info(manifests)")}
        has_declared_category = "category" in columns
        query = "SELECT name, hash, category FROM manifests ORDER BY name" if has_declared_category else "SELECT name, hash, NULL FROM manifests ORDER BY name"
        with catalog_path.open("w", encoding="utf-8") as output:
            for name, digest, declared_category in conn.execute(query):
                name = str(name)
                digest = str(digest).lower()
                row = {
                    "name": name,
                    "hash": digest,
                    "suffix": suffix_for_name(name),
                    "category": category_for_name(name),
                    "resource_path": resource_path(name, digest),
                }
                if has_declared_category:
                    row["declared_category"] = _declared_category_key(declared_category)
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
