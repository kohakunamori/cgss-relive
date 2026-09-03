#!/usr/bin/env python3
"""Verify that final manifest names round-trip through the local resource resolver.

This is a clean-room coverage check. It reads only ``manifests.name/hash`` from a
local manifest SQLite database and emits aggregate counters; no resource name,
hash, URL, or object bytes are written to the report.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server.resource_server import load_manifest_name_index, resolve_resource_request

FINAL_RESOURCE_VERSION = "10133800"
SUFFIX_CATEGORY = {
    ".unity3d": "AssetBundles",
    ".acb": "Sound",
    ".awb": "Sound",
    ".bytes": "Sound",
    ".usm": "Movie",
    ".bdb": "Generic",
    ".mdb": "Generic",
}


def category_for_name(name: str) -> str | None:
    lower = name.lower()
    for suffix, category in SUFFIX_CATEGORY.items():
        if lower.endswith(suffix):
            return category
    return None


def representative_route(name: str, category: str) -> str:
    # These are structurally valid final-client families. The purpose is to
    # exercise exact manifest-name recovery while including realistic transport
    # prefixes that the resolver must strip before matching manifests.name.
    if category == "AssetBundles":
        return f"/dl/{FINAL_RESOURCE_VERSION}/High/AssetBundles/Android/{name}"
    if category == "Sound":
        return f"/dl/{FINAL_RESOURCE_VERSION}/Sound/Android/{name}"
    if category == "Movie":
        return f"/dl/resources/High/Movie/{name}"
    if category == "Generic":
        return f"/dl/{FINAL_RESOURCE_VERSION}/Generic/Master/{name}"
    raise ValueError(category)


def iter_rows(path: Path) -> Iterable[tuple[str, str]]:
    uri = f"file:{path.resolve().as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        for name, digest in conn.execute("SELECT name, hash FROM manifests ORDER BY name"):
            yield str(name).replace("\\", "/"), str(digest).lower()


def verify_manifest(path: Path) -> dict[str, object]:
    index = load_manifest_name_index(path)
    root = Path("__coverage_only__")
    total = 0
    path_shaped = 0
    resolved = 0
    unresolved = 0
    mismatched = 0
    unknown_category = 0
    categories: dict[str, int] = {}

    for name, expected_digest in iter_rows(path):
        total += 1
        if "/" in name:
            path_shaped += 1
        category = category_for_name(name)
        if category is None:
            unknown_category += 1
            continue
        categories[category] = categories.get(category, 0) + 1
        result = resolve_resource_request(
            root,
            representative_route(name, category),
            version=FINAL_RESOURCE_VERSION,
            manifest_index=index,
        )
        if result is None:
            unresolved += 1
            continue
        _, actual_digest = result
        if actual_digest != expected_digest:
            mismatched += 1
            continue
        resolved += 1

    report: dict[str, object] = {
        "schema": 1,
        "resource_version": FINAL_RESOURCE_VERSION,
        "rows": total,
        "path_shaped_names": path_shaped,
        "resolved": resolved,
        "unresolved": unresolved,
        "mismatched": mismatched,
        "unknown_category": unknown_category,
        "category_rows": dict(sorted(categories.items())),
        "complete": (
            total > 0
            and resolved == total
            and unresolved == 0
            and mismatched == 0
            and unknown_category == 0
        ),
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify aggregate final-manifest coverage of the local filename resolver"
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    report = verify_manifest(args.manifest)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
