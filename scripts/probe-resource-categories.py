#!/usr/bin/env python3
"""Probe CGSS CDN category directories for manifest-backed resource hashes.

This tool is intentionally non-archival: it selects one real manifest object per
requested suffix, makes a tiny range request against candidate CDN categories,
and records only HTTP status/headers. It never writes game resource bodies.

A unique successful candidate is useful evidence for a suffix -> CDN directory
mapping. A result is not promoted into the archive mapping automatically; that is
an explicit review step.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CDN_BASE = "https://asset-starlight-stage.akamaized.net"
UNITY_VERSION = "2022.3.56f1"
USER_AGENT = f"UnityPlayer/{UNITY_VERSION} (UnityWebRequest/1.0, libcurl/8.10.1-DEV)"
CANDIDATE_CATEGORIES = ("AssetBundles", "Sound", "Movie", "Generic")
DEFAULT_SUFFIXES = (".unity3d", ".acb", ".awb", ".usm", ".bdb", ".bytes", ".mdb")


def select_example(manifest: Path, suffix: str) -> tuple[str, str]:
    conn = sqlite3.connect(f"file:{manifest.as_posix()}?mode=ro", uri=True)
    try:
        row = conn.execute(
            "SELECT name, hash FROM manifests WHERE lower(name) LIKE ? ORDER BY name LIMIT 1",
            ("%" + suffix.lower(),),
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise ValueError(f"manifest has no resource ending in {suffix!r}")
    return str(row[0]), str(row[1]).lower()


def probe(category: str, digest: str, *, timeout: float = 20.0) -> dict[str, Any]:
    path = f"/dl/resources/{category}/{digest[:2]}/{digest}"
    request = urllib.request.Request(
        CDN_BASE + path,
        headers={
            "User-Agent": USER_AGENT,
            "X-Unity-Version": UNITY_VERSION,
            "Range": "bytes=0-0",
            "Accept-Encoding": "identity",
            "Connection": "close",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            # Read only a single byte even if this CDN ignores Range and returns
            # 200. Closing the response prevents the probe from becoming an asset
            # downloader.
            body_prefix = response.read(1)
            return {
                "category": category,
                "path": path,
                "status": int(getattr(response, "status", 200)),
                "content_length": response.headers.get("Content-Length"),
                "content_range": response.headers.get("Content-Range"),
                "received_prefix_bytes": len(body_prefix),
            }
    except urllib.error.HTTPError as exc:
        return {
            "category": category,
            "path": path,
            "status": int(exc.code),
            "content_length": exc.headers.get("Content-Length") if exc.headers else None,
            "content_range": exc.headers.get("Content-Range") if exc.headers else None,
            "received_prefix_bytes": 0,
        }
    except urllib.error.URLError as exc:
        return {
            "category": category,
            "path": path,
            "status": None,
            "error": f"{type(exc).__name__}: {exc}",
            "received_prefix_bytes": 0,
        }


def probe_suffixes(manifest: Path, suffixes: list[str], *, timeout: float = 20.0) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for suffix in suffixes:
        name, digest = select_example(manifest, suffix)
        candidates = [probe(category, digest, timeout=timeout) for category in CANDIDATE_CATEGORIES]
        successful = [
            candidate["category"]
            for candidate in candidates
            if candidate.get("status") in {200, 206}
        ]
        results[suffix] = {
            "name": name,
            "hash": digest,
            "successful_categories": successful,
            "candidates": candidates,
        }
    return {
        "cdn_base": CDN_BASE,
        "unity_version_header": UNITY_VERSION,
        "suffixes": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe CGSS CDN category directories using manifest-backed hashes")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--suffix", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    suffixes = args.suffix or list(DEFAULT_SUFFIXES)
    report = probe_suffixes(args.manifest, suffixes, timeout=args.timeout)
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)

    ambiguous = [
        suffix
        for suffix, item in report["suffixes"].items()
        if len(item["successful_categories"]) != 1
    ]
    if ambiguous:
        print("ambiguous/unresolved suffixes: " + ", ".join(ambiguous))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
