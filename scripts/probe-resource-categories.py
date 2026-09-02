#!/usr/bin/env python3
"""Probe CGSS CDN category directories for manifest-backed resource hashes.

This tool is intentionally non-archival: it selects real manifest objects, probes
candidate CDN category paths, and records only HTTP status/headers plus at most a
single response byte. It never writes game resource bodies.

Two request modes are used because Akamai behavior is not uniform across object
families: a valid object may reject a Range request while accepting an ordinary
GET. A category is considered successful when either mode returns HTTP 200/206
and yields one response byte. Wrong category paths observed so far return 403.
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
REQUEST_MODES = ("range", "plain_get_prefix")


def select_examples(manifest: Path, suffix: str, *, limit: int = 1) -> list[tuple[str, str]]:
    conn = sqlite3.connect(f"file:{manifest.as_posix()}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT name, hash FROM manifests WHERE lower(name) LIKE ? ORDER BY name LIMIT ?",
            ("%" + suffix.lower(), max(int(limit), 1)),
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        raise ValueError(f"manifest has no resource ending in {suffix!r}")
    return [(str(name), str(digest).lower()) for name, digest in rows]


def probe(
    category: str,
    digest: str,
    *,
    mode: str,
    timeout: float = 20.0,
) -> dict[str, Any]:
    if mode not in REQUEST_MODES:
        raise ValueError(f"unsupported probe mode: {mode!r}")

    path = f"/dl/resources/{category}/{digest[:2]}/{digest}"
    headers = {
        "User-Agent": USER_AGENT,
        "X-Unity-Version": UNITY_VERSION,
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if mode == "range":
        headers["Range"] = "bytes=0-0"

    request = urllib.request.Request(CDN_BASE + path, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            # The ordinary GET path intentionally reads exactly one byte and then
            # closes the socket. This distinguishes Range policy from a category
            # miss without turning the probe into an asset downloader.
            body_prefix = response.read(1)
            return {
                "mode": mode,
                "category": category,
                "path": path,
                "status": int(getattr(response, "status", 200)),
                "content_length": response.headers.get("Content-Length"),
                "content_range": response.headers.get("Content-Range"),
                "received_prefix_bytes": len(body_prefix),
            }
    except urllib.error.HTTPError as exc:
        return {
            "mode": mode,
            "category": category,
            "path": path,
            "status": int(exc.code),
            "content_length": exc.headers.get("Content-Length") if exc.headers else None,
            "content_range": exc.headers.get("Content-Range") if exc.headers else None,
            "received_prefix_bytes": 0,
        }
    except urllib.error.URLError as exc:
        return {
            "mode": mode,
            "category": category,
            "path": path,
            "status": None,
            "error": f"{type(exc).__name__}: {exc}",
            "received_prefix_bytes": 0,
        }


def probe_category(category: str, digest: str, *, timeout: float) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    range_result = probe(category, digest, mode="range", timeout=timeout)
    attempts.append(range_result)

    # A successful range response already proves the path. Only retry with a
    # one-byte ordinary GET when Range did not establish the category.
    range_success = (
        range_result.get("status") in {200, 206}
        and int(range_result.get("received_prefix_bytes", 0)) == 1
    )
    if not range_success:
        attempts.append(probe(category, digest, mode="plain_get_prefix", timeout=timeout))

    success = any(
        attempt.get("status") in {200, 206}
        and int(attempt.get("received_prefix_bytes", 0)) == 1
        for attempt in attempts
    )
    return {
        "category": category,
        "success": success,
        "attempts": attempts,
    }


def resolve_successful_categories(samples: list[dict[str, Any]]) -> list[str]:
    successful: set[str] = set()
    for sample in samples:
        for candidate in sample["candidates"]:
            if candidate.get("success"):
                successful.add(str(candidate["category"]))
    return sorted(successful)


def probe_suffixes(
    manifest: Path,
    suffixes: list[str],
    *,
    timeout: float = 20.0,
    samples_per_suffix: int = 1,
) -> dict[str, Any]:
    results: dict[str, Any] = {}
    for suffix in suffixes:
        samples: list[dict[str, Any]] = []
        for name, digest in select_examples(manifest, suffix, limit=samples_per_suffix):
            candidates = [
                probe_category(category, digest, timeout=timeout)
                for category in CANDIDATE_CATEGORIES
            ]
            samples.append({"name": name, "hash": digest, "candidates": candidates})
        successful = resolve_successful_categories(samples)
        results[suffix] = {
            "successful_categories": successful,
            "samples": samples,
        }
    return {
        "cdn_base": CDN_BASE,
        "unity_version_header": UNITY_VERSION,
        "request_modes": list(REQUEST_MODES),
        "samples_per_suffix": max(int(samples_per_suffix), 1),
        "suffixes": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe CGSS CDN category directories using manifest-backed hashes")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--suffix", action="append", default=[])
    parser.add_argument("--samples", type=int, default=1, help="manifest-backed samples per suffix")
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--allow-unresolved", action="store_true", help="write the report but exit zero for ambiguous suffixes")
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    suffixes = args.suffix or list(DEFAULT_SUFFIXES)
    report = probe_suffixes(
        args.manifest,
        suffixes,
        timeout=args.timeout,
        samples_per_suffix=max(args.samples, 1),
    )
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
        return 0 if args.allow_unresolved else 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
