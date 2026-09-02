#!/usr/bin/env python3
"""Scan extracted APK analysis targets for high-value CGSS strings.

The scanner performs exact byte searches for a curated set of current/historical
indicators in ASCII/UTF-8 and UTF-16LE representations. It is a triage tool: offsets
are intended to guide IL2CPP metadata/native xref analysis, not replace it.
"""

from __future__ import annotations

import argparse
import json
import mmap
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_INDICATORS = [
    # Current/final resource-plane leads.
    "asset-starlight-stage.akamaized.net",
    "all_dbmanifest",
    "Android_AHigh_SHigh",
    "master.mdb",
    "2022.3.56f1",
    # Historical/current-control-plane candidates.
    "apis.game.starlight-stage.jp",
    "APP-VER",
    "RES-VER",
    "PARAM",
    "SID",
    "UDID",
    "USER-ID",
    "DEVICE-ID",
    "DEVICE-NAME",
    "X-Unity-Version",
    "viewer_id",
    "timezone",
    "data_headers",
    # Serialization / crypto / HTTP stack indicators.
    "MessagePack",
    "msgpack",
    "Rijndael",
    "AES",
    "UnityWebRequest",
    "libcurl",
    # Local data/resource implementation indicators.
    "PlayerPrefs",
    "SQLite",
    "sqlcipher",
    "AssetBundle",
    "CriWare",
]


def find_all(mm: mmap.mmap, needle: bytes, limit: int) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < limit:
        pos = mm.find(needle, start)
        if pos < 0:
            break
        offsets.append(pos)
        start = pos + max(1, len(needle))
    return offsets


def scan_file(path: Path, indicators: list[str], per_encoding_limit: int) -> list[dict]:
    if path.stat().st_size == 0:
        return []

    hits: list[dict] = []
    with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        for indicator in indicators:
            encodings = {
                "ascii": indicator.encode("utf-8"),
                "utf16le": indicator.encode("utf-16le"),
            }
            for encoding, needle in encodings.items():
                offsets = find_all(mm, needle, per_encoding_limit)
                if offsets:
                    hits.append(
                        {
                            "indicator": indicator,
                            "encoding": encoding,
                            "count_capped": len(offsets) == per_encoding_limit,
                            "offsets": offsets,
                        }
                    )
    return hits


def collect_files(root: Path) -> list[Path]:
    return sorted(
        p
        for p in root.rglob("*")
        if p.is_file() and p.name not in {"analysis-targets.json", "string-scan.json"}
    )


def scan(root: Path, indicators: list[str], per_encoding_limit: int = 100) -> dict:
    files = collect_files(root)
    result_files = []
    for path in files:
        hits = scan_file(path, indicators, per_encoding_limit)
        if hits:
            result_files.append(
                {
                    "path": str(path.relative_to(root)),
                    "size": path.stat().st_size,
                    "hits": hits,
                }
            )

    return {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": str(root.resolve()),
        "indicators": indicators,
        "files": result_files,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan extracted CGSS APK analysis targets for protocol/resource strings"
    )
    parser.add_argument(
        "root",
        type=Path,
        nargs="?",
        default=Path("work/analysis-targets"),
        help="analysis-target directory (default: work/analysis-targets)",
    )
    parser.add_argument(
        "--indicator",
        action="append",
        dest="indicators",
        help="additional/alternate exact indicator; repeatable. If supplied, replaces defaults.",
    )
    parser.add_argument(
        "--max-hits",
        type=int,
        default=100,
        help="maximum offsets per indicator/encoding/file (default: 100)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="output JSON path (default: <root>/string-scan.json)",
    )
    args = parser.parse_args()

    if not args.root.is_dir():
        parser.error(f"analysis root is not a directory: {args.root}")
    if args.max_hits < 1:
        parser.error("--max-hits must be >= 1")

    indicators = args.indicators or DEFAULT_INDICATORS
    report = scan(args.root, indicators, args.max_hits)
    out = args.output or args.root / "string-scan.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    total_groups = sum(len(f["hits"]) for f in report["files"])
    print(f"Matched {total_groups} indicator/encoding group(s) in {len(report['files'])} file(s).")
    print(f"Wrote: {out}")
    for file_record in report["files"]:
        names = sorted({hit["indicator"] for hit in file_record["hits"]})
        print(f"  {file_record['path']}: {', '.join(names)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
