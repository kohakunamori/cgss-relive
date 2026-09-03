#!/usr/bin/env python3
"""Materialize the preserved final 11.6.3 ApiType map payload.

The repository stores the authoritative derived endpoint metadata as a gzip+base64
text payload to keep connector-based commits compact. This script performs no
reconstruction or guessing: it only decodes the checked-in payload and validates
its exact A/B key coverage via ``validate-api-map.py`` semantics.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path

from validate_api_map import validate_map

EXPECTED_SOURCE_SHA256 = "5d2655d40adaeab08ee6331a5a19f59f119809b47ee8571b23f16893a39766d5"
EXPECTED_SEMANTIC_SHA256 = "8e8711e62e53645d994ab4d2d2cec3db6994e45ccb252b068df960b9bd51bcd9"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("payload", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    encoded = "".join(args.payload.read_text(encoding="ascii").split())
    raw = gzip.decompress(base64.b64decode(encoded, validate=True))
    obj = json.loads(raw.decode("utf-8"))
    report = validate_map(obj)

    canonical = json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n"
    semantic_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if semantic_sha != EXPECTED_SEMANTIC_SHA256:
        raise RuntimeError(
            f"semantic ApiType map digest mismatch: {semantic_sha} != {EXPECTED_SEMANTIC_SHA256}"
        )
    if report["groups"] != {"A": 516, "B": 22}:
        raise RuntimeError(f"unexpected ApiType group sizes: {report['groups']!r}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(canonical, encoding="utf-8")
    print(
        json.dumps(
            {
                "groups": report["groups"],
                "semantic_sha256": semantic_sha,
                "delivered_source_sha256": EXPECTED_SOURCE_SHA256,
                "note": "source SHA identifies the original delivered final_map.json; semantic SHA identifies the normalized checked-in payload",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
