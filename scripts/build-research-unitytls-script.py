#!/usr/bin/env python3
"""Build a local Research Frida script with a public CA PEM prelude."""

from __future__ import annotations

import argparse
import json
import pathlib


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ca", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--include", action="append", default=[], type=pathlib.Path)
    args = parser.parse_args()

    pem = args.ca.read_text(encoding="ascii")
    if "-----BEGIN CERTIFICATE-----" not in pem or "-----END CERTIFICATE-----" not in pem:
        parser.error("--ca must contain a PEM certificate")

    parts = [
        "'use strict';\n",
        "globalThis.CGSS_PRESERVATION_CA_PEM = ",
        json.dumps(pem),
        ";\n",
    ]
    for include in args.include:
        parts.append(f"\n// BEGIN {include.as_posix()}\n")
        parts.append(include.read_text(encoding="utf-8"))
        parts.append(f"\n// END {include.as_posix()}\n")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(parts), encoding="utf-8")
    print(f"wrote={args.output}")
    print(f"ca_bytes={len(pem.encode('ascii'))}")
    print(f"include_count={len(args.include)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
