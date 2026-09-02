#!/usr/bin/env python3
"""Static APK-set fingerprinting for cgss-relive.

This script intentionally does not extract proprietary payloads. It inventories APKs,
identifies common Unity runtime layouts, hashes relevant files and collects a small
set of static URL/domain strings useful for deciding the next reverse-engineering step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from typing import Iterable

URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,512}")
DOMAIN_RE = re.compile(rb"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]{1,63}\.)+(?:com|net|jp|co\.jp|io|app|cloudfront\.net)(?![A-Za-z0-9.-])", re.I)
UNITY_VERSION_RE = re.compile(rb"(?<!\d)(20\d{2}|5)\.\d{1,2}\.\d{1,2}[abfp]\d{1,3}(?!\d)")

INTERESTING_STRING_FILES = (
    "classes.dex",
    "classes2.dex",
    "classes3.dex",
    "assets/bin/Data/globalgamemanagers",
    "assets/bin/Data/Managed/Assembly-CSharp.dll",
    "assets/bin/Data/Managed/Metadata/global-metadata.dat",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def printable(value: bytes) -> str:
    return value.decode("utf-8", errors="ignore").rstrip("\x00")


def collect_strings(data: bytes) -> tuple[set[str], set[str], set[str]]:
    urls = {printable(m.group(0)) for m in URL_RE.finditer(data)}
    domains = {printable(m.group(0)).lower() for m in DOMAIN_RE.finditer(data)}
    versions = {printable(m.group(0)) for m in UNITY_VERSION_RE.finditer(data)}
    return urls, domains, versions


def apk_paths(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(p for p in target.iterdir() if p.is_file() and p.suffix.lower() == ".apk")


def inspect_one(path: Path) -> dict:
    report: dict = {
        "file": path.name,
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
        "zip_entries": 0,
        "abis": [],
        "unity": {
            "detected": False,
            "runtime": "unknown",
            "versions_seen": [],
            "has_assembly_csharp": False,
            "has_libil2cpp": False,
            "has_global_metadata": False,
        },
        "relevant_entries": {},
        "static_urls": [],
        "static_domains": [],
    }

    urls: set[str] = set()
    domains: set[str] = set()
    unity_versions: set[str] = set()
    abis: set[str] = set()

    with zipfile.ZipFile(path, "r") as zf:
        names = zf.namelist()
        report["zip_entries"] = len(names)
        name_set = set(names)

        assembly = "assets/bin/Data/Managed/Assembly-CSharp.dll"
        metadata = "assets/bin/Data/Managed/Metadata/global-metadata.dat"
        il2cpp_entries = [n for n in names if n.startswith("lib/") and n.endswith("/libil2cpp.so")]

        report["unity"]["has_assembly_csharp"] = assembly in name_set
        report["unity"]["has_libil2cpp"] = bool(il2cpp_entries)
        report["unity"]["has_global_metadata"] = metadata in name_set
        report["unity"]["detected"] = any(
            n in name_set
            for n in (
                "assets/bin/Data/globalgamemanagers",
                assembly,
                metadata,
            )
        ) or bool(il2cpp_entries)

        if report["unity"]["has_libil2cpp"] and report["unity"]["has_global_metadata"]:
            report["unity"]["runtime"] = "IL2CPP"
        elif report["unity"]["has_assembly_csharp"]:
            report["unity"]["runtime"] = "Mono/managed"

        for n in names:
            if n.startswith("lib/"):
                parts = n.split("/")
                if len(parts) >= 3:
                    abis.add(parts[1])

        interesting = set(INTERESTING_STRING_FILES)
        interesting.update(il2cpp_entries)
        # Split APKs can carry additional DEX files beyond the first three.
        interesting.update(n for n in names if re.fullmatch(r"classes\d*\.dex", n))

        for entry in sorted(interesting):
            if entry not in name_set:
                continue
            info = zf.getinfo(entry)
            # Avoid holding very large native libraries in memory solely for strings.
            # Hash the complete entry stream, but cap string scanning to the first 32 MiB.
            h = hashlib.sha256()
            scan = bytearray()
            with zf.open(info, "r") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
                    if len(scan) < 32 * 1024 * 1024:
                        remaining = 32 * 1024 * 1024 - len(scan)
                        scan.extend(chunk[:remaining])
            report["relevant_entries"][entry] = {
                "size": info.file_size,
                "sha256": h.hexdigest(),
            }
            found_urls, found_domains, found_versions = collect_strings(bytes(scan))
            urls.update(found_urls)
            domains.update(found_domains)
            unity_versions.update(found_versions)

    report["abis"] = sorted(abis)
    report["static_urls"] = sorted(urls)
    report["static_domains"] = sorted(domains)
    report["unity"]["versions_seen"] = sorted(unity_versions)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Fingerprint a CGSS Android APK or split-APK directory")
    parser.add_argument("target", type=Path, help="APK file or directory containing APK files")
    parser.add_argument("-o", "--output", type=Path, help="Output JSON path (default: <target>/inspection.json)")
    args = parser.parse_args()

    target = args.target.resolve()
    if not target.exists():
        parser.error(f"target does not exist: {target}")

    apks = apk_paths(target)
    if not apks:
        parser.error(f"no APK files found under: {target}")

    reports = []
    for apk in apks:
        try:
            reports.append(inspect_one(apk))
        except zipfile.BadZipFile:
            print(f"warning: not a valid APK/ZIP: {apk}", file=sys.stderr)

    aggregate_runtime = "unknown"
    runtimes = {r["unity"]["runtime"] for r in reports if r["unity"]["detected"]}
    if "IL2CPP" in runtimes:
        aggregate_runtime = "IL2CPP"
    elif "Mono/managed" in runtimes:
        aggregate_runtime = "Mono/managed"

    result = {
        "schema": 1,
        "target": str(target),
        "apk_count": len(reports),
        "unity_runtime": aggregate_runtime,
        "apks": reports,
    }

    if args.output:
        out = args.output
    elif target.is_dir():
        out = target / "inspection.json"
    else:
        out = target.with_suffix(target.suffix + ".inspection.json")

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\nWrote: {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
