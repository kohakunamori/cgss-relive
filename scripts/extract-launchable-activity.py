#!/usr/bin/env python3
"""Extract only launchable-activity identity from APK `aapt dump badging` output.

The helper is intended for the exact hash-verified final XAPK workflow. It scans
split APKs but emits no APK filename/path, full manifest, labels, icons,
permissions or other package metadata.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

_PACKAGE_RE = re.compile(
    r"^package:\s+name='(?P<name>[^']+)'\s+versionCode='(?P<code>[^']+)'\s+versionName='(?P<version>[^']*)'"
)
_LAUNCH_RE = re.compile(r"^launchable-activity:\s+name='(?P<name>[^']+)'(?:\s|$)")


def parse_badging(text: str) -> tuple[dict[str, str] | None, list[str]]:
    package: dict[str, str] | None = None
    launchable: list[str] = []
    for line in text.splitlines():
        if package is None:
            match = _PACKAGE_RE.match(line)
            if match:
                package = match.groupdict()
                continue
        match = _LAUNCH_RE.match(line)
        if match:
            launchable.append(match.group("name"))
    return package, launchable


def extract(
    aapt: Path,
    apk_root: Path,
    *,
    package_name: str,
    version_name: str,
    version_code: str,
) -> dict[str, object]:
    matching_apks = 0
    activities: set[str] = set()
    for apk in sorted(apk_root.rglob("*.apk")):
        process = subprocess.run(
            [str(aapt), "dump", "badging", str(apk)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if process.returncode != 0:
            continue
        package, launchable = parse_badging(process.stdout)
        # Drop the full aapt text immediately after parsing the two whitelisted
        # line types. It is never written to the report.
        process.stdout = ""
        if package is None:
            continue
        if (
            package["name"] != package_name
            or package["version"] != version_name
            or package["code"] != str(version_code)
        ):
            continue
        matching_apks += 1
        activities.update(launchable)

    sorted_activities = sorted(activities)
    return {
        "schema": 1,
        "package": package_name,
        "version_name": version_name,
        "version_code": int(version_code),
        "matching_split_apks": matching_apks,
        "launchable_activity_count": len(sorted_activities),
        "launchable_activities": sorted_activities,
        "unique": len(sorted_activities) == 1,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract sanitized launchable-activity identity from exact final split APKs"
    )
    parser.add_argument("--aapt", type=Path, required=True)
    parser.add_argument("--apk-root", type=Path, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--version-name", required=True)
    parser.add_argument("--version-code", required=True)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    if not args.aapt.is_file():
        parser.error("--aapt does not exist")
    report = extract(
        args.aapt,
        args.apk_root,
        package_name=args.package,
        version_name=args.version_name,
        version_code=args.version_code,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "matching_split_apks": report["matching_split_apks"],
                "launchable_activity_count": report["launchable_activity_count"],
                "unique": report["unique"],
            },
            sort_keys=True,
        )
    )
    return 0 if report["unique"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
