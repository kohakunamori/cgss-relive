#!/usr/bin/env python3
"""Safely unpack the APK members from an XAPK archive and fingerprint them."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import zipfile
from pathlib import Path, PurePosixPath


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("xapk", type=Path)
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    result = {
        "source": str(args.xapk),
        "source_sha256": sha256_file(args.xapk),
        "manifest": None,
        "apks": [],
    }

    with zipfile.ZipFile(args.xapk) as archive:
        names = archive.namelist()
        if "manifest.json" in names:
            manifest = json.loads(archive.read("manifest.json").decode("utf-8", "replace"))
            result["manifest"] = manifest
            (args.output / "xapk-manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

        for name in names:
            if not name.lower().endswith(".apk"):
                continue
            if not safe_member(name):
                raise SystemExit(f"unsafe XAPK member: {name}")
            target = args.output / Path(name).name
            with archive.open(name) as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            result["apks"].append(
                {
                    "member": name,
                    "file": target.name,
                    "size": target.stat().st_size,
                    "sha256": sha256_file(target),
                }
            )

    (args.output / "xapk-inspection.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
