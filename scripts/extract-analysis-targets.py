#!/usr/bin/env python3
"""Extract only high-value reverse-engineering targets from a CGSS APK set.

This is intentionally *not* a bulk APK decompiler/extractor. It creates a small local
working set for IL2CPP/Unity/DEX analysis and writes hashes/provenance for each file.
All outputs live under work/ by default and must not be committed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

EXACT_TARGETS = {
    "AndroidManifest.xml",
    "assets/bin/Data/boot.config",
    "assets/bin/Data/globalgamemanagers",
    "assets/bin/Data/globalgamemanagers.assets",
    "assets/bin/Data/level0",
    "assets/bin/Data/Managed/Assembly-CSharp.dll",
    "assets/bin/Data/Managed/Metadata/global-metadata.dat",
    "assets/bin/Data/ScriptingAssemblies.json",
}

NATIVE_BASENAMES = {
    "libil2cpp.so",
    "libunity.so",
    "libmain.so",
    "libcri_ware_unity.so",
    "liblz4android.so",
    "libsqlcipher.so",
    "libcyspringandroid.so",
}

DEX_RE = re.compile(r"classes(?:\d+)?\.dex$")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_target(name: str) -> bool:
    if name in EXACT_TARGETS:
        return True
    pure = PurePosixPath(name)
    if len(pure.parts) == 1 and DEX_RE.fullmatch(pure.name):
        return True
    if len(pure.parts) >= 3 and pure.parts[0] == "lib" and pure.name in NATIVE_BASENAMES:
        return True
    return False


def apk_paths(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(p for p in target.iterdir() if p.is_file() and p.suffix.lower() == ".apk")


def safe_output_path(root: Path, apk: Path, member: str) -> Path:
    # Keep split provenance to avoid silently overwriting same-named entries.
    return root / apk.stem / Path(*PurePosixPath(member).parts)


def extract(target: Path, output: Path) -> dict:
    apks = apk_paths(target)
    if not apks:
        raise ValueError(f"no APK files found: {target}")

    output.mkdir(parents=True, exist_ok=True)
    records = []
    runtimes: set[str] = set()

    for apk in apks:
        apk_sha = sha256_file(apk)
        try:
            with zipfile.ZipFile(apk, "r") as zf:
                names = zf.namelist()
                name_set = set(names)
                has_il2cpp = any(
                    PurePosixPath(n).name == "libil2cpp.so" and n.startswith("lib/")
                    for n in names
                )
                has_metadata = "assets/bin/Data/Managed/Metadata/global-metadata.dat" in name_set
                has_managed = "assets/bin/Data/Managed/Assembly-CSharp.dll" in name_set
                if has_il2cpp and has_metadata:
                    runtimes.add("IL2CPP")
                elif has_managed:
                    runtimes.add("Mono/managed")

                for member in names:
                    if not is_target(member):
                        continue
                    info = zf.getinfo(member)
                    dest = safe_output_path(output, apk, member)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info, "r") as src, dest.open("wb") as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)
                    records.append(
                        {
                            "source_apk": apk.name,
                            "source_apk_sha256": apk_sha,
                            "member": member,
                            "output": str(dest.relative_to(output)),
                            "size": dest.stat().st_size,
                            "sha256": sha256_file(dest),
                        }
                    )
        except zipfile.BadZipFile as exc:
            raise ValueError(f"invalid APK/ZIP: {apk}") from exc

    runtime = "unknown"
    if "IL2CPP" in runtimes:
        runtime = "IL2CPP"
    elif "Mono/managed" in runtimes:
        runtime = "Mono/managed"

    report = {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": str(target.resolve()),
        "runtime": runtime,
        "files": sorted(records, key=lambda r: (r["source_apk"], r["member"])),
    }
    report_path = output / "analysis-targets.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract minimal Unity/IL2CPP/DEX analysis targets from a CGSS APK set"
    )
    parser.add_argument("target", type=Path, help="APK file or directory containing split APKs")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("work/analysis-targets"),
        help="local output directory (default: work/analysis-targets)",
    )
    args = parser.parse_args()

    if not args.target.exists():
        parser.error(f"target does not exist: {args.target}")

    try:
        report = extract(args.target, args.output)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Runtime: {report['runtime']}")
    print(f"Extracted {len(report['files'])} high-value file(s)")
    print(f"Inventory: {args.output / 'analysis-targets.json'}")

    if report["runtime"] == "IL2CPP":
        print("Next: pair global-metadata.dat with the matching ABI libil2cpp.so in an IL2CPP metadata tool.")
    elif report["runtime"] == "Mono/managed":
        print("Next: inspect Assembly-CSharp.dll with a .NET decompiler.")
    else:
        print("Runtime was not identified; inspect split inventory before proceeding.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
