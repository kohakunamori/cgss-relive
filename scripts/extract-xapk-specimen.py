#!/usr/bin/env python3
"""Convert the frozen 11.6.3 XAPK into the specimen layout used by research tools."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import sys
import zipfile
from datetime import datetime, timezone

EXPECTED = {
    "xapk_sha256": "609868c5a4cf5ce78ed653be448717e426410b4df03ca9e0356a046afc0d465d",
    "package": "jp.co.bandainamcoent.BNEI0242",
    "version_name": "11.6.3",
    "version_code": "438",
    "base_name": "jp.co.bandainamcoent.BNEI0242.apk",
    "base_sha256": "c73fc868bcaaccb7912eddb4d6651189d52526c5df5c31ec9b12de8c06c19cee",
    "arm64_name": "config.arm64_v8a.apk",
    "arm64_sha256": "da2d09804bdc33a586e684599a42f496db4f43ceedc4359f45b89f8fc571d3c7",
    "armv7_name": "config.armeabi_v7a.apk",
    "armv7_sha256": "a5b5a8dafcb35a3e30f8de74d34dd5d176aa394f81e324cebb19b1aeb1412c04",
    "libil2cpp_sha256": "2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5",
    "global_metadata_sha256": "2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586",
}


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("xapk", type=pathlib.Path)
    parser.add_argument("-o", "--output", type=pathlib.Path, required=True)
    parser.add_argument(
        "--include-armeabi-v7a",
        action="store_true",
        help="also extract the 32-bit ABI split; arm64 research devices do not need it",
    )
    parser.add_argument(
        "--allow-nonbaseline",
        action="store_true",
        help="allow a different XAPK hash after package/version checks; native RVAs must then be treated as invalid",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    xapk = args.xapk.resolve()
    out = args.output.resolve()
    if not xapk.is_file():
        raise SystemExit(f"XAPK not found: {xapk}")

    xapk_hash = sha256_file(xapk)
    if xapk_hash != EXPECTED["xapk_sha256"] and not args.allow_nonbaseline:
        raise SystemExit(
            "XAPK hash mismatch. Refusing to create an RVA-compatible research specimen.\n"
            f"expected: {EXPECTED['xapk_sha256']}\nactual:   {xapk_hash}"
        )

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    with zipfile.ZipFile(xapk) as archive:
        try:
            xapk_manifest = json.loads(archive.read("manifest.json").decode("utf-8"))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SystemExit("XAPK manifest.json is missing or invalid") from exc

        package = str(xapk_manifest.get("package_name", ""))
        version_name = str(xapk_manifest.get("version_name", ""))
        version_code = str(xapk_manifest.get("version_code", ""))
        if package != EXPECTED["package"]:
            raise SystemExit(f"unexpected package: {package}")
        if version_name != EXPECTED["version_name"]:
            raise SystemExit(f"unexpected versionName: {version_name}")
        if version_code != EXPECTED["version_code"]:
            raise SystemExit(f"unexpected versionCode: {version_code}")

        selected = [
            (EXPECTED["base_name"], "base.apk", EXPECTED["base_sha256"]),
            (EXPECTED["arm64_name"], "01-config.arm64_v8a.apk", EXPECTED["arm64_sha256"]),
        ]
        if args.include_armeabi_v7a:
            selected.append(
                (EXPECTED["armv7_name"], "02-config.armeabi_v7a.apk", EXPECTED["armv7_sha256"])
            )

        records = []
        for archive_name, local_name, expected_hash in selected:
            try:
                data = archive.read(archive_name)
            except KeyError as exc:
                raise SystemExit(f"required APK is missing from XAPK: {archive_name}") from exc
            actual_hash = sha256_bytes(data)
            if xapk_hash == EXPECTED["xapk_sha256"] and actual_hash != expected_hash:
                raise SystemExit(
                    f"split hash mismatch for {archive_name}: expected {expected_hash}, got {actual_hash}"
                )
            local_path = out / local_name
            local_path.write_bytes(data)
            records.append(
                {
                    "remote_path": None,
                    "file": local_name,
                    "source_xapk_entry": archive_name,
                    "size": len(data),
                    "sha256": actual_hash,
                }
            )

    # Verify the two native-analysis anchors directly from the extracted APKs.
    with zipfile.ZipFile(out / "base.apk") as base_apk:
        metadata = base_apk.read("assets/bin/Data/Managed/Metadata/global-metadata.dat")
    metadata_hash = sha256_bytes(metadata)

    with zipfile.ZipFile(out / "01-config.arm64_v8a.apk") as arm64_apk:
        il2cpp = arm64_apk.read("lib/arm64-v8a/libil2cpp.so")
    il2cpp_hash = sha256_bytes(il2cpp)

    if xapk_hash == EXPECTED["xapk_sha256"]:
        if metadata_hash != EXPECTED["global_metadata_sha256"]:
            raise SystemExit("global-metadata.dat hash mismatch inside frozen XAPK")
        if il2cpp_hash != EXPECTED["libil2cpp_sha256"]:
            raise SystemExit("arm64 libil2cpp.so hash mismatch inside frozen XAPK")

    specimen_manifest = {
        "package": package,
        "version_name": version_name,
        "version_code": version_code,
        "adb_serial": None,
        "acquired_at": datetime.now(timezone.utc).isoformat(),
        "source": "xapk",
        "source_xapk_sha256": xapk_hash,
        "baseline_exact": xapk_hash == EXPECTED["xapk_sha256"],
        "libil2cpp_sha256": il2cpp_hash,
        "global_metadata_sha256": metadata_hash,
        "files": records,
    }
    (out / "manifest.json").write_text(
        json.dumps(specimen_manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"Specimen written to: {out}")
    print(f"baseline_exact={specimen_manifest['baseline_exact']}")
    print(f"APK count={len(records)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
