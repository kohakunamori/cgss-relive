#!/usr/bin/env python3
"""Replace one native library inside an APK using an audited client patch manifest."""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import tempfile
import zipfile


def load_patch_tool(repo_root: pathlib.Path):
    path = repo_root / "scripts" / "apply-client-patches.py"
    spec = importlib.util.spec_from_file_location("apply_client_patches_runtime", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load patch tool: {path}")
    module = importlib.util.module_from_spec(spec)
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def is_signature_entry(name: str) -> bool:
    upper = name.upper()
    if not upper.startswith("META-INF/"):
        return False
    leaf = upper.rsplit("/", 1)[-1]
    return leaf == "MANIFEST.MF" or leaf.endswith((".SF", ".RSA", ".DSA", ".EC"))


def patch_apk(
    input_apk: pathlib.Path,
    output_apk: pathlib.Path,
    manifest_path: pathlib.Path,
    member: str,
    repo_root: pathlib.Path,
) -> None:
    patch_tool = load_patch_tool(repo_root)
    target_file, _target_sha, patches = patch_tool.load_manifest(manifest_path)

    if pathlib.PurePosixPath(member).name != target_file:
        raise patch_tool.PatchError(
            f"APK member {member!r} does not match manifest target {target_file!r}"
        )

    with zipfile.ZipFile(input_apk, "r") as source_zip:
        try:
            native_bytes = source_zip.read(member)
        except KeyError as exc:
            raise patch_tool.PatchError(f"APK member is missing: {member}") from exc

        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = pathlib.Path(tmp)
            native_in = tmp_root / target_file
            native_out = tmp_root / f"patched-{target_file}"
            native_in.write_bytes(native_bytes)
            patch_tool.apply_manifest(
                manifest_path,
                native_in,
                native_out,
                check_only=False,
            )
            patched_bytes = native_out.read_bytes()

        output_apk.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_apk, "w", allowZip64=True) as output_zip:
            for info in source_zip.infolist():
                if is_signature_entry(info.filename):
                    continue
                payload = patched_bytes if info.filename == member else source_zip.read(info.filename)
                output_zip.writestr(info, payload)

    print(f"patched_apk={output_apk}")
    print(f"native_member={member}")
    print(f"patch_count={len(patches)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_apk", type=pathlib.Path)
    parser.add_argument("output_apk", type=pathlib.Path)
    parser.add_argument("patch_manifest", type=pathlib.Path)
    parser.add_argument("--member", default="lib/arm64-v8a/libunity.so")
    parser.add_argument(
        "--repo-root",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[1],
    )
    args = parser.parse_args()

    try:
        patch_apk(
            args.input_apk.resolve(),
            args.output_apk.resolve(),
            args.patch_manifest.resolve(),
            args.member,
            args.repo_root.resolve(),
        )
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        print(f"error: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
