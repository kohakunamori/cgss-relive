#!/usr/bin/env python3
"""Apply audited, hash-guarded same-length native client patches.

This tool intentionally supports only deterministic byte replacement. It is
not a binary rewriting framework and does not guess offsets or relax guards.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import sys
from dataclasses import dataclass

ALLOWED_CLASSES = {
    "endpoint",
    "tls",
    "asset",
    "android_compat",
    "instrumentation",
}


class PatchError(RuntimeError):
    pass


@dataclass(frozen=True)
class Patch:
    patch_id: str
    patch_class: str
    offset: int
    expected: bytes
    replacement: bytes
    explanation: str


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_hex_bytes(value: object, field: str, patch_id: str) -> bytes:
    if not isinstance(value, str):
        raise PatchError(f"{patch_id}: {field} must be a hex string")
    compact = "".join(value.split())
    if len(compact) % 2:
        raise PatchError(f"{patch_id}: {field} must contain whole bytes")
    try:
        return bytes.fromhex(compact)
    except ValueError as exc:
        raise PatchError(f"{patch_id}: invalid {field}: {exc}") from exc


def load_manifest(path: pathlib.Path) -> tuple[str, str, list[Patch]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema") != 1:
        raise PatchError("unsupported patch manifest schema")

    target = raw.get("target")
    if not isinstance(target, dict):
        raise PatchError("manifest target must be an object")
    target_file = target.get("file")
    target_sha256 = target.get("sha256")
    if not isinstance(target_file, str) or not target_file:
        raise PatchError("target.file must be a non-empty string")
    if not isinstance(target_sha256, str) or len(target_sha256) != 64:
        raise PatchError("target.sha256 must be a SHA-256 hex digest")
    try:
        bytes.fromhex(target_sha256)
    except ValueError as exc:
        raise PatchError("target.sha256 is not valid hex") from exc

    parsed: list[Patch] = []
    seen_ids: set[str] = set()
    seen_ranges: list[tuple[int, int, str]] = []

    patches = raw.get("patches")
    if not isinstance(patches, list):
        raise PatchError("patches must be a list")

    for index, item in enumerate(patches):
        if not isinstance(item, dict):
            raise PatchError(f"patches[{index}] must be an object")
        patch_id = item.get("id")
        if not isinstance(patch_id, str) or not patch_id:
            raise PatchError(f"patches[{index}].id must be a non-empty string")
        if patch_id in seen_ids:
            raise PatchError(f"duplicate patch id: {patch_id}")
        seen_ids.add(patch_id)

        patch_class = item.get("class")
        if patch_class not in ALLOWED_CLASSES:
            allowed = ", ".join(sorted(ALLOWED_CLASSES))
            raise PatchError(f"{patch_id}: class must be one of: {allowed}")

        offset = item.get("file_offset")
        if not isinstance(offset, int) or offset < 0:
            raise PatchError(f"{patch_id}: file_offset must be a non-negative integer")

        expected = parse_hex_bytes(item.get("expected_hex"), "expected_hex", patch_id)
        replacement = parse_hex_bytes(item.get("replacement_hex"), "replacement_hex", patch_id)
        if not expected:
            raise PatchError(f"{patch_id}: empty byte patches are not allowed")
        if len(expected) != len(replacement):
            raise PatchError(
                f"{patch_id}: replacement length {len(replacement)} does not match "
                f"expected length {len(expected)}"
            )

        explanation = item.get("explanation")
        if not isinstance(explanation, str) or not explanation.strip():
            raise PatchError(f"{patch_id}: explanation is required")

        start, end = offset, offset + len(expected)
        for other_start, other_end, other_id in seen_ranges:
            if start < other_end and other_start < end:
                raise PatchError(f"{patch_id}: overlaps patch {other_id}")
        seen_ranges.append((start, end, patch_id))

        parsed.append(
            Patch(
                patch_id=patch_id,
                patch_class=patch_class,
                offset=offset,
                expected=expected,
                replacement=replacement,
                explanation=explanation.strip(),
            )
        )

    return target_file, target_sha256.lower(), parsed


def apply_manifest(
    manifest_path: pathlib.Path,
    input_path: pathlib.Path,
    output_path: pathlib.Path | None,
    check_only: bool,
) -> None:
    target_file, target_sha256, patches = load_manifest(manifest_path)
    if input_path.name != target_file:
        raise PatchError(
            f"input filename {input_path.name!r} does not match manifest target {target_file!r}"
        )

    original = input_path.read_bytes()
    actual_sha256 = sha256_bytes(original)
    if actual_sha256 != target_sha256:
        raise PatchError(
            f"target SHA-256 mismatch: expected {target_sha256}, got {actual_sha256}"
        )

    data = bytearray(original)
    for patch in patches:
        end = patch.offset + len(patch.expected)
        if end > len(data):
            raise PatchError(f"{patch.patch_id}: patch range exceeds target file")
        actual = bytes(data[patch.offset:end])
        if actual != patch.expected:
            raise PatchError(
                f"{patch.patch_id}: expected original bytes {patch.expected.hex()} at "
                f"0x{patch.offset:x}, got {actual.hex()}"
            )
        data[patch.offset:end] = patch.replacement
        print(
            f"verified {patch.patch_id}: class={patch.patch_class} "
            f"offset=0x{patch.offset:x} bytes={len(patch.expected)}"
        )

    result_sha256 = sha256_bytes(bytes(data))
    print(f"source_sha256={actual_sha256}")
    print(f"patch_count={len(patches)}")
    print(f"result_sha256={result_sha256}")

    if check_only:
        return
    if output_path is None:
        raise PatchError("output path is required unless --check is used")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)
    shutil.copymode(input_path, output_path)
    print(f"wrote={output_path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument("input", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path, nargs="?")
    parser.add_argument("--check", action="store_true", help="verify only; do not write output")
    args = parser.parse_args()

    if not args.check and args.output is None:
        parser.error("output is required unless --check is used")

    try:
        apply_manifest(args.manifest, args.input, args.output, args.check)
    except (OSError, json.JSONDecodeError, PatchError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
