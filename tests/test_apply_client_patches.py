import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "apply-client-patches.py"
SPEC = importlib.util.spec_from_file_location("apply_client_patches", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load patch tool: {MODULE_PATH}")
PATCH_TOOL = importlib.util.module_from_spec(SPEC)
import sys
sys.modules[SPEC.name] = PATCH_TOOL
SPEC.loader.exec_module(PATCH_TOOL)
PatchError = PATCH_TOOL.PatchError
apply_manifest = PATCH_TOOL.apply_manifest


class TestApplyClientPatches(unittest.TestCase):
    def write_manifest(self, root: pathlib.Path, source: bytes, patches: list[dict]) -> pathlib.Path:
        manifest = {
            "schema": 1,
            "target": {
                "file": "libunity.so",
                "sha256": hashlib.sha256(source).hexdigest(),
            },
            "patches": patches,
        }
        path = root / "patches.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return path

    def test_applies_exact_guarded_patch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = b"0123456789"
            source_path = root / "libunity.so"
            source_path.write_bytes(source)
            manifest = self.write_manifest(
                root,
                source,
                [
                    {
                        "id": "tls.example",
                        "class": "tls",
                        "file_offset": 3,
                        "expected_hex": "333435",
                        "replacement_hex": "414243",
                        "explanation": "test replacement",
                    }
                ],
            )
            output = root / "patched" / "libunity.so"

            apply_manifest(manifest, source_path, output, check_only=False)
            self.assertEqual(output.read_bytes(), b"012ABC6789")

    def test_rejects_wrong_source_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source_path = root / "libunity.so"
            source_path.write_bytes(b"unexpected")
            manifest = root / "patches.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target": {"file": "libunity.so", "sha256": "00" * 32},
                        "patches": [],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(PatchError):
                apply_manifest(manifest, source_path, None, check_only=True)

    def test_rejects_wrong_expected_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = b"0123456789"
            source_path = root / "libunity.so"
            source_path.write_bytes(source)
            manifest = self.write_manifest(
                root,
                source,
                [
                    {
                        "id": "endpoint.example",
                        "class": "endpoint",
                        "file_offset": 2,
                        "expected_hex": "ffff",
                        "replacement_hex": "aaaa",
                        "explanation": "must not apply blindly",
                    }
                ],
            )

            with self.assertRaises(PatchError):
                apply_manifest(manifest, source_path, None, check_only=True)

    def test_rejects_overlapping_patches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = b"0123456789"
            source_path = root / "libunity.so"
            source_path.write_bytes(source)
            manifest = self.write_manifest(
                root,
                source,
                [
                    {
                        "id": "one",
                        "class": "tls",
                        "file_offset": 2,
                        "expected_hex": "3233",
                        "replacement_hex": "aaaa",
                        "explanation": "first",
                    },
                    {
                        "id": "two",
                        "class": "endpoint",
                        "file_offset": 3,
                        "expected_hex": "3334",
                        "replacement_hex": "bbbb",
                        "explanation": "overlap",
                    },
                ],
            )

            with self.assertRaises(PatchError):
                apply_manifest(manifest, source_path, None, check_only=True)


if __name__ == "__main__":
    unittest.main()
