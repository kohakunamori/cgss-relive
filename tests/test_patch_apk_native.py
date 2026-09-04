import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest
import zipfile

MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "patch-apk-native.py"
SPEC = importlib.util.spec_from_file_location("patch_apk_native", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"unable to load APK patch helper: {MODULE_PATH}")
PATCH_APK = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PATCH_APK
SPEC.loader.exec_module(PATCH_APK)


class TestPatchApkNative(unittest.TestCase):
    def test_replaces_native_member_and_drops_stale_v1_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source_native = b"ABCDEFGHIJ"
            input_apk = root / "input.apk"
            output_apk = root / "output.apk"
            member = "lib/arm64-v8a/libunity.so"

            with zipfile.ZipFile(input_apk, "w") as apk:
                apk.writestr(member, source_native)
                apk.writestr("assets/keep.txt", b"keep")
                apk.writestr("META-INF/OLD.SF", b"old signature")
                apk.writestr("META-INF/OLD.RSA", b"old signature")

            manifest = root / "patches.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "target": {
                            "file": "libunity.so",
                            "sha256": hashlib.sha256(source_native).hexdigest(),
                        },
                        "patches": [
                            {
                                "id": "tls.test",
                                "class": "tls",
                                "file_offset": 2,
                                "expected_hex": "4344",
                                "replacement_hex": "7879",
                                "explanation": "test only",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            repo_root = pathlib.Path(__file__).resolve().parents[1]
            PATCH_APK.patch_apk(input_apk, output_apk, manifest, member, repo_root)

            with zipfile.ZipFile(output_apk) as apk:
                self.assertEqual(apk.read(member), b"ABxyEFGHIJ")
                self.assertEqual(apk.read("assets/keep.txt"), b"keep")
                self.assertNotIn("META-INF/OLD.SF", apk.namelist())
                self.assertNotIn("META-INF/OLD.RSA", apk.namelist())


if __name__ == "__main__":
    unittest.main()
