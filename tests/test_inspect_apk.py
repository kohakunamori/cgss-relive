import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "inspect-apk.py"


class InspectApkTests(unittest.TestCase):
    def run_inspector(self, entries: dict[str, bytes]) -> dict:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            apk = root / "base.apk"
            with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as zf:
                for name, payload in entries.items():
                    zf.writestr(name, payload)

            out = root / "inspection.json"
            subprocess.run(
                [sys.executable, str(SCRIPT), str(apk), "-o", str(out)],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            return json.loads(out.read_text(encoding="utf-8"))

    def test_managed_unity_layout(self):
        result = self.run_inspector(
            {
                "assets/bin/Data/globalgamemanagers": b"Unity 2022.3.56f1\x00",
                "assets/bin/Data/Managed/Assembly-CSharp.dll": b"https://example.invalid/api\x00",
                "lib/arm64-v8a/libunity.so": b"unity",
            }
        )
        self.assertEqual(result["unity_runtime"], "Mono/managed")
        apk = result["apks"][0]
        self.assertTrue(apk["unity"]["has_assembly_csharp"])
        self.assertIn("arm64-v8a", apk["abis"])
        self.assertIn("2022.3.56f1", apk["unity"]["versions_seen"])

    def test_il2cpp_unity_layout(self):
        result = self.run_inspector(
            {
                "assets/bin/Data/globalgamemanagers": b"2022.3.56f1\x00",
                "assets/bin/Data/Managed/Metadata/global-metadata.dat": b"metadata",
                "lib/arm64-v8a/libil2cpp.so": b"https://api.example.com/v1/test\x00",
            }
        )
        self.assertEqual(result["unity_runtime"], "IL2CPP")
        apk = result["apks"][0]
        self.assertTrue(apk["unity"]["has_libil2cpp"])
        self.assertTrue(apk["unity"]["has_global_metadata"])
        self.assertIn("api.example.com", apk["static_domains"])


if __name__ == "__main__":
    unittest.main()
