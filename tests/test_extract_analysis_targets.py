import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "extract-analysis-targets.py"

spec = importlib.util.spec_from_file_location("extract_analysis_targets", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class ExtractAnalysisTargetsTests(unittest.TestCase):
    def test_extracts_il2cpp_targets_and_ignores_bulk_assets(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            apk_dir = root / "apk"
            apk_dir.mkdir()
            apk = apk_dir / "base.apk"

            with zipfile.ZipFile(apk, "w") as zf:
                zf.writestr("classes.dex", b"dex")
                zf.writestr("lib/arm64-v8a/libil2cpp.so", b"native")
                zf.writestr("lib/arm64-v8a/libunity.so", b"unity")
                zf.writestr(
                    "assets/bin/Data/Managed/Metadata/global-metadata.dat", b"metadata"
                )
                zf.writestr("assets/bin/Data/globalgamemanagers", b"gm")
                zf.writestr("assets/huge-game-asset.unity3d", b"do-not-extract")

            output = root / "targets"
            report = module.extract(apk_dir, output)

            self.assertEqual(report["runtime"], "IL2CPP")
            members = {row["member"] for row in report["files"]}
            self.assertIn("classes.dex", members)
            self.assertIn("lib/arm64-v8a/libil2cpp.so", members)
            self.assertIn(
                "assets/bin/Data/Managed/Metadata/global-metadata.dat", members
            )
            self.assertNotIn("assets/huge-game-asset.unity3d", members)
            self.assertTrue((output / "analysis-targets.json").exists())

    def test_split_provenance_prevents_name_collisions(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            apk_dir = root / "apk"
            apk_dir.mkdir()
            for apk_name, payload in (("base.apk", b"base"), ("config.apk", b"split")):
                with zipfile.ZipFile(apk_dir / apk_name, "w") as zf:
                    zf.writestr("classes.dex", payload)

            output = root / "targets"
            report = module.extract(apk_dir, output)

            outputs = {row["output"] for row in report["files"]}
            self.assertIn("base/classes.dex", outputs)
            self.assertIn("config/classes.dex", outputs)
            self.assertEqual(len(outputs), 2)


if __name__ == "__main__":
    unittest.main()
