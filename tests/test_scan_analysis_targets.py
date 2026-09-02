import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "scan-analysis-targets.py"

spec = importlib.util.spec_from_file_location("scan_analysis_targets", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class ScanAnalysisTargetsTests(unittest.TestCase):
    def test_scans_ascii_and_utf16le(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "base" / "global-metadata.dat"
            target.parent.mkdir(parents=True)
            target.write_bytes(
                b"prefix APP-VER suffix\x00"
                + "viewer_id".encode("utf-16le")
                + b"\x00tail"
            )

            report = module.scan(root, ["APP-VER", "viewer_id"], per_encoding_limit=10)
            self.assertEqual(len(report["files"]), 1)
            hits = report["files"][0]["hits"]
            pairs = {(h["indicator"], h["encoding"]) for h in hits}
            self.assertIn(("APP-VER", "ascii"), pairs)
            self.assertIn(("viewer_id", "utf16le"), pairs)

    def test_skips_own_reports(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "analysis-targets.json").write_text("APP-VER", encoding="utf-8")
            (root / "string-scan.json").write_text("APP-VER", encoding="utf-8")
            report = module.scan(root, ["APP-VER"])
            self.assertEqual(report["files"], [])

    def test_hit_limit_is_applied(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "classes.dex"
            target.write_bytes(b"SID SID SID SID")
            report = module.scan(root, ["SID"], per_encoding_limit=2)
            hit = report["files"][0]["hits"][0]
            self.assertEqual(hit["offsets"], [0, 4])
            self.assertTrue(hit["count_capped"])


if __name__ == "__main__":
    unittest.main()
