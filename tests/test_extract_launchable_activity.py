from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "extract-launchable-activity.py"
SPEC = importlib.util.spec_from_file_location("extract_launchable_activity", SCRIPT)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class LaunchableActivityExtractionTests(unittest.TestCase):
    def test_parse_badging_keeps_only_package_identity_and_launcher(self) -> None:
        text = "\n".join(
            [
                "package: name='jp.co.bandainamcoent.BNEI0242' versionCode='438' versionName='11.6.3' platformBuildVersionName='15'",
                "sdkVersion:'23'",
                "uses-permission: name='android.permission.INTERNET'",
                "application-label:'private label that must not be copied'",
                "launchable-activity: name='com.example.FinalActivity'  label='private' icon='private.png'",
            ]
        )
        package, launchers = module.parse_badging(text)
        self.assertEqual(
            package,
            {
                "name": "jp.co.bandainamcoent.BNEI0242",
                "code": "438",
                "version": "11.6.3",
            },
        )
        self.assertEqual(launchers, ["com.example.FinalActivity"])

    def test_extract_filters_wrong_split_identity_and_deduplicates_launcher(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("base.apk", "config.arm64.apk", "other.apk"):
                (root / name).write_bytes(b"synthetic")
            outputs = {
                "base.apk": (
                    "package: name='jp.co.bandainamcoent.BNEI0242' versionCode='438' versionName='11.6.3'\n"
                    "launchable-activity: name='com.example.FinalActivity'\n"
                ),
                "config.arm64.apk": (
                    "package: name='jp.co.bandainamcoent.BNEI0242' versionCode='438' versionName='11.6.3'\n"
                    "launchable-activity: name='com.example.FinalActivity'\n"
                ),
                "other.apk": (
                    "package: name='other.package' versionCode='438' versionName='11.6.3'\n"
                    "launchable-activity: name='com.example.Decoy'\n"
                ),
            }

            def fake_run(command, **kwargs):
                return subprocess.CompletedProcess(command, 0, stdout=outputs[Path(command[-1]).name])

            with mock.patch.object(module.subprocess, "run", side_effect=fake_run):
                report = module.extract(
                    Path("aapt"),
                    root,
                    package_name="jp.co.bandainamcoent.BNEI0242",
                    version_name="11.6.3",
                    version_code="438",
                )

        self.assertEqual(report["matching_split_apks"], 2)
        self.assertEqual(report["launchable_activity_count"], 1)
        self.assertEqual(report["launchable_activities"], ["com.example.FinalActivity"])
        self.assertTrue(report["unique"])

    def test_multiple_distinct_launchers_are_not_accepted_as_unique(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("a.apk", "b.apk"):
                (root / name).write_bytes(b"synthetic")
            outputs = {
                "a.apk": (
                    "package: name='jp.co.bandainamcoent.BNEI0242' versionCode='438' versionName='11.6.3'\n"
                    "launchable-activity: name='com.example.First'\n"
                ),
                "b.apk": (
                    "package: name='jp.co.bandainamcoent.BNEI0242' versionCode='438' versionName='11.6.3'\n"
                    "launchable-activity: name='com.example.Second'\n"
                ),
            }

            def fake_run(command, **kwargs):
                return subprocess.CompletedProcess(command, 0, stdout=outputs[Path(command[-1]).name])

            with mock.patch.object(module.subprocess, "run", side_effect=fake_run):
                report = module.extract(
                    Path("aapt"),
                    root,
                    package_name="jp.co.bandainamcoent.BNEI0242",
                    version_name="11.6.3",
                    version_code="438",
                )

        self.assertEqual(report["launchable_activity_count"], 2)
        self.assertFalse(report["unique"])


if __name__ == "__main__":
    unittest.main()
