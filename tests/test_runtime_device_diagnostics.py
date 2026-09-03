from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "analyze-runtime-events.py"


class RuntimeDeviceDiagnosticsCLITests(unittest.TestCase):
    def test_device_tls_error_attaches_without_advancing_http_phase(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "control.jsonl"
            device = root / "device.jsonl"
            control.write_text(
                json.dumps(
                    {
                        "time": 10.0,
                        "route": "/load/check",
                        "status": 200,
                        "headers": {"APP-VER": "11.6.3", "RES-VER": "10133000"},
                        "response_data_headers": {
                            "result_code": 214,
                            "required_res_ver": "10133800",
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            device.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "time": 10.5,
                        "source": "device_logcat",
                        "category": "tls_certificate_error",
                        "severity": "error",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--merge-run",
                    f"starter={control}",
                    "--device-log",
                    f"starter={device}",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["schema"], 4)
            run = report["runs"]["starter"]
            self.assertEqual(run["phase"], "resource_version_214_responded")
            self.assertEqual(len(run["sequence"]), 1)
            self.assertEqual(run["sequence"][0]["route"], "/load/check")
            diagnostics = run["device_diagnostics"]
            self.assertTrue(diagnostics["has_tls_error"])
            self.assertEqual(diagnostics["events"], 1)
            self.assertEqual(
                diagnostics["first_failure"],
                {
                    "time": 10.5,
                    "category": "tls_certificate_error",
                    "severity": "error",
                },
            )

    def test_device_log_with_message_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "control.jsonl"
            device = root / "device.jsonl"
            control.write_text(
                json.dumps({"time": 1.0, "route": "/load/check", "status": 200}) + "\n",
                encoding="utf-8",
            )
            device.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "time": 1.1,
                        "source": "device_logcat",
                        "category": "dns_error",
                        "severity": "error",
                        "message": "https://private.example SID=secret",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--merge-run",
                    f"starter={control}",
                    "--device-log",
                    f"starter={device}",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("strict device schema", result.stderr)
            self.assertNotIn("private.example", result.stderr)
            self.assertNotIn("SID=secret", result.stderr)

    def test_device_log_requires_existing_run_label(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "control.jsonl"
            device = root / "device.jsonl"
            control.write_text(
                json.dumps({"time": 1.0, "route": "/load/check", "status": 200}) + "\n",
                encoding="utf-8",
            )
            device.write_text("", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--merge-run",
                    f"starter={control}",
                    "--device-log",
                    f"other={device}",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("no matching run", result.stderr)


if __name__ == "__main__":
    unittest.main()
