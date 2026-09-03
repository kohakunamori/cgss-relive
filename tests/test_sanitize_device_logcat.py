from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sanitize-device-logcat.py"
SPEC = importlib.util.spec_from_file_location("sanitize_device_logcat", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


class DeviceLogcatSanitizerTests(unittest.TestCase):
    def test_sensitive_message_values_never_leave_whitelist(self) -> None:
        raw = [
            "1725350000.100 100 101 E Unity: SSLHandshakeException https://secret.example/x SID=secret UDID=secret\n",
            "1725350000.200 100 101 E Unity: UnknownHostException api-secret.example viewer_id=999\n",
            "1725350000.300 100 101 F DEBUG: Fatal signal 11 (SIGSEGV), fault addr secret\n",
            "1725350000.400 100 101 I Unity: harmless gameplay line secret-token\n",
        ]
        events, counts = module.sanitize_lines(raw)
        self.assertEqual([event["category"] for event in events], [
            "tls_handshake_error",
            "dns_error",
            "process_crash",
        ])
        self.assertEqual(counts["tls_handshake_error"], 1)
        self.assertEqual(counts["dns_error"], 1)
        self.assertEqual(counts["process_crash"], 1)

        output = io.StringIO()
        module.write_events(events, output)
        serialized = output.getvalue()
        for forbidden in (
            "secret.example",
            "secret-token",
            "SID=",
            "UDID=",
            "viewer_id",
            "fault addr",
            "SSLHandshakeException",
            "UnknownHostException",
        ):
            self.assertNotIn(forbidden, serialized)
        decoded = [json.loads(line) for line in serialized.splitlines()]
        for event in decoded:
            self.assertEqual(
                set(event),
                {"schema", "time", "source", "category", "severity"},
            )
            self.assertEqual(event["source"], "device_logcat")

    def test_certificate_errors_are_more_specific_than_handshake(self) -> None:
        line = (
            "1725350001.000 100 101 E Unity: SSLHandshakeException "
            "CertPathValidatorException Trust anchor for certification path not found\n"
        )
        events, _ = module.sanitize_lines([line])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["category"], "tls_certificate_error")

    def test_classified_line_without_epoch_is_skipped_not_fabricated(self) -> None:
        events, counts = module.sanitize_lines(["E Unity: connection refused secret\n"])
        self.assertEqual(events, [])
        self.assertEqual(counts["classified_without_epoch"], 1)

    def test_network_failure_categories(self) -> None:
        cases = {
            "1725350002.1 1 1 E T: failed to connect to private-host\n": "connection_refused",
            "1725350002.2 1 1 E T: Network is unreachable private-host\n": "network_unreachable",
            "1725350002.3 1 1 E T: SocketTimeoutException private-host\n": "network_timeout",
            "1725350002.4 1 1 E T: HTTP/1.1 503 private-path\n": "http_error",
            "1725350002.5 1 1 E T: UnityWebRequest failed private-url\n": "unity_web_request_error",
        }
        for raw, expected in cases.items():
            with self.subTest(expected=expected):
                events, _ = module.sanitize_lines([raw])
                self.assertEqual(events[0]["category"], expected)


if __name__ == "__main__":
    unittest.main()
