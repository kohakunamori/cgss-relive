from __future__ import annotations

import importlib.util
import ssl
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from server.tls_mux import Backend, create_server as create_mux_server


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-rooted-local-stack.py"
SPEC = importlib.util.spec_from_file_location("run_rooted_local_stack", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
stack = importlib.util.module_from_spec(SPEC)
# dataclasses resolves postponed annotations through sys.modules on Python 3.12.
sys.modules[SPEC.name] = stack
SPEC.loader.exec_module(stack)

CERT_SCRIPT = ROOT / "scripts" / "make-test-tls-cert.py"
CERT_SPEC = importlib.util.spec_from_file_location("make_test_tls_cert_for_stack", CERT_SCRIPT)
assert CERT_SPEC is not None and CERT_SPEC.loader is not None
certgen = importlib.util.module_from_spec(CERT_SPEC)
sys.modules[CERT_SPEC.name] = certgen
CERT_SPEC.loader.exec_module(certgen)


class _HealthHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"ok\n" if self.path == "/healthz" else b"no\n"
        status = 200 if self.path == "/healthz" else 404
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True


class RootedStackSupervisorTests(unittest.TestCase):
    def commands(self, *, diagnostic: bool = False, api_map: Path | None = Path("map.json")):
        return stack.build_stack_commands(
            python="python-test",
            repo_root=Path("repo"),
            resource_root=Path("resources"),
            manifest_db=Path("manifest.db"),
            cert=Path("server.chain.pem"),
            key=Path("server.key.pem"),
            preflight_report=Path("preflight.json"),
            control_log=Path("control.jsonl"),
            resource_log=Path("resource.jsonl"),
            api_map=api_map,
            viewer_id=7,
            producer_name="Test Producer",
            api_port=18080,
            resource_port=18081,
            tls_port=18445,
            accept_old_resource_version=diagnostic,
        )

    def test_native_commands_preflight_then_starter_backends_and_mux(self) -> None:
        commands = self.commands()

        self.assertEqual(commands.preflight[0], "python-test")
        self.assertIn("preflight-local-resources.py", commands.preflight[1])
        self.assertIn("10133800", commands.preflight)
        self.assertIn("resources", commands.preflight)
        self.assertIn("manifest.db", commands.preflight)
        self.assertIn("preflight.json", commands.preflight)

        self.assertEqual(commands.api[:3], ("python-test", "-m", "server.http_server"))
        self.assertIn("--experimental-starter-load-index", commands.api)
        self.assertIn("--viewer-id", commands.api)
        self.assertIn("7", commands.api)
        self.assertIn("Test Producer", commands.api)
        self.assertIn("control.jsonl", commands.api)
        self.assertIn("map.json", commands.api)
        self.assertNotIn("--accept-old-resource-version", commands.api)

        self.assertEqual(
            commands.resource[:3],
            ("python-test", "-m", "server.resource_server"),
        )
        self.assertIn("10133800", commands.resource)
        self.assertIn("resource.jsonl", commands.resource)
        self.assertIn("manifest.db", commands.resource)

        self.assertEqual(commands.mux[:3], ("python-test", "-m", "server.tls_mux"))
        self.assertIn("server.chain.pem", commands.mux)
        self.assertIn("server.key.pem", commands.mux)
        self.assertIn("127.0.0.1:18080", commands.mux)
        self.assertIn("127.0.0.1:18081", commands.mux)
        self.assertIn("18445", commands.mux)

    def test_diagnostic_policy_is_explicit_only(self) -> None:
        native = self.commands(diagnostic=False)
        diagnostic = self.commands(diagnostic=True)
        self.assertNotIn("--accept-old-resource-version", native.api)
        self.assertIn("--accept-old-resource-version", diagnostic.api)

    def test_api_map_is_optional(self) -> None:
        commands = self.commands(api_map=None)
        self.assertNotIn("--api-map", commands.api)
        self.assertNotIn("map.json", commands.api)

    def test_port_parser_rejects_out_of_range_values(self) -> None:
        self.assertEqual(stack.positive_port("443"), 443)
        with self.assertRaises(Exception):
            stack.positive_port("0")
        with self.assertRaises(Exception):
            stack.positive_port("65536")

    def test_tls_probe_verifies_ca_chain_and_both_original_host_sans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = certgen.generate(
                Path(directory),
                stack.API_HOST,
                additional_hostnames=[stack.RESOURCE_HOST],
                days=1,
            )
            backend = ThreadingHTTPServer(("127.0.0.1", 0), _HealthHandler)
            backend.daemon_threads = True
            backend_thread = threading.Thread(target=backend.serve_forever, daemon=True)
            backend_thread.start()

            routes = {
                stack.API_HOST: Backend("127.0.0.1", backend.server_port),
                stack.RESOURCE_HOST: Backend("127.0.0.1", backend.server_port),
            }
            mux = create_mux_server("127.0.0.1", 0, routes)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(paths["server_chain"], paths["server_key"])
            mux.socket = context.wrap_socket(mux.socket, server_side=True)
            mux_thread = threading.Thread(target=mux.serve_forever, daemon=True)
            mux_thread.start()
            try:
                self.assertEqual(
                    stack.probe_tls_route(
                        mux.server_port,
                        stack.API_HOST,
                        paths["ca_cert"],
                        timeout=2,
                    ),
                    200,
                )
                self.assertEqual(
                    stack.probe_tls_route(
                        mux.server_port,
                        stack.RESOURCE_HOST,
                        paths["ca_cert"],
                        timeout=2,
                    ),
                    200,
                )
                with self.assertRaises(ssl.SSLCertVerificationError):
                    stack.probe_tls_route(
                        mux.server_port,
                        "not-in-leaf.invalid",
                        paths["ca_cert"],
                        timeout=2,
                    )
            finally:
                mux.shutdown()
                mux.server_close()
                backend.shutdown()
                backend.server_close()
                mux_thread.join(timeout=2)
                backend_thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
