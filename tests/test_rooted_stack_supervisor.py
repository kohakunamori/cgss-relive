from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run-rooted-local-stack.py"
SPEC = importlib.util.spec_from_file_location("run_rooted_local_stack", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
stack = importlib.util.module_from_spec(SPEC)
# dataclasses resolves postponed annotations through sys.modules on Python 3.12.
sys.modules[SPEC.name] = stack
SPEC.loader.exec_module(stack)


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


if __name__ == "__main__":
    unittest.main()
