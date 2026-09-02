from __future__ import annotations

import importlib.util
import pathlib
import sqlite3
import tempfile
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "probe-resource-categories.py"
SPEC = importlib.util.spec_from_file_location("probe_resource_categories", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class _Headers(dict):
    def get(self, key: str, default=None):
        return super().get(key, default)


class _Response:
    status = 206
    headers = _Headers({"Content-Length": "1", "Content-Range": "bytes 0-0/123"})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size: int = -1) -> bytes:
        return b"x"[:size]


class ProbeResourceCategoriesTests(unittest.TestCase):
    def test_select_example_uses_manifest_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "manifest.db"
            with sqlite3.connect(path) as db:
                db.execute("CREATE TABLE manifests (name TEXT, hash TEXT)")
                db.executemany(
                    "INSERT INTO manifests VALUES (?, ?)",
                    [
                        ("z/example.awb", "b" * 32),
                        ("a/example.awb", "a" * 32),
                    ],
                )
            self.assertEqual(MODULE.select_example(path, ".awb"), ("a/example.awb", "a" * 32))

    def test_probe_reads_only_prefix_and_accepts_partial_content(self) -> None:
        with mock.patch.object(MODULE.urllib.request, "urlopen", return_value=_Response()) as urlopen:
            result = MODULE.probe("Sound", "a" * 32)
        self.assertEqual(result["status"], 206)
        self.assertEqual(result["received_prefix_bytes"], 1)
        self.assertEqual(result["content_range"], "bytes 0-0/123")
        request = urlopen.call_args.args[0]
        self.assertIn("/dl/resources/Sound/aa/", request.full_url)
        self.assertEqual(request.headers["Range"], "bytes=0-0")


if __name__ == "__main__":
    unittest.main()
