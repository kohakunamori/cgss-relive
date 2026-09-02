from __future__ import annotations

import hashlib
import http.client
import tempfile
import threading
import unittest
from pathlib import Path

from server.resource_server import (
    RangeNotSatisfiable,
    create_server,
    object_path,
    parse_single_range,
    resolve_resource_request,
)


class ResourcePathTests(unittest.TestCase):
    def test_resolve_canonical_resource_request(self) -> None:
        root = Path("cache")
        digest = "0123456789abcdef0123456789abcdef"
        resolved = resolve_resource_request(
            root,
            f"/dl/resources/AssetBundles/01/{digest}?ignored=1",
        )
        self.assertEqual(resolved, (root / "objects" / "01" / digest, digest))
        self.assertIsNone(resolve_resource_request(root, f"/dl/resources/AssetBundles/ff/{digest}"))
        self.assertIsNone(resolve_resource_request(root, f"/dl/resources/Unknown/01/{digest}"))

    def test_single_range_parser(self) -> None:
        self.assertIsNone(parse_single_range(None, 10))
        self.assertEqual(parse_single_range("bytes=2-5", 10), (2, 5))
        self.assertEqual(parse_single_range("bytes=7-", 10), (7, 9))
        self.assertEqual(parse_single_range("bytes=-4", 10), (6, 9))
        self.assertEqual(parse_single_range("bytes=8-99", 10), (8, 9))
        for value in ("items=0-1", "bytes=", "bytes=2-1", "bytes=10-", "bytes=0-1,4-5"):
            with self.subTest(value=value):
                with self.assertRaises(RangeNotSatisfiable):
                    parse_single_range(value, 10)


class ResourceHTTPServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.payload = b"0123456789"
        self.digest = hashlib.md5(self.payload).hexdigest()
        path = object_path(self.root, self.digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.payload)
        self.route = f"/dl/resources/Generic/{self.digest[:2]}/{self.digest}"

        self.server = create_server("127.0.0.1", 0, root=self.root)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address[:2]

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def _request(self, method: str, route: str, headers: dict[str, str] | None = None):
        conn = http.client.HTTPConnection(self.host, self.port, timeout=5)
        conn.request(method, route, headers=headers or {})
        response = conn.getresponse()
        body = response.read()
        result = response.status, dict(response.getheaders()), body
        conn.close()
        return result

    def test_get_full_object(self) -> None:
        status, headers, body = self._request("GET", self.route)
        self.assertEqual(status, 200)
        self.assertEqual(body, self.payload)
        self.assertEqual(headers["Content-Length"], str(len(self.payload)))
        self.assertEqual(headers["Accept-Ranges"], "bytes")
        self.assertEqual(headers["ETag"], f'"{self.digest}"')

    def test_head_returns_headers_without_body(self) -> None:
        status, headers, body = self._request("HEAD", self.route)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(headers["Content-Length"], str(len(self.payload)))

    def test_explicit_and_suffix_ranges(self) -> None:
        status, headers, body = self._request("GET", self.route, {"Range": "bytes=2-5"})
        self.assertEqual(status, 206)
        self.assertEqual(body, b"2345")
        self.assertEqual(headers["Content-Range"], "bytes 2-5/10")

        status, headers, body = self._request("GET", self.route, {"Range": "bytes=-4"})
        self.assertEqual(status, 206)
        self.assertEqual(body, b"6789")
        self.assertEqual(headers["Content-Range"], "bytes 6-9/10")

    def test_unsatisfied_range(self) -> None:
        status, headers, body = self._request("GET", self.route, {"Range": "bytes=99-"})
        self.assertEqual(status, 416)
        self.assertEqual(body, b"")
        self.assertEqual(headers["Content-Range"], "bytes */10")

    def test_missing_and_noncanonical_paths_are_not_served(self) -> None:
        status, _, _ = self._request("GET", self.route.replace(f"/{self.digest[:2]}/", "/ff/"))
        self.assertEqual(status, 404)
        status, _, _ = self._request("GET", "/dl/resources/Generic/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(status, 404)

    def test_healthz(self) -> None:
        status, _, body = self._request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok\n")


if __name__ == "__main__":
    unittest.main()
