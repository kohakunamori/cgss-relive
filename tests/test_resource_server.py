from __future__ import annotations

import hashlib
import http.client
import json
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
    resource_event_route,
)
from server.safe_events import SafeEventLog


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

    def test_resolve_final_is_s3_false_storages_url_families(self) -> None:
        root = Path("cache")
        digest = "0123456789abcdef0123456789abcdef"
        index = {
            "ab_file": digest,
            "sound_file": digest,
            "movie_file": digest,
            "master.mdb": digest,
            "bundle_manifest": digest,
        }
        expected = (root / "objects" / "01" / digest, digest)

        # Regular/versioned AssetBundle base:
        # dl/<ver>/[Low|High/]AssetBundles/<Platform>/<filename>
        self.assertEqual(
            resolve_resource_request(
                root,
                "/dl/10133800/High/AssetBundles/Android/ab_file",
                manifest_index=index,
            ),
            expected,
        )

        # Hush/compressed storages AssetBundle base:
        # dl/resources/[Low|High/]AssetBundles/<Platform>/<filename>.lz4
        self.assertEqual(
            resolve_resource_request(
                root,
                "/dl/resources/High/AssetBundles/Android/ab_file.lz4",
                manifest_index=index,
            ),
            expected,
        )

        # Per-bundle manifest is appended below the selected AssetBundle base.
        self.assertEqual(
            resolve_resource_request(
                root,
                "/dl/10133800/High/AssetBundles/Android/manifest/bundle_manifest",
                manifest_index=index,
            ),
            expected,
        )

        # Versioned Sound supports Platform/Common tails.
        self.assertEqual(
            resolve_resource_request(
                root,
                "/dl/10133800/High/Sound/Android/sound_file",
                manifest_index=index,
            ),
            expected,
        )
        self.assertEqual(
            resolve_resource_request(
                root,
                "/dl/10133800/Sound/Common/sound_file",
                manifest_index=index,
            ),
            expected,
        )

        # Final-client Movie base is the unversioned /dl/resources family.
        self.assertEqual(
            resolve_resource_request(
                root,
                "/dl/resources/High/Movie/movie_file",
                manifest_index=index,
            ),
            expected,
        )

        # Generic Master/Blob directories remain filename-addressed tails.
        self.assertEqual(
            resolve_resource_request(
                root,
                "/dl/10133800/Generic/Master/master.mdb",
                manifest_index=index,
            ),
            expected,
        )
        self.assertEqual(
            resolve_resource_request(
                root,
                "/dl/resources/Generic/Blob/master.mdb.lz4",
                manifest_index=index,
            ),
            expected,
        )

    def test_rejects_nonfinal_or_wrong_family_resource_urls(self) -> None:
        root = Path("cache")
        digest = "0123456789abcdef0123456789abcdef"
        index = {"file": digest}

        self.assertIsNone(
            resolve_resource_request(
                root,
                "/dl/10133799/High/AssetBundles/Android/file",
                manifest_index=index,
            )
        )
        self.assertIsNone(
            resolve_resource_request(
                root,
                "/dl/High/AssetBundles/Android/file",
                manifest_index=index,
            )
        )
        self.assertIsNone(
            resolve_resource_request(
                root,
                "/dl/10133800/High/Movie/file",
                manifest_index=index,
            )
        )
        self.assertIsNone(
            resolve_resource_request(
                root,
                "/dl/10133800/High/AssetBundles/Android/file",
                manifest_index=None,
            )
        )

    def test_bootstrap_manifest_route_is_versioned_wire_file(self) -> None:
        root = Path("cache")
        self.assertEqual(
            resolve_resource_request(root, "/dl/10133800/manifests/all_dbmanifest"),
            (root / "manifests" / "all_dbmanifest", None),
        )
        self.assertEqual(
            resolve_resource_request(root, "/dl/10133800/manifests/Android_AHigh_SHigh"),
            (root / "manifests" / "Android_AHigh_SHigh", None),
        )
        self.assertIsNone(
            resolve_resource_request(root, "/dl/10133799/manifests/all_dbmanifest")
        )

    def test_resource_event_route_never_contains_filename_or_hash(self) -> None:
        digest = "0123456789abcdef0123456789abcdef"
        self.assertEqual(
            resource_event_route(f"/dl/resources/AssetBundles/01/{digest}?secret=query"),
            "@resource/AssetBundles",
        )
        self.assertEqual(
            resource_event_route("/dl/10133800/manifests/Android_AHigh_SHigh"),
            "@resource/manifest",
        )
        self.assertEqual(
            resource_event_route("/dl/10133800/High/AssetBundles/Android/private_filename"),
            "@resource/AssetBundles",
        )
        self.assertEqual(resource_event_route("/something/private"), "@resource/unresolved")

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
        self.event_path = self.root / "events.jsonl"

        self.server = create_server(
            "127.0.0.1",
            0,
            root=self.root,
            event_log=SafeEventLog(self.event_path),
        )
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

    def _events(self) -> list[dict]:
        if not self.event_path.exists():
            return []
        return [json.loads(line) for line in self.event_path.read_text().splitlines() if line.strip()]

    def test_get_full_object(self) -> None:
        status, headers, body = self._request("GET", self.route)
        self.assertEqual(status, 200)
        self.assertEqual(body, self.payload)
        self.assertEqual(headers["Content-Length"], str(len(self.payload)))
        self.assertEqual(headers["Accept-Ranges"], "bytes")
        self.assertEqual(headers["ETag"], f'"{self.digest}"')

        event = self._events()[-1]
        self.assertEqual(event["route"], "@resource/Generic")
        self.assertEqual(event["status"], 200)
        serialized = json.dumps(event)
        self.assertNotIn(self.digest, serialized)
        self.assertNotIn(self.digest[:2], event["route"])

    def test_final_client_filename_addressed_url_serves_archive_object(self) -> None:
        event_path = self.root / "filename-events.jsonl"
        server = create_server(
            "127.0.0.1",
            0,
            root=self.root,
            manifest_index={"bundle_file": self.digest},
            event_log=SafeEventLog(event_path),
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address[:2]
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request(
                "GET",
                "/dl/10133800/High/AssetBundles/Android/bundle_file",
            )
            response = conn.getresponse()
            body = response.read()
            self.assertEqual(response.status, 200)
            self.assertEqual(body, self.payload)
            conn.close()

            events = [
                json.loads(line)
                for line in event_path.read_text().splitlines()
                if line.strip()
            ]
            self.assertEqual(events[-1]["route"], "@resource/AssetBundles")
            serialized = json.dumps(events[-1])
            self.assertNotIn("bundle_file", serialized)
            self.assertNotIn(self.digest, serialized)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

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
        self.assertEqual(self._events()[-1]["status"], 416)

    def test_missing_and_noncanonical_paths_are_not_served(self) -> None:
        status, _, _ = self._request("GET", self.route.replace(f"/{self.digest[:2]}/", "/ff/"))
        self.assertEqual(status, 404)
        status, _, _ = self._request("GET", "/dl/resources/Generic/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        self.assertEqual(status, 404)
        self.assertEqual(self._events()[-1]["route"], "@resource/Generic")

    def test_healthz_is_not_runtime_evidence(self) -> None:
        before = len(self._events())
        status, _, body = self._request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok\n")
        self.assertEqual(len(self._events()), before)


if __name__ == "__main__":
    unittest.main()