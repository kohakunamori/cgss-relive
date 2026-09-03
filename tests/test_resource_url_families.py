from __future__ import annotations

import hashlib
import http.client
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from server.resource_server import create_server, load_manifest_name_index, object_path, resolve_resource_request


class ResourceURLFamilyTests(unittest.TestCase):
    def test_storage_and_cdn_hash_forms_resolve_to_same_archive_object(self) -> None:
        root = Path("cache")
        digest = "0123456789abcdef0123456789abcdef"
        expected = (root / "objects" / "01" / digest, digest)
        routes = (
            f"/dl/resources/AssetBundles/01/{digest}",
            f"/dl/resources/High/AssetBundles/Android/{digest}.lz4",
            f"/dl/10133800/High/AssetBundles/Android/{digest}",
            f"/dl/10133800/Sound/Common/{digest}",
            f"/dl/resources/High/Movie/{digest}",
            f"/dl/10133800/Generic/Master/{digest}",
        )
        for route in routes:
            with self.subTest(route=route):
                self.assertEqual(resolve_resource_request(root, route), expected)

        self.assertIsNone(resolve_resource_request(root, f"/dl/10133000/Generic/Master/{digest}"))
        self.assertIsNone(resolve_resource_request(root, f"/dl/10133800/Movie/{digest}"))
        self.assertIsNone(resolve_resource_request(root, f"/dl/resources/AssetBundles/ff/{digest}"))

    def test_filename_storage_form_requires_local_manifest_index(self) -> None:
        root = Path("cache")
        digest = "0123456789abcdef0123456789abcdef"
        route = "/dl/10133800/High/AssetBundles/Android/foo.unity3d"
        self.assertIsNone(resolve_resource_request(root, route))
        self.assertEqual(
            resolve_resource_request(root, route, manifest_index={"foo.unity3d": digest}),
            (root / "objects" / "01" / digest, digest),
        )

    def test_path_shaped_manifest_name_wins_before_shorter_suffix(self) -> None:
        root = Path("cache")
        path_digest = "11111111111111111111111111111111"
        bare_digest = "22222222222222222222222222222222"
        route = "/dl/10133800/High/AssetBundles/Android/chara/body/foo.unity3d"
        index = {
            "chara/body/foo.unity3d": path_digest,
            "foo.unity3d": bare_digest,
        }
        self.assertEqual(
            resolve_resource_request(root, route, manifest_index=index),
            (root / "objects" / "11" / path_digest, path_digest),
        )

    def test_conflicting_basenames_do_not_create_aliases(self) -> None:
        root = Path("cache")
        first_digest = "33333333333333333333333333333333"
        second_digest = "44444444444444444444444444444444"
        index = {
            "a/shared.unity3d": first_digest,
            "b/shared.unity3d": second_digest,
        }
        self.assertEqual(
            resolve_resource_request(
                root,
                "/dl/10133800/AssetBundles/Android/a/shared.unity3d",
                manifest_index=index,
            ),
            (root / "objects" / "33" / first_digest, first_digest),
        )
        self.assertEqual(
            resolve_resource_request(
                root,
                "/dl/10133800/AssetBundles/Android/b/shared.unity3d",
                manifest_index=index,
            ),
            (root / "objects" / "44" / second_digest, second_digest),
        )
        self.assertIsNone(
            resolve_resource_request(
                root,
                "/dl/10133800/AssetBundles/Android/shared.unity3d",
                manifest_index=index,
            )
        )

    def test_path_shaped_lz4_name_strips_extension_at_same_suffix_depth(self) -> None:
        root = Path("cache")
        digest = "55555555555555555555555555555555"
        route = "/dl/resources/High/AssetBundles/Android/chara/body/foo.unity3d.lz4"
        self.assertEqual(
            resolve_resource_request(
                root,
                route,
                manifest_index={"chara/body/foo.unity3d": digest},
            ),
            (root / "objects" / "55" / digest, digest),
        )

    def test_manifest_db_loader_is_read_only_name_to_hash_index(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "manifest.db"
            with sqlite3.connect(db) as conn:
                conn.execute("CREATE TABLE manifests(name TEXT PRIMARY KEY, hash TEXT NOT NULL)")
                conn.execute(
                    "INSERT INTO manifests VALUES(?, ?)",
                    ("foo.unity3d", "0123456789abcdef0123456789abcdef"),
                )
            self.assertEqual(
                load_manifest_name_index(db),
                {"foo.unity3d": "0123456789abcdef0123456789abcdef"},
            )

    def test_bootstrap_manifest_paths_are_version_scoped(self) -> None:
        root = Path("cache")
        for name in ("all_dbmanifest", "Android_AHigh_SHigh"):
            with self.subTest(name=name):
                self.assertEqual(
                    resolve_resource_request(root, f"/dl/10133800/manifests/{name}"),
                    (root / "manifests" / name, None),
                )
                self.assertIsNone(
                    resolve_resource_request(root, f"/dl/10133000/manifests/{name}")
                )


class ResourceURLHTTPTests(unittest.TestCase):
    def _request(self, host: str, port: int, method: str, route: str):
        conn = http.client.HTTPConnection(host, port, timeout=5)
        conn.request(method, route)
        response = conn.getresponse()
        body = response.read()
        result = response.status, dict(response.getheaders()), body
        conn.close()
        return result

    def test_storage_filename_and_both_bootstrap_manifests_are_served(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = b"0123456789"
            digest = hashlib.md5(payload).hexdigest()
            path = object_path(root, digest)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            manifest_dir = root / "manifests"
            manifest_dir.mkdir()
            wire_payloads = {
                "all_dbmanifest": b"synthetic-index",
                "Android_AHigh_SHigh": b"synthetic-android-wire",
            }
            for name, wire_payload in wire_payloads.items():
                (manifest_dir / name).write_bytes(wire_payload)

            server = create_server(
                "127.0.0.1",
                0,
                root=root,
                manifest_index={"foo.unity3d": digest},
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address[:2]
            try:
                status, _, body = self._request(
                    host,
                    port,
                    "GET",
                    "/dl/10133800/High/AssetBundles/Android/foo.unity3d",
                )
                self.assertEqual(status, 200)
                self.assertEqual(body, payload)

                for name, expected in wire_payloads.items():
                    route = f"/dl/10133800/manifests/{name}"
                    with self.subTest(name=name, method="GET"):
                        status, headers, body = self._request(host, port, "GET", route)
                        self.assertEqual(status, 200)
                        self.assertEqual(body, expected)
                        self.assertEqual(headers["Cache-Control"], "no-cache")
                        self.assertNotIn("ETag", headers)
                    with self.subTest(name=name, method="HEAD"):
                        status, headers, body = self._request(host, port, "HEAD", route)
                        self.assertEqual(status, 200)
                        self.assertEqual(body, b"")
                        self.assertEqual(headers["Content-Length"], str(len(expected)))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
