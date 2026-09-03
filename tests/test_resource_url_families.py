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

    def test_bootstrap_manifest_path_is_version_scoped(self) -> None:
        root = Path("cache")
        self.assertEqual(
            resolve_resource_request(root, "/dl/10133800/manifests/all_dbmanifest"),
            (root / "manifests" / "all_dbmanifest", None),
        )
        self.assertIsNone(resolve_resource_request(root, "/dl/10133000/manifests/all_dbmanifest"))


class ResourceURLHTTPTests(unittest.TestCase):
    def test_storage_filename_and_manifest_are_served_from_frozen_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            payload = b"0123456789"
            digest = hashlib.md5(payload).hexdigest()
            path = object_path(root, digest)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            (root / "manifests").mkdir()
            (root / "manifests" / "all_dbmanifest").write_bytes(b"manifest")

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
                for route, expected in (
                    ("/dl/10133800/High/AssetBundles/Android/foo.unity3d", payload),
                    ("/dl/10133800/manifests/all_dbmanifest", b"manifest"),
                ):
                    conn = http.client.HTTPConnection(host, port, timeout=5)
                    conn.request("GET", route)
                    response = conn.getresponse()
                    body = response.read()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(body, expected)
                    conn.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
