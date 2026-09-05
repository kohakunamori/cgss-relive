from __future__ import annotations

import http.client
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from server import cgss_codec
from server.conservative_templates import (
    ConservativeTemplateError,
    load_conservative_empty_templates,
)
from server.http_server import create_server
from server.response_templates import ResponseTemplateStore
from server.semantic_contracts import SemanticContractIndex


def _header_encode(value: str) -> str:
    groups = "".join("12" + chr(ord(ch) + 10) + "3" for ch in value)
    return f"{len(value):04x}" + groups + ("7" * 32)


def _write_semantic_db(path: Path) -> None:
    db = sqlite3.connect(path)
    try:
        db.executescript(
            """
            CREATE TABLE endpoints(
              id INTEGER PRIMARY KEY, route TEXT NOT NULL, enum TEXT, status TEXT,
              group_name TEXT, api_key INTEGER
            );
            CREATE TABLE request_fields(id INTEGER PRIMARY KEY, endpoint_id INTEGER);
            CREATE TABLE response_fields(
              id INTEGER PRIMARY KEY, endpoint_id INTEGER, task TEXT NOT NULL,
              method TEXT, field TEXT NOT NULL, requiredness TEXT, value_types_json TEXT
            );
            CREATE TABLE endpoint_state_mutations(endpoint_id INTEGER, mutation_id INTEGER);
            CREATE TABLE subsystems(id INTEGER PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE endpoint_subsystems(endpoint_id INTEGER, state_type TEXT, subsystem_id INTEGER);
            CREATE VIEW endpoint_semantics AS SELECT id AS endpoint_id, route FROM endpoints;
            """
        )
        db.executemany(
            "INSERT INTO endpoints(id,route,enum,status,group_name,api_key) VALUES(?,?,?,?,?,?)",
            [
                (1, "/safe/empty", "SafeEmpty", "proven-static", "A", 1),
                (2, "/needs/value", "NeedsValue", "proven-static", "A", 2),
                (3, "/duplicate", "DupA", "proven-static", "A", 3),
                (4, "/duplicate", "DupB", "unresolved", "B", 8),
            ],
        )
        db.execute(
            "INSERT INTO response_fields(id,endpoint_id,task,method,field,requiredness,value_types_json) "
            "VALUES(?,?,?,?,?,?,?)",
            (1, 2, "Stage.NeedsValueTask", "Parse", "value", "required-path", '["int"]'),
        )
        db.commit()
    finally:
        db.close()


def _catalog(path: Path, *, safe_id: int = 1) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "endpoint_count": 4,
                "unique_route_count": 3,
                "duplicate_route_count": 1,
                "routes": [
                    {
                        "route": "/safe/empty",
                        "endpoints": [
                            {
                                "endpoint_id": safe_id,
                                "concrete_response_fields": [],
                                "exact_state_mutation_count": 0,
                                "effective_base_parsers": [
                                    {"response_scope": "common-envelope"}
                                ],
                            }
                        ],
                    },
                    {
                        "route": "/needs/value",
                        "endpoints": [
                            {
                                "endpoint_id": 2,
                                "concrete_response_fields": [{"field": "value"}],
                                "exact_state_mutation_count": 0,
                                "effective_base_parsers": [],
                            }
                        ],
                    },
                    {
                        "route": "/duplicate",
                        "endpoints": [
                            {
                                "endpoint_id": 3,
                                "concrete_response_fields": [],
                                "exact_state_mutation_count": 0,
                                "effective_base_parsers": [],
                            },
                            {
                                "endpoint_id": 4,
                                "concrete_response_fields": [],
                                "exact_state_mutation_count": 0,
                                "effective_base_parsers": [],
                            },
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


class ConservativeRuntimeTemplateTests(unittest.TestCase):
    def _index(self, root: Path) -> SemanticContractIndex:
        db = root / "semantic.sqlite"
        _write_semantic_db(db)
        return SemanticContractIndex(db, enforce_final_counts=False)

    def test_loader_exposes_only_unique_empty_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = self._index(root)
            catalog = root / "c14.json"
            _catalog(catalog)
            store = load_conservative_empty_templates(
                catalog,
                semantic_index=index,
                enforce_final_counts=False,
            )
            self.assertEqual(store.routes, ("/safe/empty",))
            template = store.get("/safe/empty")
            self.assertIsNotNone(template)
            assert template is not None
            self.assertEqual(template.endpoint_id, 1)
            self.assertEqual(dict(template.data), {})
            self.assertIn("static candidate", template.evidence or "")

    def test_loader_rejects_c14_c9_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = self._index(root)
            catalog = root / "c14.json"
            _catalog(catalog, safe_id=999)
            with self.assertRaisesRegex(
                ConservativeTemplateError,
                "endpoint identity mismatch",
            ):
                load_conservative_empty_templates(
                    catalog,
                    semantic_index=index,
                    enforce_final_counts=False,
                )

    def test_explicit_template_overrides_baseline_same_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = self._index(root)
            catalog = root / "c14.json"
            _catalog(catalog)
            baseline = load_conservative_empty_templates(
                catalog,
                semantic_index=index,
                enforce_final_counts=False,
            )
            explicit_path = root / "explicit.json"
            explicit_path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "routes": {
                            "/safe/empty": {
                                "endpoint_id": 1,
                                "data": {"promoted": True},
                                "evidence": "synthetic stronger evidence",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            explicit = ResponseTemplateStore.load(explicit_path, semantic_index=index)
            merged = baseline.merged(explicit)
            self.assertEqual(merged.count, 1)
            template = merged.get("/safe/empty")
            self.assertIsNotNone(template)
            assert template is not None
            self.assertEqual(dict(template.data), {"promoted": True})

    def test_conservative_template_uses_normal_encrypted_success_wire_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = self._index(root)
            catalog = root / "c14.json"
            _catalog(catalog)
            store = load_conservative_empty_templates(
                catalog,
                semantic_index=index,
                enforce_final_counts=False,
            )
            server = create_server(
                "127.0.0.1",
                0,
                semantic_index=index,
                response_templates=store,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            udid = "00112233-4455-6677-8899-aabbccddeeff"
            body = cgss_codec.encode_body(
                {"viewer_id": "opaque"},
                udid,
                dynamic_key=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
            )
            headers = {
                "Content-Type": "application/octet-stream",
                "UDID": _header_encode(udid),
                "SID": "synthetic-sid",
                "APP-VER": "11.6.3",
                "RES-VER": "10133800",
            }
            try:
                host, port = server.server_address[:2]
                connection = http.client.HTTPConnection(host, port, timeout=5)
                connection.request("POST", "/safe/empty", body=body, headers=headers)
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response_body = response.read()
                connection.close()
                decoded = cgss_codec.decode_body(response_body, udid)
                self.assertEqual(decoded["data_headers"]["result_code"], 1)
                self.assertEqual(decoded["data_headers"]["sid"], "synthetic-sid")
                self.assertEqual(decoded["data"], {})
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
