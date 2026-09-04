from __future__ import annotations

import http.client
import json
import pathlib
import sqlite3
import tempfile
import threading
import unittest

from server import cgss_codec
from server.http_server import create_server
from server.response_templates import ResponseTemplateStore
from server.semantic_contracts import SemanticContractIndex


def synthetic_header_encode(value: str) -> str:
    groups = "".join("12" + chr(ord(ch) + 10) + "3" for ch in value)
    return f"{len(value):04x}" + groups + ("7" * 32)


def build_fixture_db(path: pathlib.Path) -> None:
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
                (1, "/story/start", "StoryStart", "proven-static", "A", 47),
                (2, "/duplicate/path", "DuplicateA", "proven-static", "A", 100),
                (3, "/duplicate/path", "DuplicateB", "unresolved", "B", 10),
            ],
        )
        db.execute("INSERT INTO request_fields(id,endpoint_id) VALUES(1,1)")
        db.executemany(
            "INSERT INTO response_fields(id,endpoint_id,task,method,field,requiredness,value_types_json) "
            "VALUES(?,?,?,?,?,?,?)",
            [
                (1, 1, "Stage.StoryStartTask", "Parse", "story_id", "required-path", '["int"]'),
                (2, 1, "Stage.StoryStartTask", "Parse", "optional", "unknown-cfg", '["json"]'),
            ],
        )
        db.execute("INSERT INTO endpoint_state_mutations(endpoint_id,mutation_id) VALUES(1,1)")
        db.execute("INSERT INTO subsystems(id,name) VALUES(1,'story-commu')")
        db.execute(
            "INSERT INTO endpoint_subsystems(endpoint_id,state_type,subsystem_id) "
            "VALUES(1,'Stage.WorkStoryData',1)"
        )
        db.commit()
    finally:
        db.close()


class SemanticContractIndexTests(unittest.TestCase):
    def test_preserves_duplicate_paths_and_field_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "contracts.sqlite"
            build_fixture_db(path)
            index = SemanticContractIndex(path, enforce_final_counts=False)
            self.assertEqual(index.endpoint_count, 3)
            self.assertEqual(index.unique_route_count, 2)
            self.assertEqual([x.endpoint_id for x in index.route_candidates("story/start")], [1])
            self.assertEqual(
                [x.endpoint_id for x in index.route_candidates("/duplicate/path?opaque=ignored")],
                [2, 3],
            )
            endpoint = index.endpoint(1)
            self.assertEqual(endpoint.request_field_count, 1)
            self.assertEqual(endpoint.exact_state_mutation_count, 1)
            self.assertEqual(endpoint.inferred_subsystems, ("story-commu",))
            self.assertEqual([x.field for x in endpoint.required_response_fields], ["story_id"])
            self.assertEqual([x.field for x in endpoint.unknown_response_fields], ["optional"])
            self.assertEqual(endpoint.response_fields[0].value_types, ("int",))

    def test_template_store_requires_unique_exact_c9_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            db_path = root / "contracts.sqlite"
            build_fixture_db(db_path)
            index = SemanticContractIndex(db_path, enforce_final_counts=False)

            good = root / "good.json"
            good.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "routes": {
                            "/story/start": {
                                "endpoint_id": 1,
                                "data": {"story_id": 1},
                                "evidence": "synthetic unit test",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            store = ResponseTemplateStore.load(good, semantic_index=index)
            self.assertEqual(store.get("story/start").data, {"story_id": 1})

            ambiguous = root / "ambiguous.json"
            ambiguous.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "routes": {
                            "/duplicate/path": {"endpoint_id": 2, "data": {}}
                        },
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                ResponseTemplateStore.load(ambiguous, semantic_index=index)


class SemanticHTTPRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.db_path = self.root / "contracts.sqlite"
        build_fixture_db(self.db_path)
        self.index = SemanticContractIndex(self.db_path, enforce_final_counts=False)
        self.udid = "00112233-4455-6677-8899-aabbccddeeff"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _request_body(self) -> bytes:
        return cgss_codec.encode_body(
            {"viewer_id": "opaque", "story_id": 1},
            self.udid,
            dynamic_key=b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/octet-stream",
            "UDID": synthetic_header_encode(self.udid),
            "SID": "synthetic-sid",
            "APP-VER": "11.6.3",
            "RES-VER": "10133800",
        }

    def _serve(self, *, templates: ResponseTemplateStore | None = None, event_log: pathlib.Path | None = None):
        server = create_server(
            "127.0.0.1",
            0,
            semantic_index=self.index,
            response_templates=templates,
            event_log=event_log,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_known_contract_without_template_is_501_and_safely_annotated(self) -> None:
        event_log = self.root / "events.jsonl"
        server, thread = self._serve(event_log=event_log)
        host, port = server.server_address[:2]
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("POST", "/story/start", body=b"", headers={"Content-Length": "0"})
            response = conn.getresponse()
            self.assertEqual(response.status, 501)
            response.read()
            conn.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        event = json.loads(event_log.read_text(encoding="utf-8").strip())
        self.assertEqual(event["error"], "contract_known_template_missing")
        self.assertEqual(event["contract_candidates"][0]["endpoint_id"], 1)
        self.assertEqual(event["contract_candidates"][0]["required_response_field_count"], 1)
        self.assertEqual(event["contract_candidates"][0]["unknown_response_field_count"], 1)

    def test_explicit_unique_template_is_encoded_as_normal_success(self) -> None:
        template_path = self.root / "templates.json"
        template_path.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "routes": {
                        "/story/start": {
                            "endpoint_id": 1,
                            "data": {"story_id": 777, "result": []},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        templates = ResponseTemplateStore.load(template_path, semantic_index=self.index)
        server, thread = self._serve(templates=templates)
        host, port = server.server_address[:2]
        try:
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request(
                "POST",
                "/story/start",
                body=self._request_body(),
                headers=self._headers(),
            )
            response = conn.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
            conn.close()
            decoded = cgss_codec.decode_body(body, self.udid)
            self.assertEqual(decoded["data_headers"]["result_code"], 1)
            self.assertEqual(decoded["data_headers"]["sid"], "synthetic-sid")
            self.assertEqual(decoded["data"], {"story_id": 777, "result": []})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
