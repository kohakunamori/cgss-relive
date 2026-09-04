from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from server.response_templates import ResponseTemplateStore
from server.semantic_contracts import SemanticContractIndex
from server.template_response import build_template_success_payload


def _db(path: Path) -> None:
    db = sqlite3.connect(path)
    try:
        db.executescript(
            """
            CREATE TABLE endpoints(id INTEGER PRIMARY KEY, route TEXT NOT NULL, enum TEXT, status TEXT, group_name TEXT, api_key INTEGER);
            CREATE TABLE request_fields(id INTEGER PRIMARY KEY, endpoint_id INTEGER);
            CREATE TABLE response_fields(id INTEGER PRIMARY KEY, endpoint_id INTEGER, task TEXT NOT NULL, method TEXT, field TEXT NOT NULL, requiredness TEXT, value_types_json TEXT);
            CREATE TABLE endpoint_state_mutations(endpoint_id INTEGER, mutation_id INTEGER);
            CREATE TABLE subsystems(id INTEGER PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE endpoint_subsystems(endpoint_id INTEGER, state_type TEXT, subsystem_id INTEGER);
            CREATE VIEW endpoint_semantics AS SELECT id AS endpoint_id, route FROM endpoints;
            INSERT INTO endpoints(id,route,enum,status,group_name,api_key) VALUES(1,'/list/data','ListData','proven-static','A',1);
            """
        )
        db.commit()
    finally:
        db.close()


class TemplateResponseShapeTests(unittest.TestCase):
    def test_success_payload_preserves_array_and_scalar_data_shapes(self) -> None:
        array = [1, {"x": 2}]
        payload = build_template_success_payload(array, sid="s", servertime=10)
        self.assertEqual(payload["data"], array)
        self.assertIsNot(payload["data"], array)
        self.assertEqual(payload["data_headers"], {"result_code": 1, "servertime": 10, "sid": "s"})

        self.assertIsNone(build_template_success_payload(None, servertime=11)["data"])
        self.assertEqual(build_template_success_payload("ok", servertime=12)["data"], "ok")

    def test_template_store_loads_json_array_without_coercion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "semantic.sqlite"
            _db(db_path)
            semantic = SemanticContractIndex(db_path, enforce_final_counts=False)
            template_path = root / "templates.json"
            template_path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "routes": {
                            "/list/data": {
                                "endpoint_id": 1,
                                "data": [{"id": 1}, {"id": 2}],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            store = ResponseTemplateStore.load(template_path, semantic_index=semantic)
            template = store.get("/list/data")
            self.assertIsNotNone(template)
            assert template is not None
            self.assertEqual(template.data, [{"id": 1}, {"id": 2}])


if __name__ == "__main__":
    unittest.main()
