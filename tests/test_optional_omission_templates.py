from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from server.optional_omission_templates import load_optional_omission_templates
from server.semantic_contracts import SemanticContractIndex


def _db(path: Path) -> SemanticContractIndex:
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
                (1, "/optional", "Optional", "proven-static", "A", 1),
                (2, "/required", "Required", "proven-static", "A", 2),
                (3, "/stateful", "Stateful", "proven-static", "A", 3),
                (4, "/base", "Base", "proven-static", "A", 4),
            ],
        )
        db.commit()
    finally:
        db.close()
    return SemanticContractIndex(path, enforce_final_counts=False)


def _field(name: str, requiredness: str) -> dict:
    return {
        "field": name,
        "task": "Stage.SyntheticTask",
        "method": "Stage.SyntheticTask$$Parse",
        "requiredness": requiredness,
        "value_types": ["int"],
    }


def _endpoint(endpoint_id: int, fields: list[dict], *, mutations: int = 0, non_common_base: bool = False) -> dict:
    overlays = [{"response_scope": "common-envelope"}]
    if non_common_base:
        overlays.append({"response_scope": "base-parser-surface"})
    return {
        "endpoint_id": endpoint_id,
        "concrete_response_fields": fields,
        "exact_state_mutation_count": mutations,
        "effective_base_parsers": overlays,
    }


def _catalog(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "endpoint_count": 4,
                "unique_route_count": 4,
                "duplicate_route_count": 0,
                "routes": [
                    {
                        "route": "/optional",
                        "endpoints": [
                            _endpoint(
                                1,
                                [
                                    _field("rank", "optional-defaulted"),
                                    _field("list", "optional-conditional"),
                                ],
                            )
                        ],
                    },
                    {
                        "route": "/required",
                        "endpoints": [_endpoint(2, [_field("rank", "required-path")])],
                    },
                    {
                        "route": "/stateful",
                        "endpoints": [
                            _endpoint(3, [_field("rank", "optional-defaulted")], mutations=1)
                        ],
                    },
                    {
                        "route": "/base",
                        "endpoints": [
                            _endpoint(4, [_field("rank", "optional-defaulted")], non_common_base=True)
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )


class OptionalOmissionTemplateTests(unittest.TestCase):
    def test_only_all_optional_stateless_common_envelope_route_is_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = _db(root / "semantic.sqlite")
            catalog = root / "c14.json"
            _catalog(catalog)
            store = load_optional_omission_templates(
                catalog,
                semantic_index=index,
                enforce_final_counts=False,
            )
            self.assertEqual(store.routes, ("/optional",))
            template = store.get("/optional")
            self.assertIsNotNone(template)
            assert template is not None
            self.assertEqual(template.endpoint_id, 1)
            self.assertEqual(template.data, {})
            self.assertIn("parser-proven omission", template.evidence or "")

    def test_required_unknown_or_state_semantics_are_not_guessed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            index = _db(root / "semantic.sqlite")
            catalog = root / "c14.json"
            _catalog(catalog)
            doc = json.loads(catalog.read_text())
            doc["routes"][0]["endpoints"][0]["concrete_response_fields"][0]["requiredness"] = "unknown-cfg"
            catalog.write_text(json.dumps(doc), encoding="utf-8")
            store = load_optional_omission_templates(
                catalog,
                semantic_index=index,
                enforce_final_counts=False,
            )
            self.assertEqual(store.count, 0)


if __name__ == "__main__":
    unittest.main()
