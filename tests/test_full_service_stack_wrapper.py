from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run-rooted-full-service-stack.py"
SPEC = importlib.util.spec_from_file_location("full_service_stack_wrapper", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


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
            INSERT INTO endpoints(id,route,enum,status,group_name,api_key)
              VALUES(1,'/safe/empty','SafeEmpty','proven-static','A',1);
            """
        )
        db.commit()
    finally:
        db.close()


def _write_catalog(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "endpoint_count": 1,
                "unique_route_count": 1,
                "duplicate_route_count": 0,
                "routes": [
                    {
                        "route": "/safe/empty",
                        "endpoints": [
                            {
                                "endpoint_id": 1,
                                "concrete_response_fields": [],
                                "exact_state_mutation_count": 0,
                                "effective_base_parsers": [
                                    {"response_scope": "common-envelope"}
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


class FullServiceStackWrapperTests(unittest.TestCase):
    def test_compiler_builds_c15_baseline_and_preserves_explicit_array_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            semantic = root / "semantic.sqlite"
            catalog = root / "c14.json"
            explicit = root / "explicit.json"
            output = root / "compiled.json"
            _write_semantic_db(semantic)
            _write_catalog(catalog)
            explicit.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "routes": {
                            "/safe/empty": {
                                "endpoint_id": 1,
                                "data": [{"id": 1}],
                                "evidence": "synthetic stronger evidence",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            counts = MODULE.compile_templates(
                semantic_db=semantic,
                effective_runtime_catalog=catalog,
                output=output,
                explicit_templates=explicit,
                enforce_final_counts=False,
            )
            self.assertEqual(counts, (1, 1, 1))
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(document["routes"]["/safe/empty"]["endpoint_id"], 1)
            self.assertEqual(document["routes"]["/safe/empty"]["data"], [{"id": 1}])
            self.assertEqual(
                document["routes"]["/safe/empty"]["evidence"],
                "synthetic stronger evidence",
            )

    def test_delegate_command_injects_semantics_templates_and_preserves_passthrough(self) -> None:
        semantic = Path("semantic.sqlite")
        templates = Path("compiled.json")
        command = MODULE.build_delegate_command(
            semantic_db=semantic,
            compiled_templates=templates,
            passthrough=("--api-port", "18080", "--accept-old-resource-version"),
        )
        self.assertEqual(command[0], sys.executable)
        self.assertTrue(command[1].endswith("scripts/run-rooted-local-stack.py"))
        self.assertEqual(command[2:6], (
            "--semantic-db", "semantic.sqlite", "--response-templates", "compiled.json"
        ))
        self.assertEqual(
            command[6:],
            ("--api-port", "18080", "--accept-old-resource-version"),
        )


if __name__ == "__main__":
    unittest.main()
