from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from server.dead_value_templates import DeadValueTemplateError, load_dead_value_templates
from server.semantic_contracts import SemanticContractIndex


def _semantic(path: Path) -> SemanticContractIndex:
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
              VALUES(1,'/dead/value','DeadValue','proven-static','A',1);
            """
        )
        db.commit()
    finally:
        db.close()
    return SemanticContractIndex(path, enforce_final_counts=False)


def _report(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "route": "/dead/value",
                "endpoint_id": 1,
                "task": "Stage.SyntheticDeadTask",
                "method": "Stage.SyntheticDeadTask$$Parse",
                "parser_data_value_class": "dead-value",
                "parser_local_arbitrary_json_value_safe": True,
                "empty_object_promotion": "parser-local-safe-if-field-present",
                "semantic_sink_count": 0,
                "semantic_sinks": [],
                "reachable_unresolved_control_flow": [],
                "reachable_normal_return_count": 1,
                "reachable_managed_tail_exit_count": 0,
                "untouched_client_acceptance": False,
                "ui_visible_success": False,
            }
        ),
        encoding="utf-8",
    )


class DeadValueTemplateTests(unittest.TestCase):
    def test_dead_value_proof_promotes_deterministic_empty_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            semantic = _semantic(root / "semantic.sqlite")
            report = root / "c27.json"
            _report(report)
            store = load_dead_value_templates(
                report,
                semantic_index=semantic,
                enforce_final_identity=False,
            )
            self.assertEqual(store.routes, ("/dead/value",))
            template = store.get("/dead/value")
            self.assertIsNotNone(template)
            assert template is not None
            self.assertEqual(template.endpoint_id, 1)
            self.assertEqual(template.data, {})
            self.assertIn("dead-value proof", template.evidence or "")

    def test_sink_or_unresolved_flow_blocks_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            semantic = _semantic(root / "semantic.sqlite")
            report = root / "c27.json"
            _report(report)
            doc = json.loads(report.read_text(encoding="utf-8"))
            doc["semantic_sink_count"] = 1
            doc["semantic_sinks"] = [{"kind": "call-argument"}]
            report.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(DeadValueTemplateError):
                load_dead_value_templates(
                    report,
                    semantic_index=semantic,
                    enforce_final_identity=False,
                )

            _report(report)
            doc = json.loads(report.read_text(encoding="utf-8"))
            doc["reachable_unresolved_control_flow"] = [{"kind": "indirect-branch"}]
            report.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(DeadValueTemplateError):
                load_dead_value_templates(
                    report,
                    semantic_index=semantic,
                    enforce_final_identity=False,
                )


if __name__ == "__main__":
    unittest.main()
