from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from server.parser_overlays import EffectiveParserOverlayIndex
from server.semantic_contracts import SemanticContractIndex


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
                (1, "/load/index", "LoadIndex", "proven-static", "A", 1),
                (2, "/story/start", "StoryStart", "proven-static", "A", 2),
            ],
        )
        db.executemany(
            "INSERT INTO request_fields(id,endpoint_id) VALUES(?,?)",
            [(1, 1), (2, 1)],
        )
        db.execute(
            "INSERT INTO response_fields(id,endpoint_id,task,method,field,requiredness,value_types_json) "
            "VALUES(?,?,?,?,?,?,?)",
            (1, 1, "Stage.LoadTask", "Stage.LoadTask$$Parse", "user_data", "required-path", '["object"]'),
        )
        db.executemany(
            "INSERT INTO endpoint_state_mutations(endpoint_id,mutation_id) VALUES(?,?)",
            [(1, 1), (1, 2), (1, 3), (2, 4)],
        )
        db.executemany(
            "INSERT INTO subsystems(id,name) VALUES(?,?)",
            [(1, "home"), (2, "story-commu")],
        )
        db.executemany(
            "INSERT INTO endpoint_subsystems(endpoint_id,state_type,subsystem_id) VALUES(?,?,?)",
            [
                (1, "Stage.WorkHomeData", 1),
                (2, "Stage.WorkStoryData", 2),
            ],
        )
        db.commit()
    finally:
        db.close()


def _write_overlay(
    path: Path,
    *,
    route: str = "/load/index",
    provenance_kind: str = "direct-BL",
) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "overlays": [
                    {
                        "endpoint": {"endpoint_id": 1, "route": route},
                        "base_task": "Stage.BaseTask",
                        "base_parser_method": "Stage.BaseTask$$Parse",
                        "base_parser_rva": 4660,
                        "fields": [
                            {"field": "data", "requiredness": "required-path"},
                            {"field": "result_code", "requiredness": "unknown-cfg"},
                        ],
                        "provenance": [{"kind": provenance_kind}],
                    }
                ],
                "residual_unmapped_method_count": 1,
                "residual_unmapped_methods": ["Stage.BusBaseTask$$EventInfoParse"],
            }
        ),
        encoding="utf-8",
    )


def _semantic_index(tmp_path: Path) -> SemanticContractIndex:
    db = tmp_path / "semantic.sqlite"
    _write_semantic_db(db)
    return SemanticContractIndex(db, enforce_final_counts=False)


def test_overlay_index_exposes_safe_aggregate_summary(tmp_path: Path) -> None:
    semantic = _semantic_index(tmp_path)
    overlay = tmp_path / "overlay.json"
    _write_overlay(overlay)

    index = EffectiveParserOverlayIndex(
        overlay,
        semantic_index=semantic,
        enforce_final_counts=False,
    )

    assert index.endpoint_count == 1
    assert index.relation_count == 1
    assert index.field_link_count == 2
    assert index.endpoint_overlays(2) == ()
    assert index.safe_endpoint_summary(1) == {
        "effective_base_parser_count": 1,
        "effective_base_field_link_count": 2,
        "effective_base_required_field_link_count": 1,
        "effective_base_unknown_field_link_count": 1,
        "effective_base_provenance": ["direct-BL"],
    }


def test_overlay_index_rejects_c9_route_mismatch(tmp_path: Path) -> None:
    semantic = _semantic_index(tmp_path)
    overlay = tmp_path / "overlay.json"
    _write_overlay(overlay, route="/wrong/path")

    with pytest.raises(ValueError, match="C13/C9 endpoint route mismatch"):
        EffectiveParserOverlayIndex(
            overlay,
            semantic_index=semantic,
            enforce_final_counts=False,
        )


def test_overlay_index_rejects_unsupported_provenance(tmp_path: Path) -> None:
    semantic = _semantic_index(tmp_path)
    overlay = tmp_path / "overlay.json"
    _write_overlay(overlay, provenance_kind="heuristic")

    with pytest.raises(ValueError, match="unsupported C13 provenance kind"):
        EffectiveParserOverlayIndex(
            overlay,
            semantic_index=semantic,
            enforce_final_counts=False,
        )
