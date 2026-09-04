#!/usr/bin/env python3
"""C9: extend the C6 endpoint contract SQLite with C7a/C7b/C8 semantics.

Inputs are sanitized semantic artifacts only. Existing C6 endpoint IDs are
preserved exactly, including duplicate route+enum records.

Evidence levels remain distinct:
- endpoint_state_mutations: exact C7a endpoint candidate -> parser mutator relation.
- endpoint_state_consumers: state-surface bridge from an endpoint known to mutate a
  state type to a direct C7b reader consumer of the same state type.
The second relation is useful feature-discovery evidence but is not represented as
endpoint-specific control-flow proof.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
from collections import defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 2


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def norm_route(value: Any) -> str:
    route = str(value or "")
    return route if route.startswith("/") else "/" + route


def norm_key(value: Any) -> Any:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def ep_identity(route: Any, enum: Any, status: Any, group: Any, key: Any) -> tuple[Any, ...]:
    return (norm_route(route), enum, status, group, norm_key(key))


def json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--c6-sqlite", type=Path, required=True)
    p.add_argument("--c7a", type=Path, required=True)
    p.add_argument("--c7b", type=Path, required=True)
    p.add_argument("--c8", type=Path, required=True)
    p.add_argument("--sqlite-output", type=Path, required=True)
    p.add_argument("--json-output", type=Path, required=True)
    p.add_argument("--markdown-output", type=Path)
    a = p.parse_args()

    c7a, c7b, c8 = load(a.c7a), load(a.c7b), load(a.c8)
    if c7a.get("schema") != 1:
        raise RuntimeError("unsupported C7a schema")
    if c7b.get("schema") != 2:
        raise RuntimeError("expected refined C7b schema 2")
    if c8.get("schema") != 1:
        raise RuntimeError("unsupported C8 schema")
    if c8.get("relation_count") != c7b.get("unique_reader_consumer_relation_count"):
        raise RuntimeError("C7b/C8 relation count mismatch")

    a.sqlite_output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(a.c6_sqlite, a.sqlite_output)
    db = sqlite3.connect(a.sqlite_output)
    db.row_factory = sqlite3.Row
    try:
        db.execute("PRAGMA foreign_keys=ON")
        if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise RuntimeError("input C6 sqlite failed quick_check")

        endpoint_map: dict[tuple[Any, ...], list[int]] = defaultdict(list)
        for row in db.execute("SELECT id,route,enum,status,group_name,api_key FROM endpoints ORDER BY id"):
            endpoint_map[ep_identity(row["route"], row["enum"], row["status"], row["group_name"], row["api_key"])].append(int(row["id"]))

        db.executescript("""
        DROP VIEW IF EXISTS endpoint_semantics;
        DROP VIEW IF EXISTS endpoint_state_edges;
        DROP VIEW IF EXISTS endpoint_state_consumer_methods;
        DROP TABLE IF EXISTS endpoint_subsystems;
        DROP TABLE IF EXISTS endpoint_state_consumers;
        DROP TABLE IF EXISTS endpoint_state_mutations;
        DROP TABLE IF EXISTS state_consumers;
        DROP TABLE IF EXISTS state_readers;
        DROP TABLE IF EXISTS state_mutations;
        DROP TABLE IF EXISTS subsystems;

        CREATE TABLE subsystems(
          id INTEGER PRIMARY KEY,
          name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE state_mutations(
          id INTEGER PRIMARY KEY,
          task TEXT,
          parser TEXT NOT NULL,
          parser_rva INTEGER,
          state_type TEXT NOT NULL,
          state_category TEXT,
          operation TEXT NOT NULL,
          target TEXT NOT NULL,
          target_rva INTEGER,
          mutation_kind TEXT,
          confidence TEXT,
          call_count INTEGER,
          call_rvas_json TEXT,
          evidence TEXT
        );
        CREATE TABLE state_readers(
          id INTEGER PRIMARY KEY,
          state_type TEXT NOT NULL,
          reader_method TEXT NOT NULL,
          reader_full_name TEXT NOT NULL,
          reader_rva INTEGER NOT NULL,
          reader_kind TEXT,
          signature TEXT,
          UNIQUE(state_type,reader_full_name,reader_rva)
        );
        CREATE TABLE state_consumers(
          id INTEGER PRIMARY KEY,
          reader_id INTEGER NOT NULL,
          state_type TEXT NOT NULL,
          reader_full_name TEXT NOT NULL,
          reader_rva INTEGER NOT NULL,
          consumer_method TEXT NOT NULL,
          consumer_rva INTEGER NOT NULL,
          edge_kind TEXT NOT NULL,
          xref_confidence TEXT,
          call_count INTEGER,
          callsite_rvas_json TEXT,
          game_owned INTEGER NOT NULL,
          consumer_relevance TEXT,
          consumer_generated_kind TEXT,
          zero_offset_tail_thunk INTEGER NOT NULL DEFAULT 0,
          classification_status TEXT NOT NULL,
          classification_confidence TEXT NOT NULL,
          subsystem_id INTEGER,
          subsystem_score INTEGER,
          subsystem_runner_up_score INTEGER,
          classification_evidence_json TEXT,
          xref_evidence TEXT,
          FOREIGN KEY(reader_id) REFERENCES state_readers(id),
          FOREIGN KEY(subsystem_id) REFERENCES subsystems(id)
        );
        CREATE TABLE endpoint_state_mutations(
          endpoint_id INTEGER NOT NULL,
          mutation_id INTEGER NOT NULL,
          confidence TEXT NOT NULL,
          evidence TEXT,
          PRIMARY KEY(endpoint_id,mutation_id),
          FOREIGN KEY(endpoint_id) REFERENCES endpoints(id),
          FOREIGN KEY(mutation_id) REFERENCES state_mutations(id)
        );
        CREATE TABLE endpoint_state_consumers(
          endpoint_id INTEGER NOT NULL,
          consumer_id INTEGER NOT NULL,
          state_type TEXT NOT NULL,
          bridge_kind TEXT NOT NULL,
          confidence TEXT NOT NULL,
          evidence TEXT NOT NULL,
          PRIMARY KEY(endpoint_id,consumer_id),
          FOREIGN KEY(endpoint_id) REFERENCES endpoints(id),
          FOREIGN KEY(consumer_id) REFERENCES state_consumers(id)
        );
        CREATE TABLE endpoint_subsystems(
          endpoint_id INTEGER NOT NULL,
          state_type TEXT NOT NULL,
          subsystem_id INTEGER NOT NULL,
          confidence TEXT NOT NULL,
          evidence TEXT NOT NULL,
          PRIMARY KEY(endpoint_id,state_type,subsystem_id),
          FOREIGN KEY(endpoint_id) REFERENCES endpoints(id),
          FOREIGN KEY(subsystem_id) REFERENCES subsystems(id)
        );

        CREATE INDEX idx_mutation_state ON state_mutations(state_type);
        CREATE INDEX idx_reader_state ON state_readers(state_type);
        CREATE INDEX idx_consumer_state ON state_consumers(state_type);
        CREATE INDEX idx_consumer_method ON state_consumers(consumer_method);
        CREATE INDEX idx_consumer_subsystem ON state_consumers(subsystem_id);
        CREATE INDEX idx_ep_mut_endpoint ON endpoint_state_mutations(endpoint_id);
        CREATE INDEX idx_ep_cons_endpoint ON endpoint_state_consumers(endpoint_id);
        CREATE INDEX idx_ep_sub_endpoint ON endpoint_subsystems(endpoint_id);
        """)

        subsystem_ids: dict[str, int] = {}
        for name in c8.get("taxonomy", []):
            cur = db.execute("INSERT INTO subsystems(name) VALUES (?)", (name,))
            subsystem_ids[name] = int(cur.lastrowid)

        unmatched_endpoint_candidates: list[dict[str, Any]] = []
        state_endpoint_ids: dict[str, set[int]] = defaultdict(set)
        mutation_bound_relation_count = 0
        for rel in c7a.get("relations", []):
            cur = db.execute("""INSERT INTO state_mutations(
              task,parser,parser_rva,state_type,state_category,operation,target,target_rva,
              mutation_kind,confidence,call_count,call_rvas_json,evidence)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                rel.get("task"), rel.get("parser"), rel.get("parser_rva"), rel.get("state_type"),
                rel.get("state_category"), rel.get("operation"), rel.get("target"), rel.get("target_rva"),
                rel.get("mutation_kind"), rel.get("confidence"), rel.get("call_count"),
                json_text(rel.get("call_rvas", [])), rel.get("evidence")))
            mutation_id = int(cur.lastrowid)
            matched_any = False
            for ep in rel.get("endpoint_candidates", []):
                ident = ep_identity(ep.get("route"), ep.get("enum"), ep.get("status"), ep.get("group"), ep.get("key"))
                endpoint_ids = endpoint_map.get(ident, [])
                if not endpoint_ids:
                    unmatched_endpoint_candidates.append({"mutation_id": mutation_id, "endpoint": ep})
                    continue
                matched_any = True
                for endpoint_id in endpoint_ids:
                    db.execute("""INSERT OR IGNORE INTO endpoint_state_mutations(endpoint_id,mutation_id,confidence,evidence)
                                  VALUES (?,?,?,?)""", (endpoint_id, mutation_id, rel.get("confidence") or "unknown",
                                  "exact C7a endpoint candidate -> response parser state mutator binding"))
                    state_endpoint_ids[str(rel.get("state_type"))].add(endpoint_id)
            if matched_any:
                mutation_bound_relation_count += 1

        reader_ids: dict[tuple[str, str, int], int] = {}
        reader_count = 0
        for state in c7b.get("state_types", []):
            state_type = str(state["state_type"])
            for reader in state.get("readers", []):
                cur = db.execute("""INSERT INTO state_readers(
                  state_type,reader_method,reader_full_name,reader_rva,reader_kind,signature)
                  VALUES (?,?,?,?,?,?)""", (state_type, reader.get("method"), reader.get("full_name"),
                  reader.get("rva"), reader.get("reader_kind"), reader.get("signature")))
                reader_id = int(cur.lastrowid)
                reader_ids[(state_type, str(reader.get("full_name")), int(reader.get("rva", 0)))] = reader_id
                reader_count += 1

        consumer_ids_by_state: dict[str, list[int]] = defaultdict(list)
        classified_consumer_count = 0
        missing_readers: list[tuple[str, str, int]] = []
        for rel in c8.get("relations", []):
            key = (str(rel.get("state_type")), str(rel.get("reader_full_name")), int(rel.get("reader_rva", 0)))
            reader_id = reader_ids.get(key)
            if reader_id is None:
                missing_readers.append(key)
                continue
            classification = rel.get("subsystem") or {}
            primary = classification.get("primary_subsystem")
            subsystem_id = subsystem_ids.get(primary) if primary else None
            if primary:
                classified_consumer_count += 1
            cur = db.execute("""INSERT INTO state_consumers(
              reader_id,state_type,reader_full_name,reader_rva,consumer_method,consumer_rva,edge_kind,
              xref_confidence,call_count,callsite_rvas_json,game_owned,consumer_relevance,
              consumer_generated_kind,zero_offset_tail_thunk,classification_status,
              classification_confidence,subsystem_id,subsystem_score,subsystem_runner_up_score,
              classification_evidence_json,xref_evidence)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                reader_id, rel.get("state_type"), rel.get("reader_full_name"), rel.get("reader_rva"),
                rel.get("consumer_method"), rel.get("consumer_rva"), rel.get("edge_kind"), rel.get("confidence"),
                rel.get("call_count"), json_text(rel.get("callsite_rvas", [])), 1 if rel.get("game_owned") else 0,
                rel.get("consumer_relevance"), rel.get("consumer_generated_kind"),
                1 if rel.get("zero_offset_tail_thunk") else 0,
                classification.get("status") or "unknown", classification.get("confidence") or "unknown",
                subsystem_id, classification.get("score"), classification.get("runner_up_score"),
                json_text(classification), rel.get("evidence")))
            consumer_ids_by_state[str(rel.get("state_type"))].append(int(cur.lastrowid))

        if missing_readers:
            raise RuntimeError(f"C8 relations reference {len(missing_readers)} missing readers")

        endpoint_subsystem_keys: set[tuple[int, str, int]] = set()
        for state_type, consumer_ids in consumer_ids_by_state.items():
            for endpoint_id in state_endpoint_ids.get(state_type, set()):
                for consumer_id in consumer_ids:
                    db.execute("""INSERT OR IGNORE INTO endpoint_state_consumers(
                      endpoint_id,consumer_id,state_type,bridge_kind,confidence,evidence)
                      VALUES (?,?,?,?,?,?)""", (endpoint_id, consumer_id, state_type, "state-surface",
                      "inferred-state-bridge",
                      "endpoint mutates state type by C7a; consumer directly reads same state type by C7b"))
                    subsystem_row = db.execute("SELECT subsystem_id FROM state_consumers WHERE id=?", (consumer_id,)).fetchone()
                    subsystem_id = subsystem_row["subsystem_id"] if subsystem_row else None
                    if subsystem_id is not None:
                        endpoint_subsystem_keys.add((endpoint_id, state_type, int(subsystem_id)))
        for endpoint_id, state_type, subsystem_id in sorted(endpoint_subsystem_keys):
            db.execute("""INSERT INTO endpoint_subsystems(endpoint_id,state_type,subsystem_id,confidence,evidence)
                          VALUES (?,?,?,?,?)""", (endpoint_id, state_type, subsystem_id, "inferred-state-bridge",
                          "classified consumer of a state surface mutated by endpoint"))

        db.executescript("""
        CREATE VIEW endpoint_state_consumer_methods AS
        SELECT DISTINCT esc.endpoint_id, esc.state_type, sc.consumer_method, sc.consumer_rva
        FROM endpoint_state_consumers esc
        JOIN state_consumers sc ON sc.id=esc.consumer_id;

        CREATE VIEW endpoint_state_edges AS
        SELECT esm.endpoint_id, sm.state_type, 'mutation' AS edge_kind,
               esm.mutation_id, NULL AS consumer_id, NULL AS subsystem_id,
               esm.confidence, esm.evidence
        FROM endpoint_state_mutations esm
        JOIN state_mutations sm ON sm.id=esm.mutation_id
        UNION ALL
        SELECT esc.endpoint_id, esc.state_type, 'consumer' AS edge_kind,
               NULL AS mutation_id, esc.consumer_id, sc.subsystem_id,
               esc.confidence, esc.evidence
        FROM endpoint_state_consumers esc
        JOIN state_consumers sc ON sc.id=esc.consumer_id;

        CREATE VIEW endpoint_semantics AS
        SELECT
          e.id AS endpoint_id, e.route, e.enum, e.status, e.group_name, e.api_key,
          (SELECT COUNT(*) FROM request_fields rf WHERE rf.endpoint_id=e.id) AS request_field_count,
          (SELECT COUNT(*) FROM response_fields rf WHERE rf.endpoint_id=e.id) AS response_field_count,
          (SELECT COUNT(*) FROM endpoint_state_mutations x WHERE x.endpoint_id=e.id) AS exact_state_mutation_count,
          (SELECT COUNT(*) FROM endpoint_state_consumers x WHERE x.endpoint_id=e.id) AS inferred_state_consumer_relation_count,
          (SELECT COUNT(*) FROM endpoint_state_consumer_methods x WHERE x.endpoint_id=e.id) AS inferred_state_consumer_method_count,
          COALESCE((SELECT json_group_array(json_object(
                    'task',rf.task,'field',rf.field,'managed_type',rf.managed_type,'confidence',rf.confidence))
                    FROM request_fields rf WHERE rf.endpoint_id=e.id),'[]') AS request_fields_json,
          COALESCE((SELECT json_group_array(json_object(
                    'task',rf.task,'field',rf.field,'requiredness',rf.requiredness,'value_types',json(rf.value_types_json)))
                    FROM response_fields rf WHERE rf.endpoint_id=e.id),'[]') AS response_fields_json,
          COALESCE((SELECT json_group_array(json_object(
                    'state_type',sm.state_type,'operation',sm.operation,'mutation_kind',sm.mutation_kind,'confidence',x.confidence))
                    FROM endpoint_state_mutations x JOIN state_mutations sm ON sm.id=x.mutation_id
                    WHERE x.endpoint_id=e.id),'[]') AS state_mutations_json,
          COALESCE((SELECT json_group_array(DISTINCT sm.state_type)
                    FROM endpoint_state_mutations x JOIN state_mutations sm ON sm.id=x.mutation_id
                    WHERE x.endpoint_id=e.id),'[]') AS state_types_json,
          COALESCE((SELECT json_group_array(DISTINCT s.name)
                    FROM endpoint_subsystems es JOIN subsystems s ON s.id=es.subsystem_id
                    WHERE es.endpoint_id=e.id),'[]') AS inferred_subsystems_json
        FROM endpoints e;
        """)

        counts = {
            "endpoint_count": db.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0],
            "state_mutation_count": db.execute("SELECT COUNT(*) FROM state_mutations").fetchone()[0],
            "state_reader_count": db.execute("SELECT COUNT(*) FROM state_readers").fetchone()[0],
            "state_consumer_count": db.execute("SELECT COUNT(*) FROM state_consumers").fetchone()[0],
            "subsystem_count": db.execute("SELECT COUNT(*) FROM subsystems").fetchone()[0],
            "endpoint_state_mutation_link_count": db.execute("SELECT COUNT(*) FROM endpoint_state_mutations").fetchone()[0],
            "endpoint_state_consumer_relation_bridge_count": db.execute("SELECT COUNT(*) FROM endpoint_state_consumers").fetchone()[0],
            "endpoint_state_consumer_method_bridge_count": db.execute("SELECT COUNT(*) FROM endpoint_state_consumer_methods").fetchone()[0],
            "endpoint_subsystem_link_count": db.execute("SELECT COUNT(*) FROM endpoint_subsystems").fetchone()[0],
            "endpoint_semantics_count": db.execute("SELECT COUNT(*) FROM endpoint_semantics").fetchone()[0],
        }
        metadata = {
            "semantic_db_schema": SCHEMA,
            "c7a_mutation_relation_count": len(c7a.get("relations", [])),
            "c7b_reader_count": reader_count,
            "c7b_consumer_relation_count": len(c8.get("relations", [])),
            "c8_classified_consumer_relation_count": classified_consumer_count,
            **{k: v for k, v in counts.items() if k.startswith("endpoint_")},
            "unmatched_c7a_endpoint_candidate_count": len(unmatched_endpoint_candidates),
            "consumer_bridge_evidence_level": "inferred-state-bridge",
        }
        db.executemany("INSERT OR REPLACE INTO metadata(key,value) VALUES (?,?)",
                       [(k, json_text(v)) for k, v in metadata.items()])
        db.commit()

        quick_check = db.execute("PRAGMA quick_check").fetchone()[0]
        report = {
            "schema": SCHEMA,
            "scope": "C9 semantic DB upgrade: C6 request/response + C7a exact state mutations + C7b direct consumers + C8 conservative subsystem labels",
            "quick_check": quick_check,
            **counts,
            "c7a_bound_relation_count": mutation_bound_relation_count,
            "c7a_unmatched_endpoint_candidate_count": len(unmatched_endpoint_candidates),
            "c8_classified_relation_count": classified_consumer_count,
            "c8_ambiguous_relation_count": c8.get("ambiguous_relation_count"),
            "c8_unknown_relation_count": c8.get("unknown_relation_count"),
            "bridge_policy": {
                "endpoint_to_mutation": "exact C7a endpoint candidate binding",
                "mutation_state_to_consumer": "state-surface inference; not endpoint-specific control-flow proof",
                "upstream_route_used_for_c8_classification": False,
            },
            "unmatched_endpoint_candidates": unmatched_endpoint_candidates[:100],
        }
        if quick_check != "ok":
            raise RuntimeError(f"output quick_check={quick_check!r}")
        if counts["endpoint_count"] != 538:
            raise RuntimeError("endpoint identity/count changed")
        if counts["state_mutation_count"] != c7a.get("mutation_relation_count"):
            raise RuntimeError("mutation count mismatch")
        if counts["state_reader_count"] != c7b.get("reader_method_count"):
            raise RuntimeError("reader count mismatch")
        if counts["state_consumer_count"] != c8.get("relation_count"):
            raise RuntimeError("consumer count mismatch")
        if counts["endpoint_state_consumer_method_bridge_count"] != c7b.get("endpoint_state_consumer_relation_count"):
            raise RuntimeError("endpoint/state/consumer method bridge count mismatch")
        if len(unmatched_endpoint_candidates) != 0:
            raise RuntimeError(f"unmatched endpoint candidates: {len(unmatched_endpoint_candidates)}")
    finally:
        db.close()

    a.json_output.parent.mkdir(parents=True, exist_ok=True)
    a.json_output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if a.markdown_output:
        lines = [
            "# C9 client semantic contract DB", "",
            f"- SQLite quick_check: **{report['quick_check']}**",
            f"- endpoints preserved: **{report['endpoint_count']}**",
            f"- state mutations: **{report['state_mutation_count']}**",
            f"- state readers: **{report['state_reader_count']}**",
            f"- state consumers: **{report['state_consumer_count']}**",
            f"- classified consumer relations: **{report['c8_classified_relation_count']}**",
            f"- exact endpoint→mutation links: **{report['endpoint_state_mutation_link_count']}**",
            f"- inferred endpoint→state→consumer relation bridges: **{report['endpoint_state_consumer_relation_bridge_count']}**",
            f"- inferred endpoint→state→consumer method bridges: **{report['endpoint_state_consumer_method_bridge_count']}**",
            f"- inferred endpoint→state→subsystem links: **{report['endpoint_subsystem_link_count']}**", "",
            "Exact C7a endpoint→mutation evidence and inferred state-surface consumer bridges are stored separately.",
            "`endpoint_semantics` preserves independent endpoint IDs; route+enum is not treated as unique.", "",
        ]
        a.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        a.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
