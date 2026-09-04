#!/usr/bin/env python3
"""Refine C7b direct state-consumer evidence after the first exact-specimen run.

This pass consumes only the sanitized C7b JSON. It keeps the raw direct-xref
counts unchanged, but removes direct-B self loops from promoted consumer
relations, separates unresolved BL from unresolved tail branches, and labels
compiler-generated consumer wrappers so later subsystem classification can use
the enclosing feature name without pretending the wrapper itself is a feature.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 2


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def generated_kind(name: str) -> str:
    if "<>c__DisplayClass" in name or ("$$<" in name and ">b__" in name):
        return "compiler-generated-lambda"
    if (".<" in name and ">d__" in name) or ("$$MoveNext" in name and "<" in name):
        return "async-or-iterator-state-machine"
    if "<>c$$" in name:
        return "compiler-generated-closure"
    return "regular"


def rel_key(row: dict[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("state_type"), row.get("reader_full_name"), row.get("reader_rva"),
        row.get("consumer_method"), row.get("consumer_rva"), row.get("edge_kind"),
    )


def ep_key(endpoint: dict[str, Any]) -> tuple[Any, ...]:
    return (
        endpoint.get("route"), endpoint.get("enum"), endpoint.get("group"),
        endpoint.get("key"), endpoint.get("status"),
    )


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--markdown-output", type=Path)
    a = p.parse_args()

    src = load(a.input)
    if int(src.get("schema", 0)) != 1:
        raise RuntimeError(f"expected C7b schema 1, got {src.get('schema')!r}")

    suppressed = []
    relations = []
    for row in src.get("relations", []):
        if (
            row.get("edge_kind") == "B-tail"
            and int(row.get("consumer_rva", -1)) == int(row.get("reader_rva", -2))
        ):
            suppressed.append(row)
            continue
        item = dict(row)
        item["consumer_generated_kind"] = generated_kind(str(item.get("consumer_method") or ""))
        relations.append(item)

    keep_keys = {rel_key(row) for row in relations}
    state_docs = []
    endpoint_state_consumer = set()
    for state in src.get("state_types", []):
        state_type = state["state_type"]
        readers = []
        state_relations = [row for row in relations if row.get("state_type") == state_type]
        for reader in state.get("readers", []):
            r = dict(reader)
            consumers = []
            for consumer in reader.get("consumers", []):
                if rel_key(consumer) not in keep_keys:
                    continue
                c = dict(consumer)
                c["consumer_generated_kind"] = generated_kind(str(c.get("consumer_method") or ""))
                consumers.append(c)
            r["consumers"] = consumers
            readers.append(r)
        unique_consumers = {
            (row.get("consumer_method"), int(row.get("consumer_rva", 0)))
            for row in state_relations
        }
        game_consumers = {
            (row.get("consumer_method"), int(row.get("consumer_rva", 0)))
            for row in state_relations if row.get("game_owned")
        }
        endpoints = state.get("upstream_endpoints", [])
        for endpoint in endpoints:
            for consumer_name, consumer_rva in unique_consumers:
                endpoint_state_consumer.add(ep_key(endpoint) + (state_type, consumer_name, consumer_rva))
        item = dict(state)
        item["readers"] = readers
        item["consumer_count"] = len(unique_consumers)
        item["game_owned_consumer_count"] = len(game_consumers)
        state_docs.append(item)

    unresolved_by_kind = Counter()
    ambiguous_by_kind = Counter()
    for row in src.get("ambiguous_or_unresolved_xrefs", []):
        confidence = row.get("confidence")
        kind = str(row.get("edge_kind") or "unknown")
        if confidence == "unresolved":
            unresolved_by_kind[kind] += 1
        elif confidence == "ambiguous":
            ambiguous_by_kind[kind] += 1

    consumer_methods = {(r["consumer_method"], r["consumer_rva"]) for r in relations}
    game_consumers = {
        (r["consumer_method"], r["consumer_rva"]) for r in relations if r.get("game_owned")
    }
    states_with_consumers = {r["state_type"] for r in relations}
    all_states = {s["state_type"] for s in state_docs}

    out = dict(src)
    out.update({
        "schema": SCHEMA,
        "source_schema": 1,
        "scope": "C7b refined direct state-reader consumer graph; BL high confidence, direct B tail medium, indirect BR/BLR unrecovered",
        "refinement_notes": [
            "direct B self loops are suppressed from promoted consumer relations",
            "unresolved xrefs are separated by BL vs B-tail evidence kind",
            "compiler-generated lambda/async/iterator wrappers are explicitly labeled",
            "shared reader/caller RVAs remain ambiguous rather than guessed apart",
        ],
        "relations": relations,
        "state_types": state_docs,
        "suppressed_self_tail_relations": suppressed,
        "self_tail_relation_suppressed_count": len(suppressed),
        "unique_reader_consumer_relation_count": len(relations),
        "consumer_method_count": len(consumer_methods),
        "game_owned_consumer_count": len(game_consumers),
        "state_types_with_consumers": len(states_with_consumers),
        "state_types_without_consumers": len(all_states - states_with_consumers),
        "endpoint_state_consumer_relation_count": len(endpoint_state_consumer),
        "unresolved_xref_edge_kind_counts": dict(sorted(unresolved_by_kind.items())),
        "ambiguous_xref_edge_kind_counts": dict(sorted(ambiguous_by_kind.items())),
        "relation_edge_kind_counts": dict(sorted(Counter(r["edge_kind"] for r in relations).items())),
        "consumer_generated_kind_counts": dict(sorted(Counter(r["consumer_generated_kind"] for r in relations).items())),
        "indirect_dispatch_status": "not recovered; BR/BLR and generic/interface dispatch remain conservative unknowns",
    })

    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(out, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if a.markdown_output:
        lines = [
            "# C7b refined state consumer graph", "",
            "Direct native xref evidence only. Indirect BR/BLR dispatch is still not recovered.", "",
            f"- state types: **{out['state_type_count']}**",
            f"- reader methods: **{out['reader_method_count']}**",
            f"- direct reader xrefs: **{out['reader_xref_count']}**",
            f"- reader→consumer relations: **{out['unique_reader_consumer_relation_count']}**",
            f"- consumer methods: **{out['consumer_method_count']}**",
            f"- game-owned consumer methods: **{out['game_owned_consumer_count']}**",
            f"- state types with consumers: **{out['state_types_with_consumers']}**",
            f"- endpoint→state→consumer relations: **{out['endpoint_state_consumer_relation_count']}**",
            f"- suppressed direct-B self loops: **{out['self_tail_relation_suppressed_count']}**",
            f"- unresolved by edge kind: `{out['unresolved_xref_edge_kind_counts']}`", "",
            "## Generated consumer wrappers", "",
        ]
        lines.extend(f"- `{k}`: **{v}**" for k, v in out["consumer_generated_kind_counts"].items())
        a.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({k: out[k] for k in (
        "state_type_count", "reader_method_count", "reader_xref_count",
        "unique_reader_consumer_relation_count", "consumer_method_count",
        "game_owned_consumer_count", "state_types_with_consumers",
        "endpoint_state_consumer_relation_count", "self_tail_relation_suppressed_count",
        "unresolved_xref_edge_kind_counts", "ambiguous_xref_edge_kind_counts",
        "relation_edge_kind_counts", "consumer_generated_kind_counts",
    )}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
