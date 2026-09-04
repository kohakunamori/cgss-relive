#!/usr/bin/env python3
"""C7b: derive client-state reader -> direct native consumer edges.

The analyzer starts from the C7a response->state mutation graph, selects reader-like
methods owned by those state types from Il2CppDumper ``script.json``, then scans the
executable ARM64 PT_LOAD ranges for direct BL/B immediates whose exact destination
is a selected reader RVA. Call sites are mapped back to the containing managed
method using Il2CppDumper's complete address boundary set.

Evidence is intentionally conservative:
- exact state-owner + reader verb is required;
- direct BL is high-confidence call evidence;
- direct B to an exact reader RVA is retained as tail-call evidence, separately;
- shared reader RVAs and shared caller starts are preserved as ambiguous rather
  than guessed apart;
- framework/third-party consumers are retained with lower relevance instead of
  being silently dropped.

This is native direct-xref evidence. It does not recover indirect BR/BLR dispatch.
"""
from __future__ import annotations

import argparse
import bisect
import json
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

SCHEMA = 1

READER_PREFIXES = (
    "get_", "Get", "Is", "Has", "Find", "Contains", "Exists", "Check",
    "Can", "Current", "Count", "TryGet",
)
MUTATOR_PREFIXES = (
    "set_", "Set", "Add", "Update", "Save", "Clear", "Reset", "Remove",
    "Insert", "Replace", "Append", "Apply", "Delete", "Create", "Init",
    "Initialize", "Open", "Close", "Unlock", "Release", "Push", "Pop",
    "Sub", "Use", "Consume", "Receive", "Acquire", "Register", "Unregister",
    "Change", "Edit", "Refresh", "LoadFrom", "SetUp", "SlotDataClear",
)
GAME_PREFIXES = ("Stage.", "Cute.", "Plat.", "Cenere.", "StageMinigame.")
FRAMEWORK_PREFIXES = (
    "System.", "UnityEngine.", "Unity.", "LitJson.", "MessagePack.", "Cysharp.",
    "TMPro.", "UniRx.", "Newtonsoft.", "Google.", "Firebase.",
)
PF_X = 0x1
BRANCH_MASK = 0xFC000000
BL_OPCODE = 0x94000000
B_OPCODE = 0x14000000


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: str | None

    @property
    def owner_and_method(self) -> tuple[str, str] | None:
        if "$$" not in self.name:
            return None
        owner, method = self.name.split("$$", 1)
        return owner, method


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(f"unsupported address value: {value!r}")


def load_script_methods(path: Path) -> tuple[list[Method], dict[int, list[Method]], list[int]]:
    data = load_json(path)
    methods: list[Method] = []
    by_start: dict[int, list[Method]] = defaultdict(list)
    boundaries: set[int] = set()
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        name = str(item.get("Name") or "")
        if address <= 0 or not name:
            continue
        method = Method(address=address, name=name, signature=item.get("Signature"))
        methods.append(method)
        by_start[address].append(method)
        boundaries.add(address)
    for value in data.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            boundaries.add(address)
    for rows in by_start.values():
        rows.sort(key=lambda m: (m.name, m.signature or ""))
    methods.sort(key=lambda m: (m.address, m.name, m.signature or ""))
    return methods, dict(by_start), sorted(boundaries)


def reader_kind(method: str) -> str | None:
    if method.startswith(MUTATOR_PREFIXES):
        return None
    for prefix in READER_PREFIXES:
        if method.startswith(prefix):
            if prefix == "get_":
                return "property-get"
            if prefix == "TryGet":
                return "try-get"
            if prefix in ("Is", "Has", "Contains", "Exists", "Check", "Can"):
                return "predicate"
            if prefix == "Count":
                return "count"
            if prefix == "Find":
                return "lookup"
            return "get-or-read"
    return None


def endpoint_identity(endpoint: dict[str, Any]) -> tuple[Any, ...]:
    return (
        endpoint.get("route"), endpoint.get("enum"), endpoint.get("group"),
        endpoint.get("key"), endpoint.get("status"),
    )


def c7a_state_inputs(doc: dict[str, Any]) -> tuple[list[str], dict[str, list[dict[str, Any]]], dict[str, int]]:
    if int(doc.get("schema", 0)) != 1:
        raise RuntimeError(f"unsupported C7a schema: {doc.get('schema')!r}")
    state_types = sorted({str(row["state_type"]) for row in doc.get("relations", [])})
    upstream: dict[str, dict[tuple[Any, ...], dict[str, Any]]] = defaultdict(dict)
    mutation_counts: Counter[str] = Counter()
    for row in doc.get("relations", []):
        state_type = str(row["state_type"])
        mutation_counts[state_type] += 1
        for endpoint in row.get("endpoint_candidates", []):
            upstream[state_type].setdefault(endpoint_identity(endpoint), endpoint)
    return (
        state_types,
        {k: sorted(v.values(), key=lambda x: tuple(str(y) for y in endpoint_identity(x))) for k, v in upstream.items()},
        dict(mutation_counts),
    )


def classify_consumer(name: str) -> tuple[str, bool]:
    if name.startswith(GAME_PREFIXES):
        return "game-owned", True
    if name.startswith(FRAMEWORK_PREFIXES):
        return "framework-low-relevance", False
    if name.startswith(("Il2Cpp", "Microsoft.", "Mono.", "mscorlib.")):
        return "runtime-low-relevance", False
    return "third-party-or-unknown", False


def signed_imm26(word: int) -> int:
    imm26 = word & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return imm26 << 2


def scan_direct_xrefs(lib_path: Path, target_rvas: set[int]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    scanned_bytes = 0
    executable_segments = 0
    with lib_path.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD" or not (int(segment["p_flags"]) & PF_X):
                continue
            executable_segments += 1
            vaddr = int(segment["p_vaddr"])
            offset = int(segment["p_offset"])
            filesz = int(segment["p_filesz"])
            stream.seek(offset)
            data = stream.read(filesz)
            usable = len(data) - (len(data) % 4)
            scanned_bytes += usable
            for index, (word,) in enumerate(struct.iter_unpack("<I", data[:usable])):
                opcode = word & BRANCH_MASK
                if opcode not in (BL_OPCODE, B_OPCODE):
                    continue
                site = vaddr + index * 4
                target = site + signed_imm26(word)
                if target not in target_rvas:
                    continue
                hits.append({
                    "callsite_rva": site,
                    "target_rva": target,
                    "edge_kind": "BL" if opcode == BL_OPCODE else "B-tail",
                })
    hits.sort(key=lambda x: (x["callsite_rva"], x["target_rva"], x["edge_kind"]))
    return hits, {"executable_segment_count": executable_segments, "executable_bytes_scanned": scanned_bytes}


def containing_methods(address: int, boundaries: list[int], by_start: dict[int, list[Method]]) -> tuple[int | None, list[Method]]:
    index = bisect.bisect_right(boundaries, address) - 1
    if index < 0:
        return None, []
    start = boundaries[index]
    return start, by_start.get(start, [])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--state-mutations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    c7a = load_json(args.state_mutations)
    state_types, upstream_endpoints, mutation_counts = c7a_state_inputs(c7a)
    state_type_set = set(state_types)
    methods, methods_by_start, boundaries = load_script_methods(args.script_json)

    reader_rows: list[dict[str, Any]] = []
    for method in methods:
        parsed = method.owner_and_method
        if parsed is None:
            continue
        owner, short_name = parsed
        if owner not in state_type_set:
            continue
        kind = reader_kind(short_name)
        if kind is None:
            continue
        reader_rows.append({
            "state_type": owner, "method": short_name, "full_name": method.name,
            "rva": method.address, "signature": method.signature, "reader_kind": kind,
        })

    readers_by_rva: dict[int, list[dict[str, Any]]] = defaultdict(list)
    readers_by_state: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in reader_rows:
        readers_by_rva[int(row["rva"])].append(row)
        readers_by_state[str(row["state_type"])].append(row)
    for rows in readers_by_rva.values():
        rows.sort(key=lambda x: (x["state_type"], x["full_name"], x.get("signature") or ""))
    for rows in readers_by_state.values():
        rows.sort(key=lambda x: (x["rva"], x["full_name"], x.get("signature") or ""))

    raw_hits, scan_meta = scan_direct_xrefs(args.lib, set(readers_by_rva))
    xrefs: list[dict[str, Any]] = []
    unresolved_consumer_xrefs = 0
    ambiguous_consumer_xrefs = 0
    ambiguous_reader_xrefs = 0
    for hit in raw_hits:
        caller_start, caller_methods = containing_methods(hit["callsite_rva"], boundaries, methods_by_start)
        if not caller_methods:
            unresolved_consumer_xrefs += 1
        if len(caller_methods) > 1:
            ambiguous_consumer_xrefs += 1
        reader_candidates = readers_by_rva[hit["target_rva"]]
        if len(reader_candidates) > 1:
            ambiguous_reader_xrefs += 1
        caller_candidates: list[dict[str, Any]] = []
        for caller in caller_methods:
            relevance, game_owned = classify_consumer(caller.name)
            caller_candidates.append({
                "method": caller.name, "rva": caller.address, "signature": caller.signature,
                "relevance": relevance, "game_owned": game_owned,
            })
        confidence = "high"
        reasons: list[str] = []
        if hit["edge_kind"] != "BL":
            confidence = "medium"
            reasons.append("direct B tail edge rather than BL")
        if len(reader_candidates) > 1:
            confidence = "ambiguous"
            reasons.append("reader RVA shared by multiple reader methods")
        if len(caller_methods) != 1:
            confidence = "ambiguous" if caller_methods else "unresolved"
            reasons.append("caller boundary maps to zero or multiple managed methods")
        xrefs.append({
            **hit, "caller_boundary_rva": caller_start,
            "reader_candidates": reader_candidates, "consumer_candidates": caller_candidates,
            "confidence": confidence, "ambiguity_reasons": reasons,
            "evidence": "exact ARM64 direct branch immediate targets selected state-reader RVA",
        })

    consumer_edges: list[dict[str, Any]] = []
    for xref in xrefs:
        if len(xref["reader_candidates"]) != 1 or len(xref["consumer_candidates"]) != 1:
            continue
        reader = xref["reader_candidates"][0]
        consumer = xref["consumer_candidates"][0]
        consumer_edges.append({
            "state_type": reader["state_type"], "reader_method": reader["method"],
            "reader_full_name": reader["full_name"], "reader_rva": reader["rva"],
            "reader_kind": reader["reader_kind"], "callsite_rva": xref["callsite_rva"],
            "edge_kind": xref["edge_kind"], "consumer_method": consumer["method"],
            "consumer_rva": consumer["rva"], "consumer_relevance": consumer["relevance"],
            "game_owned": consumer["game_owned"],
            "confidence": "high" if xref["edge_kind"] == "BL" else "medium",
            "evidence": xref["evidence"],
        })

    grouped_edges: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for row in consumer_edges:
        key = (
            row["state_type"], row["reader_full_name"], row["reader_rva"],
            row["consumer_method"], row["consumer_rva"], row["edge_kind"],
        )
        grouped_edges[key].append(row)
    relations: list[dict[str, Any]] = []
    for _, rows in sorted(grouped_edges.items(), key=lambda kv: tuple(str(x) for x in kv[0])):
        first = rows[0]
        relations.append({
            "state_type": first["state_type"], "reader_method": first["reader_method"],
            "reader_full_name": first["reader_full_name"], "reader_rva": first["reader_rva"],
            "reader_kind": first["reader_kind"], "consumer_method": first["consumer_method"],
            "consumer_rva": first["consumer_rva"], "consumer_relevance": first["consumer_relevance"],
            "game_owned": first["game_owned"], "edge_kind": first["edge_kind"],
            "confidence": first["confidence"], "call_count": len(rows),
            "callsite_rvas": sorted({int(r["callsite_rva"]) for r in rows}),
            "evidence": "one or more exact direct native xrefs to uniquely identified state reader",
        })

    relations_by_state: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in relations:
        relations_by_state[row["state_type"]].append(row)

    state_docs: list[dict[str, Any]] = []
    endpoint_state_consumer_keys: set[tuple[Any, ...]] = set()
    for state_type in state_types:
        state_relations = relations_by_state.get(state_type, [])
        per_reader: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
        for relation in state_relations:
            per_reader[(relation["reader_full_name"], relation["reader_rva"])].append(relation)
        readers: list[dict[str, Any]] = []
        for reader in readers_by_state.get(state_type, []):
            key = (reader["full_name"], reader["rva"])
            consumers = sorted(
                per_reader.get(key, []),
                key=lambda x: (not x["game_owned"], x["consumer_method"], x["consumer_rva"], x["edge_kind"]),
            )
            readers.append({**reader, "consumers": consumers})
        unique_consumers = {(r["consumer_method"], r["consumer_rva"]) for r in state_relations}
        game_consumers = {
            (r["consumer_method"], r["consumer_rva"]) for r in state_relations if r["game_owned"]
        }
        endpoints = upstream_endpoints.get(state_type, [])
        for endpoint in endpoints:
            ep_key = endpoint_identity(endpoint)
            for consumer_name, consumer_rva in unique_consumers:
                endpoint_state_consumer_keys.add(ep_key + (state_type, consumer_name, consumer_rva))
        state_docs.append({
            "state_type": state_type,
            "c7a_mutation_relation_count": mutation_counts.get(state_type, 0),
            "upstream_endpoints": endpoints,
            "reader_count": len(readers),
            "consumer_count": len(unique_consumers),
            "game_owned_consumer_count": len(game_consumers),
            "readers": readers,
        })

    consumer_methods = {(r["consumer_method"], r["consumer_rva"]) for r in relations}
    game_consumer_methods = {
        (r["consumer_method"], r["consumer_rva"]) for r in relations if r["game_owned"]
    }
    state_types_with_readers = {row["state_type"] for row in reader_rows}
    state_types_with_consumers = {row["state_type"] for row in relations}
    shared_reader_rvas = {rva: rows for rva, rows in readers_by_rva.items() if len(rows) > 1}

    report = {
        "schema": SCHEMA,
        "scope": "C7b exact state-reader direct ARM64 xrefs to managed consumers; indirect BR/BLR dispatch not recovered",
        "source_c7a_schema": c7a.get("schema"),
        "state_type_count": len(state_types),
        "reader_method_count": len(reader_rows),
        "reader_rva_count": len(readers_by_rva),
        "shared_reader_rva_count": len(shared_reader_rvas),
        "reader_xref_count": len(xrefs),
        "unique_reader_consumer_relation_count": len(relations),
        "consumer_method_count": len(consumer_methods),
        "game_owned_consumer_count": len(game_consumer_methods),
        "state_types_with_readers": len(state_types_with_readers),
        "state_types_without_readers": len(state_type_set - state_types_with_readers),
        "state_types_with_consumers": len(state_types_with_consumers),
        "state_types_without_consumers": len(state_type_set - state_types_with_consumers),
        "endpoint_state_consumer_relation_count": len(endpoint_state_consumer_keys),
        "unresolved_consumer_xref_count": unresolved_consumer_xrefs,
        "ambiguous_consumer_xref_count": ambiguous_consumer_xrefs,
        "ambiguous_reader_xref_count": ambiguous_reader_xrefs,
        "edge_kind_counts": dict(sorted(Counter(x["edge_kind"] for x in xrefs).items())),
        "relation_edge_kind_counts": dict(sorted(Counter(x["edge_kind"] for x in relations).items())),
        "consumer_relevance_counts": dict(sorted(Counter(x["consumer_relevance"] for x in relations).items())),
        "reader_kind_counts": dict(sorted(Counter(x["reader_kind"] for x in reader_rows).items())),
        **scan_meta,
        "state_types": state_docs,
        "relations": relations,
        "ambiguous_or_unresolved_xrefs": [x for x in xrefs if x["confidence"] in ("ambiguous", "unresolved")],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = [
            "# C7b state consumer graph", "",
            "Exact direct ARM64 reader xrefs only. Indirect BR/BLR dispatch remains runtime/static-followup work.", "",
            f"- C7a state types: **{report['state_type_count']}**",
            f"- reader methods: **{report['reader_method_count']}**",
            f"- unique reader RVAs: **{report['reader_rva_count']}**",
            f"- shared reader RVAs: **{report['shared_reader_rva_count']}**",
            f"- direct reader xrefs: **{report['reader_xref_count']}**",
            f"- unique reader→consumer relations: **{report['unique_reader_consumer_relation_count']}**",
            f"- consumer methods: **{report['consumer_method_count']}**",
            f"- game-owned consumer methods: **{report['game_owned_consumer_count']}**",
            f"- state types with readers: **{report['state_types_with_readers']}**",
            f"- state types with consumers: **{report['state_types_with_consumers']}**",
            f"- endpoint→state→consumer relations: **{report['endpoint_state_consumer_relation_count']}**",
            f"- unresolved consumer xrefs: **{report['unresolved_consumer_xref_count']}**",
            f"- ambiguous consumer xrefs: **{report['ambiguous_consumer_xref_count']}**",
            f"- ambiguous reader xrefs: **{report['ambiguous_reader_xref_count']}**", "",
            "## Direct edge kinds", "",
        ]
        lines.extend(f"- `{k}`: **{v}**" for k, v in report["edge_kind_counts"].items())
        lines.extend(["", "## State types with most game-owned consumers", ""])
        for state in sorted(state_docs, key=lambda x: (-x["game_owned_consumer_count"], -x["consumer_count"], x["state_type"]))[:100]:
            lines.append(
                f"- `{state['state_type']}`: readers **{state['reader_count']}**, consumers **{state['consumer_count']}**, "
                f"game-owned **{state['game_owned_consumer_count']}**, upstream endpoints **{len(state['upstream_endpoints'])}**"
            )
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary_keys = (
        "state_type_count", "reader_method_count", "reader_rva_count", "shared_reader_rva_count",
        "reader_xref_count", "unique_reader_consumer_relation_count", "consumer_method_count",
        "game_owned_consumer_count", "state_types_with_readers", "state_types_without_readers",
        "state_types_with_consumers", "state_types_without_consumers",
        "endpoint_state_consumer_relation_count", "unresolved_consumer_xref_count",
        "ambiguous_consumer_xref_count", "ambiguous_reader_xref_count",
        "edge_kind_counts", "consumer_relevance_counts",
    )
    print(json.dumps({k: report[k] for k in summary_keys}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
