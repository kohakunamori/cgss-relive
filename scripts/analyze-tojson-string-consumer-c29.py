#!/usr/bin/env python3
"""C29: resolve and trace the shared consumer of three C28 ToJson strings.

C28 proved that `/bus/favorite`, `/concert/finish_mv_loading`, and
`/concert/mv_start` serialize their response ``data`` with JsonData.ToJson and
then pass the returned string to the same direct call target.  This pass resolves
that exact target against final-client managed metadata and conservatively taints
the string through the target body.

The report records only managed identities and sanitized sink metadata.  It does
not infer an official response value or claim untouched-client acceptance.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter, defaultdict, deque
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run-dead-json-response-value-c27.py"
SPEC = importlib.util.spec_from_file_location("c27_hardened_for_c29", RUNNER)
assert SPEC is not None and SPEC.loader is not None
HARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARD
SPEC.loader.exec_module(HARD)
BASE = HARD.BASE

SCHEMA = 1
EXPECTED_ROUTE_COUNT = 3


class C29Error(ValueError):
    pass


def load_managed(path: Path) -> tuple[list[int], set[int], dict[int, list[dict[str, Any]]]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    starts: set[int] = set()
    managed_starts: set[int] = set()
    methods: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in doc.get("ScriptMethod", []):
        rva = BASE.as_int(row.get("Address", 0))
        if rva <= 0:
            continue
        starts.add(rva)
        managed_starts.add(rva)
        name = row.get("Name")
        if name:
            methods[rva].append(
                {
                    "name": str(name),
                    "signature": str(row.get("Signature")) if row.get("Signature") else None,
                }
            )
    for value in doc.get("Addresses", []):
        rva = BASE.as_int(value)
        if rva > 0:
            starts.add(rva)
    for rows in methods.values():
        rows.sort(key=lambda item: str(item["name"]))
    return sorted(starts), managed_starts, dict(methods)


def load_target(c28_path: Path) -> tuple[int, list[dict[str, Any]]]:
    doc = json.loads(c28_path.read_text(encoding="utf-8"))
    if doc.get("schema") != 1 or doc.get("target_route_count") != EXPECTED_ROUTE_COUNT:
        raise C29Error("unexpected C28 report")
    rows = doc.get("routes")
    if not isinstance(rows, list) or len(rows) != EXPECTED_ROUTE_COUNT:
        raise C29Error("malformed C28 routes")
    targets: set[int] = set()
    normalized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise C29Error("malformed C28 route row")
        sinks = row.get("semantic_sinks")
        if not isinstance(sinks, list) or len(sinks) != 1:
            raise C29Error(f"expected one C28 sink for {row.get('route')}")
        sink = sinks[0]
        if (
            not isinstance(sink, dict)
            or sink.get("kind") != "call-argument"
            or sink.get("call_kind") != "direct"
            or sink.get("argument_positions") != [0]
            or not isinstance(sink.get("target_rva"), int)
        ):
            raise C29Error(f"unexpected C28 sink shape for {row.get('route')}")
        targets.add(int(sink["target_rva"]))
        normalized.append(
            {
                "route": row.get("route"),
                "endpoint_id": row.get("endpoint_id"),
                "parser_method": row.get("method"),
                "consumer_callsite_rva": sink.get("rva"),
            }
        )
    if len(targets) != 1:
        raise C29Error(f"C28 routes do not share one consumer target: {sorted(targets)}")
    return next(iter(targets)), sorted(normalized, key=lambda item: str(item["route"]))


def trace_consumer(
    *,
    view: Any,
    starts: list[int],
    managed_starts: set[int],
    methods: dict[int, list[dict[str, Any]]],
    target_rva: int,
) -> dict[str, Any]:
    end = BASE.function_end(starts, target_rva)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(target_rva, end - target_rva), target_rva))
    if not insns:
        raise C29Error("shared consumer could not be disassembled")
    by = {int(ins.address): ins for ins in insns}
    entry = int(insns[0].address)
    succ, unresolved_edges = BASE.instruction_successors(insns, target_rva, end, managed_starts)

    state_at: dict[int, Any] = {entry: BASE.State(frozenset({"x0"}), frozenset())}
    queue: deque[int] = deque([entry])
    sinks: dict[tuple[Any, ...], dict[str, Any]] = {}
    returns: set[int] = set()
    tails: set[int] = set()
    reached_unresolved: list[dict[str, Any]] = []
    iterations = 0

    while queue:
        addr = queue.popleft()
        iterations += 1
        if iterations > 200000:
            raise C29Error("shared consumer dataflow iteration cap exceeded")
        current = state_at[addr]
        out_state, new_sinks, terminal = BASE.transfer(by[addr], md, current, managed_starts)
        for sink in new_sinks:
            enriched = dict(sink)
            target = enriched.get("target_rva")
            if isinstance(target, int) and target in methods:
                enriched["target_methods"] = methods[target]
            key = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in enriched.items()))
            sinks[key] = enriched
        if terminal == "return":
            returns.add(addr)
        elif terminal == "managed-tail-exit":
            tails.add(addr)

        for edge in unresolved_edges:
            if edge["rva"] == addr:
                reached_unresolved.append(edge)
                if current.regs or current.stack:
                    sink = {
                        "kind": "unknown-control-flow-with-live-taint",
                        "rva": addr,
                        "edge_kind": edge["kind"],
                    }
                    key = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in sink.items()))
                    sinks[key] = sink

        for dst in succ.get(addr, []):
            previous = state_at.get(dst)
            merged = out_state if previous is None else previous.union(out_state)
            if previous != merged:
                state_at[dst] = merged
                queue.append(dst)

    return {
        "consumer_target_rva": target_rva,
        "consumer_methods": methods.get(target_rva, []),
        "reachable_instruction_count": len(state_at),
        "reachable_normal_return_count": len(returns),
        "reachable_managed_tail_exit_count": len(tails),
        "reachable_unresolved_control_flow": reached_unresolved,
        "semantic_sink_count": len(sinks),
        "semantic_sink_kind_counts": dict(sorted(Counter(str(x["kind"]) for x in sinks.values()).items())),
        "semantic_sinks": sorted(sinks.values(), key=lambda row: (int(row["rva"]), str(row["kind"]))),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--c28", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        target_rva, routes = load_target(args.c28)
        starts, managed_starts, methods = load_managed(args.script_json)
        view = BASE.BinaryView(args.lib)
        try:
            consumer = trace_consumer(
                view=view,
                starts=starts,
                managed_starts=managed_starts,
                methods=methods,
                target_rva=target_rva,
            )
        finally:
            view.close()
    except (OSError, json.JSONDecodeError, C29Error, BASE.AnalysisError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = {
        "schema": SCHEMA,
        "scope": (
            "C29 exact final-client shared consumer identity and conservative string-value dataflow "
            "for three C28 ToJson response routes; no official response value inferred"
        ),
        "route_count": len(routes),
        "routes": routes,
        **consumer,
        "untouched_client_acceptance": False,
        "ui_visible_success": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "route_count": report["route_count"],
        "consumer_target_rva": report["consumer_target_rva"],
        "consumer_methods": report["consumer_methods"],
        "semantic_sink_count": report["semantic_sink_count"],
        "semantic_sink_kind_counts": report["semantic_sink_kind_counts"],
        "reachable_unresolved_control_flow_count": len(report["reachable_unresolved_control_flow"]),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
