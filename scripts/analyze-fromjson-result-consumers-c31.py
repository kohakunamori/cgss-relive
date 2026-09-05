#!/usr/bin/env python3
"""C31: trace the deserialized DTO objects for the three C28/C29 routes.

C29 proves that the ToJson strings are consumed by the shared IL2CPP body for
``UnityEngine.JsonUtility.FromJson<object>``.  The important next question is
what each parser does with that returned object.  This pass starts immediately
after each exact FromJson callsite and conservatively taints x0 through the
parser, enriching direct-call sinks with final-client managed identities.

A non-stack store proves the DTO escapes into object state; a call-argument sink
identifies the next semantic consumer.  No DTO type or official response value
is guessed from route names.
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
from capstone.arm64 import ARM64_INS_BL

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run-dead-json-response-value-c27.py"
SPEC = importlib.util.spec_from_file_location("c27_hardened_for_c31", RUNNER)
assert SPEC is not None and SPEC.loader is not None
HARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARD
SPEC.loader.exec_module(HARD)
BASE = HARD.BASE

SCHEMA = 1
EXPECTED_ROUTE_COUNT = 3
FROMJSON_SHARED_RVA = 91388168


class C31Error(ValueError):
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
        if row.get("Name"):
            methods[rva].append({
                "name": str(row["Name"]),
                "signature": str(row.get("Signature")) if row.get("Signature") else None,
            })
    for value in doc.get("Addresses", []):
        rva = BASE.as_int(value)
        if rva > 0:
            starts.add(rva)
    for rows in methods.values():
        rows.sort(key=lambda item: str(item["name"]))
    return sorted(starts), managed_starts, dict(methods)


def load_targets(c28_path: Path) -> list[dict[str, Any]]:
    doc = json.loads(c28_path.read_text(encoding="utf-8"))
    if doc.get("schema") != 1 or doc.get("target_route_count") != EXPECTED_ROUTE_COUNT:
        raise C31Error("unexpected C28 report")
    out: list[dict[str, Any]] = []
    for row in doc.get("routes", []):
        if not isinstance(row, dict):
            raise C31Error("malformed C28 route row")
        sinks = row.get("semantic_sinks")
        if not isinstance(sinks, list) or len(sinks) != 1:
            raise C31Error(f"expected exactly one ToJson-result sink for {row.get('route')}")
        sink = sinks[0]
        if (
            not isinstance(sink, dict)
            or sink.get("kind") != "call-argument"
            or sink.get("call_kind") != "direct"
            or sink.get("argument_positions") != [0]
            or sink.get("target_rva") != FROMJSON_SHARED_RVA
        ):
            raise C31Error(f"unexpected FromJson sink for {row.get('route')}")
        method_rva = row.get("method_rva")
        callsite = sink.get("rva")
        if not isinstance(method_rva, int) or not isinstance(callsite, int):
            raise C31Error(f"missing parser/FromJson RVA for {row.get('route')}")
        out.append({
            "route": row.get("route"),
            "endpoint_id": row.get("endpoint_id"),
            "task": row.get("task"),
            "method": row.get("method"),
            "method_rva": method_rva,
            "fromjson_callsite_rva": callsite,
            "fromjson_target_rva": FROMJSON_SHARED_RVA,
        })
    out.sort(key=lambda item: str(item["route"]))
    if len(out) != EXPECTED_ROUTE_COUNT:
        raise C31Error(f"expected {EXPECTED_ROUTE_COUNT} targets, got {len(out)}")
    return out


def analyze_target(
    *,
    view: Any,
    starts: list[int],
    managed_starts: set[int],
    methods: dict[int, list[dict[str, Any]]],
    target: dict[str, Any],
) -> dict[str, Any]:
    start = int(target["method_rva"])
    callsite = int(target["fromjson_callsite_rva"])
    end = BASE.function_end(starts, start)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, end - start), start))
    by = {int(ins.address): ins for ins in insns}
    call = by.get(callsite)
    if call is None or call.id != ARM64_INS_BL or BASE.branch_target(call) != FROMJSON_SHARED_RVA:
        raise C31Error(f"FromJson callsite mismatch for {target['route']}")
    addrs = sorted(by)
    pos = addrs.index(callsite)
    if pos + 1 >= len(addrs):
        raise C31Error(f"FromJson call has no following instruction for {target['route']}")
    entry = addrs[pos + 1]
    succ, unresolved = BASE.instruction_successors(insns, start, end, managed_starts)

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
            raise C31Error(f"result dataflow iteration cap exceeded for {target['route']}")
        current = state_at[addr]
        out_state, new_sinks, terminal = BASE.transfer(by[addr], md, current, managed_starts)
        for sink in new_sinks:
            enriched = dict(sink)
            callee = enriched.get("target_rva")
            if isinstance(callee, int) and callee in methods:
                enriched["target_methods"] = methods[callee]
            key = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in enriched.items()))
            sinks[key] = enriched
        if terminal == "return":
            returns.add(addr)
        elif terminal == "managed-tail-exit":
            tails.add(addr)
        for edge in unresolved:
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
        **target,
        "post_fromjson_entry_rva": entry,
        "reachable_instruction_count": len(state_at),
        "reachable_normal_return_count": len(returns),
        "reachable_managed_tail_exit_count": len(tails),
        "reachable_unresolved_control_flow": reached_unresolved,
        "semantic_sink_count": len(sinks),
        "semantic_sink_kind_counts": dict(sorted(Counter(str(s["kind"]) for s in sinks.values()).items())),
        "semantic_sinks": sorted(sinks.values(), key=lambda row: (int(row["rva"]), str(row["kind"]))),
        "untouched_client_acceptance": False,
        "ui_visible_success": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--c28", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        targets = load_targets(args.c28)
        starts, managed_starts, methods = load_managed(args.script_json)
        if not any(m.get("name") == "UnityEngine.JsonUtility$$FromJson<object>" for m in methods.get(FROMJSON_SHARED_RVA, [])):
            raise C31Error("final-client shared FromJson<object> identity changed")
        view = BASE.BinaryView(args.lib)
        try:
            rows = [
                analyze_target(
                    view=view,
                    starts=starts,
                    managed_starts=managed_starts,
                    methods=methods,
                    target=row,
                )
                for row in targets
            ]
        finally:
            view.close()
    except (OSError, json.JSONDecodeError, C31Error, BASE.AnalysisError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = {
        "schema": SCHEMA,
        "scope": "C31 final-client FromJson result-object consumers for three ToJson response routes",
        "route_count": len(rows),
        "routes": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "route_count": len(rows),
        "routes": [
            {
                "route": row["route"],
                "semantic_sink_count": row["semantic_sink_count"],
                "semantic_sink_kind_counts": row["semantic_sink_kind_counts"],
                "semantic_sinks": row["semantic_sinks"],
            }
            for row in rows
        ],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
