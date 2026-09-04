#!/usr/bin/env python3
"""C28: prove whether opaque response values only feed a dead ToJson result.

C25 leaves three low-complexity routes opaque because their exact top-level
``data`` JsonData value is passed only to ``LitJson.JsonData.ToJson``.  The call
itself does not reveal object/array business semantics.  This pass starts after
that exact ToJson call and conservatively taints its returned string through the
same hardened ARM64 CFG/dataflow rules used by C27.

A route is promoted only when the ToJson result has zero semantic sinks, every
reachable control-flow edge is resolved, and a known parser exit is reachable.
For such a route the parser still requires ``data`` to exist, but deterministic
``{}`` is parser-locally safe because it is valid JsonData and the resulting
serialization is proven dead.  Untouched-client/business/UI acceptance remains
unproven.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter, deque
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run-dead-json-response-value-c27.py"
SPEC = importlib.util.spec_from_file_location("c27_hardened_for_c28", RUNNER)
assert SPEC is not None and SPEC.loader is not None
HARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARD
SPEC.loader.exec_module(HARD)
BASE = HARD.BASE

SCHEMA = 1
TOJSON_NAME = "LitJson.JsonData$$ToJson"
EXPECTED_TARGET_COUNT = 3


class C28Error(ValueError):
    pass


def load_targets(c20_path: Path) -> list[dict[str, Any]]:
    doc = json.loads(c20_path.read_text(encoding="utf-8"))
    if doc.get("schema") != 1 or doc.get("target_route_count") != 15:
        raise C28Error("unexpected C20 report")
    targets: list[dict[str, Any]] = []
    for row in doc.get("routes", []):
        if not isinstance(row, dict) or row.get("consumer_resolution") != "direct-managed-consumer":
            continue
        consumer = row.get("first_direct_managed_consumer")
        if not isinstance(consumer, dict):
            continue
        methods = consumer.get("target_methods")
        if not isinstance(methods, list) or len(methods) != 1:
            continue
        method = methods[0]
        if not isinstance(method, dict) or method.get("name") != TOJSON_NAME:
            continue
        required = {
            "route": row.get("route"),
            "endpoint_id": row.get("endpoint_id"),
            "task": row.get("task"),
            "method": row.get("method"),
            "method_rva": row.get("method_rva"),
            "data_access_rva": row.get("data_access_rva"),
            "tojson_callsite_rva": consumer.get("callsite_rva"),
            "tojson_target_rva": consumer.get("target_rva"),
        }
        if not isinstance(required["route"], str) or not isinstance(required["endpoint_id"], int):
            raise C28Error("malformed C20 route identity")
        for key in ("method_rva", "data_access_rva", "tojson_callsite_rva", "tojson_target_rva"):
            if not isinstance(required[key], int):
                raise C28Error(f"missing {key} for {required['route']}")
        targets.append(required)
    targets.sort(key=lambda row: str(row["route"]))
    if len(targets) != EXPECTED_TARGET_COUNT:
        raise C28Error(f"expected {EXPECTED_TARGET_COUNT} ToJson routes, got {len(targets)}")
    return targets


def analyze_target(
    view: Any,
    starts: list[int],
    managed_starts: set[int],
    target: dict[str, Any],
) -> dict[str, Any]:
    start = int(target["method_rva"])
    callsite = int(target["tojson_callsite_rva"])
    end = BASE.function_end(starts, start)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, end - start), start))
    by = {int(ins.address): ins for ins in insns}
    ins = by.get(callsite)
    if ins is None or ins.id != ARM64_INS_BL:
        raise C28Error(f"ToJson callsite is not direct BL for {target['route']}")
    if BASE.branch_target(ins) != int(target["tojson_target_rva"]):
        raise C28Error(f"ToJson target mismatch for {target['route']}")

    addrs = sorted(by)
    pos = addrs.index(callsite)
    if pos + 1 >= len(addrs):
        raise C28Error(f"ToJson call has no following instruction for {target['route']}")
    entry = addrs[pos + 1]
    succ, unresolved_edges = BASE.instruction_successors(insns, start, end, managed_starts)

    state_at: dict[int, Any] = {entry: BASE.State(frozenset({"x0"}), frozenset())}
    queue: deque[int] = deque([entry])
    sinks: dict[tuple[Any, ...], dict[str, Any]] = {}
    reached_returns: set[int] = set()
    reached_tail_exits: set[int] = set()
    reached_unresolved: list[dict[str, Any]] = []
    iterations = 0

    while queue:
        addr = queue.popleft()
        iterations += 1
        if iterations > 200000:
            raise C28Error(f"dataflow iteration cap exceeded for {target['route']}")
        current = state_at[addr]
        out_state, new_sinks, terminal = BASE.transfer(by[addr], md, current, managed_starts)
        for sink in new_sinks:
            key = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in sink.items()))
            sinks[key] = sink
        if terminal == "return":
            reached_returns.add(addr)
        elif terminal == "managed-tail-exit":
            reached_tail_exits.add(addr)

        for edge in unresolved_edges:
            if edge["rva"] != addr:
                continue
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

    known_exits = len(reached_returns) + len(reached_tail_exits)
    dead = not sinks and not reached_unresolved and known_exits > 0
    return {
        **target,
        "post_tojson_entry_rva": entry,
        "reachable_instruction_count": len(state_at),
        "reachable_normal_return_count": len(reached_returns),
        "reachable_managed_tail_exit_count": len(reached_tail_exits),
        "reachable_unresolved_control_flow": reached_unresolved,
        "semantic_sink_count": len(sinks),
        "semantic_sinks": sorted(sinks.values(), key=lambda row: (int(row["rva"]), str(row["kind"]))),
        "tojson_result_value_class": "dead-value" if dead else "observable-or-unresolved",
        "parser_local_empty_object_safe": dead,
        "empty_object_promotion": "parser-local-safe-via-dead-tojson-result" if dead else "not-proven-by-c28",
        "untouched_client_acceptance": False,
        "ui_visible_success": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lib", type=Path, required=True)
    p.add_argument("--script-json", type=Path, required=True)
    p.add_argument("--c20", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        targets = load_targets(args.c20)
        starts, managed_starts = BASE.load_method_starts(args.script_json)
        view = BASE.BinaryView(args.lib)
        try:
            routes = [analyze_target(view, starts, managed_starts, row) for row in targets]
        finally:
            view.close()
    except (OSError, json.JSONDecodeError, C28Error, BASE.AnalysisError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    classes = Counter(row["tojson_result_value_class"] for row in routes)
    proven = [row for row in routes if row["parser_local_empty_object_safe"]]
    report = {
        "schema": SCHEMA,
        "scope": (
            "C28 final-client liveness of LitJson.JsonData.ToJson return strings for the three "
            "remaining ToJson-only opaque response routes; no response value from the official server inferred"
        ),
        "target_route_count": len(routes),
        "parser_local_empty_object_safe_route_count": len(proven),
        "result_class_counts": dict(sorted(classes.items())),
        "routes": routes,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "target_route_count": len(routes),
        "parser_local_empty_object_safe_route_count": len(proven),
        "result_class_counts": report["result_class_counts"],
        "proven_routes": [row["route"] for row in proven],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
