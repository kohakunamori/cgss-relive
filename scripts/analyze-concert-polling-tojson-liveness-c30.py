#!/usr/bin/env python3
"""C30: trace the ToJson result inside ConcertMVPollingTask.CheckJson.

C21 shows `/concert/mv_polling` passes response ``data`` into the exact managed
helper ``ConcertMVPollingTask.CheckJson``; inside that helper the tainted JsonData
is serialized once with ``JsonData.ToJson``.  This pass begins after that exact
serialization and applies the hardened C27 liveness rules to the returned string.

The result determines whether polling joins the three C28 routes at the same
shared string consumer or has distinct semantics.  No official response value or
client/device acceptance is inferred.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import deque
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run-dead-json-response-value-c27.py"
SPEC = importlib.util.spec_from_file_location("c27_hardened_for_c30", RUNNER)
assert SPEC is not None and SPEC.loader is not None
HARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARD
SPEC.loader.exec_module(HARD)
BASE = HARD.BASE

SCHEMA = 1
TARGET_ROUTE = "/concert/mv_polling"
TARGET_ENDPOINT_ID = 306
TARGET_HELPER = "Stage.ConcertMVPollingTask$$CheckJson"
TOJSON_NAME = "LitJson.JsonData$$ToJson"


class C30Error(ValueError):
    pass


def load_target(c21_path: Path) -> dict[str, Any]:
    doc = json.loads(c21_path.read_text(encoding="utf-8"))
    if doc.get("schema") != 1 or doc.get("target_route_count") != 15:
        raise C30Error("unexpected C21 report")
    rows = [row for row in doc.get("routes", []) if isinstance(row, dict) and row.get("route") == TARGET_ROUTE]
    if len(rows) != 1:
        raise C30Error("C21 polling route missing/duplicated")
    row = rows[0]
    if row.get("endpoint_id") != TARGET_ENDPOINT_ID:
        raise C30Error("polling endpoint identity mismatch")
    first = row.get("first_direct_consumer")
    if not isinstance(first, dict):
        raise C30Error("polling first consumer missing")
    methods = first.get("target_methods")
    if not isinstance(methods, list) or not any(
        isinstance(m, dict) and m.get("name") == TARGET_HELPER for m in methods
    ):
        raise C30Error("polling first consumer is not CheckJson")
    helper_rva = first.get("target_rva")
    if not isinstance(helper_rva, int):
        raise C30Error("CheckJson RVA missing")
    ops = row.get("helper_json_operations")
    if not isinstance(ops, list):
        raise C30Error("polling helper operations missing")
    tojson = [
        op for op in ops
        if isinstance(op, dict)
        and op.get("operation") == "json-to-json"
        and any(
            isinstance(m, dict) and m.get("name") == TOJSON_NAME
            for m in (op.get("target_methods") or [])
        )
    ]
    if len(tojson) != 1:
        raise C30Error(f"expected one polling ToJson operation, got {len(tojson)}")
    callsite = tojson[0].get("callsite_rva")
    target = tojson[0].get("target_rva")
    if not isinstance(callsite, int) or not isinstance(target, int):
        raise C30Error("polling ToJson identity missing")
    return {
        "route": TARGET_ROUTE,
        "endpoint_id": TARGET_ENDPOINT_ID,
        "helper_method": TARGET_HELPER,
        "helper_rva": helper_rva,
        "tojson_callsite_rva": callsite,
        "tojson_target_rva": target,
    }


def analyze(view: Any, script_json: Path, target: dict[str, Any]) -> dict[str, Any]:
    starts, managed_starts = BASE.load_method_starts(script_json)
    start = int(target["helper_rva"])
    callsite = int(target["tojson_callsite_rva"])
    end = BASE.function_end(starts, start)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, end - start), start))
    by = {int(ins.address): ins for ins in insns}
    ins = by.get(callsite)
    if ins is None or ins.id != ARM64_INS_BL:
        raise C30Error("polling ToJson callsite is not direct BL")
    if BASE.branch_target(ins) != int(target["tojson_target_rva"]):
        raise C30Error("polling ToJson target mismatch")
    addrs = sorted(by)
    pos = addrs.index(callsite)
    if pos + 1 >= len(addrs):
        raise C30Error("polling ToJson has no following instruction")
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
            raise C30Error("polling ToJson liveness iteration cap exceeded")
        current = state_at[addr]
        out_state, new_sinks, terminal = BASE.transfer(by[addr], md, current, managed_starts)
        for sink in new_sinks:
            key = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in sink.items()))
            sinks[key] = sink
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

    known_exits = len(returns) + len(tails)
    dead = not sinks and not reached_unresolved and known_exits > 0
    return {
        **target,
        "post_tojson_entry_rva": entry,
        "reachable_instruction_count": len(state_at),
        "reachable_normal_return_count": len(returns),
        "reachable_managed_tail_exit_count": len(tails),
        "reachable_unresolved_control_flow": reached_unresolved,
        "semantic_sink_count": len(sinks),
        "semantic_sinks": sorted(sinks.values(), key=lambda row: (int(row["rva"]), str(row["kind"]))),
        "tojson_result_value_class": "dead-value" if dead else "observable-or-unresolved",
        "parser_local_empty_object_safe": dead,
        "untouched_client_acceptance": False,
        "ui_visible_success": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--c21", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        target = load_target(args.c21)
        view = BASE.BinaryView(args.lib)
        try:
            report = analyze(view, args.script_json, target)
        finally:
            view.close()
    except (OSError, json.JSONDecodeError, C30Error, BASE.AnalysisError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = {"schema": SCHEMA, "scope": "C30 final-client CheckJson ToJson-return liveness", **report}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "route": report["route"],
        "tojson_result_value_class": report["tojson_result_value_class"],
        "semantic_sink_count": report["semantic_sink_count"],
        "semantic_sinks": report["semantic_sinks"],
        "reachable_unresolved_control_flow_count": len(report["reachable_unresolved_control_flow"]),
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
