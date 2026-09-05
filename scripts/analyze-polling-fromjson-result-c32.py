#!/usr/bin/env python3
"""C32: trace the deserialized object returned inside Concert polling CheckJson.

C30 shows the `CheckJson` helper serializes response data then invokes the same
`UnityEngine.JsonUtility.FromJson<object>` body identified by C29.  This pass
starts after that exact call and follows the returned object through CheckJson
using the hardened C27 CFG/dataflow rules.
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
SPEC = importlib.util.spec_from_file_location("c27_hardened_for_c32", RUNNER)
assert SPEC is not None and SPEC.loader is not None
HARD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARD
SPEC.loader.exec_module(HARD)
BASE = HARD.BASE

SCHEMA = 1
FROMJSON_SHARED_RVA = 91388168
TARGET_ROUTE = "/concert/mv_polling"
TARGET_ENDPOINT_ID = 306


class C32Error(ValueError):
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
        starts.add(rva); managed_starts.add(rva)
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


def load_target(c30_path: Path) -> dict[str, Any]:
    doc = json.loads(c30_path.read_text(encoding="utf-8"))
    if doc.get("schema") != 1 or doc.get("route") != TARGET_ROUTE or doc.get("endpoint_id") != TARGET_ENDPOINT_ID:
        raise C32Error("unexpected C30 report")
    sinks = doc.get("semantic_sinks")
    if not isinstance(sinks, list) or len(sinks) != 1:
        raise C32Error("expected one polling ToJson-result sink")
    sink = sinks[0]
    if (
        not isinstance(sink, dict)
        or sink.get("kind") != "call-argument"
        or sink.get("call_kind") != "direct"
        or sink.get("argument_positions") != [0]
        or sink.get("target_rva") != FROMJSON_SHARED_RVA
    ):
        raise C32Error("polling sink is not shared FromJson<object>")
    helper_rva = doc.get("helper_rva")
    callsite = sink.get("rva")
    if not isinstance(helper_rva, int) or not isinstance(callsite, int):
        raise C32Error("polling helper/FromJson RVA missing")
    return {
        "route": TARGET_ROUTE,
        "endpoint_id": TARGET_ENDPOINT_ID,
        "helper_method": doc.get("helper_method"),
        "helper_rva": helper_rva,
        "fromjson_callsite_rva": callsite,
        "fromjson_target_rva": FROMJSON_SHARED_RVA,
    }


def analyze(view: Any, script_json: Path, target: dict[str, Any]) -> dict[str, Any]:
    starts, managed_starts, methods = load_managed(script_json)
    if not any(m.get("name") == "UnityEngine.JsonUtility$$FromJson<object>" for m in methods.get(FROMJSON_SHARED_RVA, [])):
        raise C32Error("shared FromJson<object> identity changed")
    start = int(target["helper_rva"])
    callsite = int(target["fromjson_callsite_rva"])
    end = BASE.function_end(starts, start)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
    insns = list(md.disasm(view.read(start, end - start), start))
    by = {int(ins.address): ins for ins in insns}
    call = by.get(callsite)
    if call is None or call.id != ARM64_INS_BL or BASE.branch_target(call) != FROMJSON_SHARED_RVA:
        raise C32Error("polling FromJson callsite mismatch")
    addrs = sorted(by); pos = addrs.index(callsite)
    if pos + 1 >= len(addrs):
        raise C32Error("polling FromJson has no following instruction")
    entry = addrs[pos + 1]
    succ, unresolved = BASE.instruction_successors(insns, start, end, managed_starts)
    state_at: dict[int, Any] = {entry: BASE.State(frozenset({"x0"}), frozenset())}
    queue: deque[int] = deque([entry])
    sinks: dict[tuple[Any, ...], dict[str, Any]] = {}
    returns: set[int] = set(); tails: set[int] = set(); reached_unresolved: list[dict[str, Any]] = []
    iterations = 0
    while queue:
        addr = queue.popleft(); iterations += 1
        if iterations > 200000:
            raise C32Error("polling result dataflow iteration cap exceeded")
        current = state_at[addr]
        out_state, new_sinks, terminal = BASE.transfer(by[addr], md, current, managed_starts)
        for sink in new_sinks:
            enriched = dict(sink)
            callee = enriched.get("target_rva")
            if isinstance(callee, int) and callee in methods:
                enriched["target_methods"] = methods[callee]
            key = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in enriched.items()))
            sinks[key] = enriched
        if terminal == "return": returns.add(addr)
        elif terminal == "managed-tail-exit": tails.add(addr)
        for edge in unresolved:
            if edge["rva"] == addr:
                reached_unresolved.append(edge)
                if current.regs or current.stack:
                    sink = {"kind":"unknown-control-flow-with-live-taint","rva":addr,"edge_kind":edge["kind"]}
                    key = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in sink.items()))
                    sinks[key] = sink
        for dst in succ.get(addr, []):
            previous = state_at.get(dst)
            merged = out_state if previous is None else previous.union(out_state)
            if previous != merged:
                state_at[dst] = merged; queue.append(dst)
    return {
        "schema": SCHEMA,
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
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lib", type=Path, required=True)
    p.add_argument("--script-json", type=Path, required=True)
    p.add_argument("--c30", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        target = load_target(args.c30)
        view = BASE.BinaryView(args.lib)
        try: report = analyze(view, args.script_json, target)
        finally: view.close()
    except (OSError, json.JSONDecodeError, C32Error, BASE.AnalysisError) as exc:
        print(f"error: {exc}", file=sys.stderr); return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    print(json.dumps({
        "route": report["route"],
        "semantic_sink_count": report["semantic_sink_count"],
        "semantic_sink_kind_counts": report["semantic_sink_kind_counts"],
        "semantic_sinks": report["semantic_sinks"],
        "reachable_unresolved_control_flow_count": len(report["reachable_unresolved_control_flow"]),
    }, indent=2, sort_keys=True))
    return 0

if __name__ == "__main__": raise SystemExit(main())
