#!/usr/bin/env python3
"""C24: recursively refine C21-unresolved opaque data through direct helpers.

C21 inspects one direct helper body.  Some final-client helpers immediately pass
the same JsonData object to another managed helper, so the first-level pass can
remain unresolved even though a deeper direct call contains shape evidence.

This pass follows only direct managed BL/B calls that receive the tainted ``data``
argument, with a strict depth/visit bound.  At every level it records exact
LitJson JsonData operations on that tainted argument.  Indirect BLR calls are
counted but never assigned an identity.  Method names alone never prove a shape.
No empty response value or untouched-client acceptance is inferred.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_B, ARM64_INS_BL, ARM64_INS_BLR, ARM64_OP_REG

ROOT = Path(__file__).resolve().parents[1]
BASE_PATH = ROOT / "scripts" / "analyze-empty-object-zero-iteration.py"
C21_PATH = ROOT / "scripts" / "analyze-opaque-data-helper-semantics.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BASE = _load_module("c24_zero_iteration_base", BASE_PATH)
C21 = _load_module("c24_c21_semantics", C21_PATH)

SCHEMA = 1
MAX_DEPTH = 3
MAX_VISITS = 64


class RecursiveHelperError(ValueError):
    pass


def load_targets(c20_path: Path, c21_path: Path) -> list[dict[str, Any]]:
    c20 = json.loads(c20_path.read_text(encoding="utf-8"))
    c21 = json.loads(c21_path.read_text(encoding="utf-8"))
    if c20.get("schema") != 1 or c20.get("target_route_count") != 15:
        raise RecursiveHelperError("unexpected C20 report")
    if c21.get("schema") != 1 or c21.get("target_route_count") != 15:
        raise RecursiveHelperError("unexpected C21 report")
    by20 = {row["route"]: row for row in c20.get("routes", []) if isinstance(row, dict)}
    out = []
    for row in c21.get("routes", []):
        if not isinstance(row, dict) or row.get("shape_refinement") != "helper-unresolved":
            continue
        route = row.get("route")
        source = by20.get(route)
        if source is None:
            raise RecursiveHelperError(f"C21 unresolved route absent from C20: {route}")
        first = source.get("first_direct_managed_consumer")
        out.append({
            "route": route,
            "endpoint_id": source.get("endpoint_id"),
            "task": source.get("task"),
            "first_direct_managed_consumer": first,
        })
    return sorted(out, key=lambda row: str(row["route"]))


def _method_names(methods: list[dict[str, Any]]) -> list[str]:
    return sorted({str(row.get("name")) for row in methods if row.get("name")})


def trace_recursive(
    *,
    helper_rva: int,
    data_arg_positions: list[int],
    view: Any,
    starts: list[int],
    managed: dict[int, list[dict[str, str | None]]],
    depth: int,
    chain: list[dict[str, Any]],
    seen: set[tuple[int, tuple[int, ...]]],
    state: dict[str, Any],
) -> None:
    key = (helper_rva, tuple(sorted(set(data_arg_positions))))
    if key in seen:
        return
    if depth > MAX_DEPTH or len(seen) >= MAX_VISITS:
        state["truncated"] = True
        return
    seen.add(key)
    state["visited_helper_count"] += 1

    end = BASE.function_end(starts, helper_rva)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(helper_rva, end - helper_rva), helper_rva))
    regs: dict[str, set[str]] = {
        f"x{pos}": {"data"} for pos in sorted(set(data_arg_positions)) if 0 <= pos <= 7
    }
    stack: dict[tuple[str, int], set[str]] = {}

    for ins in insns:
        if ins.id in {ARM64_INS_BL, ARM64_INS_B}:
            target = BASE.branch_target(ins)
            arg_positions = [idx for idx in range(8) if "data" in regs.get(f"x{idx}", set())]
            methods = managed.get(target or -1, [])
            if arg_positions and methods:
                op = C21.json_operation(methods)
                call = {
                    "callsite_rva": int(ins.address),
                    "target_rva": target,
                    "branch_kind": "BL" if ins.id == ARM64_INS_BL else "B-tail",
                    "argument_positions": arg_positions,
                    "target_methods": methods,
                }
                if op is not None:
                    state["json_operations"].append({
                        **call,
                        "operation": op,
                        "depth": depth,
                        "helper_chain": chain,
                    })
                elif depth < MAX_DEPTH:
                    state["managed_helper_edges"].append({
                        **call,
                        "depth": depth,
                        "helper_chain": chain,
                    })
                    trace_recursive(
                        helper_rva=int(target),
                        data_arg_positions=arg_positions,
                        view=view,
                        starts=starts,
                        managed=managed,
                        depth=depth + 1,
                        chain=chain + [{
                            "rva": int(target),
                            "methods": _method_names(methods),
                            "argument_positions": arg_positions,
                        }],
                        seen=seen,
                        state=state,
                    )
            if ins.id == ARM64_INS_BL:
                for reg in list(regs):
                    if reg in BASE.CALLER_SAVED:
                        regs.pop(reg, None)
            continue
        if ins.id == ARM64_INS_BLR:
            arg_positions = [idx for idx in range(8) if "data" in regs.get(f"x{idx}", set())]
            if arg_positions:
                target_reg = None
                if ins.operands and ins.operands[0].type == ARM64_OP_REG:
                    target_reg = BASE.norm_reg(md.reg_name(ins.operands[0].reg))
                state["indirect_tainted_calls"].append({
                    "callsite_rva": int(ins.address),
                    "target_register": target_reg,
                    "argument_positions": arg_positions,
                    "depth": depth,
                    "helper_chain": chain,
                })
            for reg in list(regs):
                if reg in BASE.CALLER_SAVED:
                    regs.pop(reg, None)
            continue
        BASE.propagate_simple(ins, md, regs, stack)


def analyze_route(
    row: dict[str, Any],
    view: Any,
    starts: list[int],
    managed: dict[int, list[dict[str, str | None]]],
) -> dict[str, Any]:
    first = row.get("first_direct_managed_consumer")
    state: dict[str, Any] = {
        "json_operations": [],
        "managed_helper_edges": [],
        "indirect_tainted_calls": [],
        "visited_helper_count": 0,
        "truncated": False,
    }
    if isinstance(first, dict) and isinstance(first.get("target_rva"), int):
        positions = [int(x) for x in first.get("argument_positions", []) if isinstance(x, int)]
        methods = first.get("target_methods") if isinstance(first.get("target_methods"), list) else []
        trace_recursive(
            helper_rva=int(first["target_rva"]),
            data_arg_positions=positions,
            view=view,
            starts=starts,
            managed=managed,
            depth=1,
            chain=[{
                "rva": int(first["target_rva"]),
                "methods": _method_names(methods),
                "argument_positions": positions,
            }],
            seen=set(),
            state=state,
        )
    operations = [str(item["operation"]) for item in state["json_operations"]]
    shape = C21.shape_from_operations(operations)
    return {
        "route": row.get("route"),
        "endpoint_id": row.get("endpoint_id"),
        "task": row.get("task"),
        "recursive_shape_refinement": shape,
        "recursive_json_operations": state["json_operations"],
        "managed_helper_edge_count": len(state["managed_helper_edges"]),
        "managed_helper_edges": state["managed_helper_edges"],
        "indirect_tainted_call_count": len(state["indirect_tainted_calls"]),
        "indirect_tainted_calls": state["indirect_tainted_calls"],
        "visited_helper_count": state["visited_helper_count"],
        "analysis_truncated": state["truncated"],
        "empty_value_promotion": "not-proven-by-c24",
        "untouched_client_acceptance": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lib", type=Path, required=True)
    p.add_argument("--script-json", type=Path, required=True)
    p.add_argument("--c20", type=Path, required=True)
    p.add_argument("--c21", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    try:
        targets = load_targets(args.c20, args.c21)
        starts, managed = C21.load_managed(args.script_json)
        view = BASE.BinaryView(args.lib)
        try:
            routes = [analyze_route(row, view, starts, managed) for row in targets]
        finally:
            view.close()
    except (OSError, json.JSONDecodeError, RecursiveHelperError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    counts = Counter(row["recursive_shape_refinement"] for row in routes)
    report = {
        "schema": SCHEMA,
        "scope": (
            "C24 bounded recursive direct-managed helper taint for C21-unresolved opaque data; "
            "shape evidence only, indirect calls unresolved, no response values"
        ),
        "target_route_count": len(routes),
        "max_depth": MAX_DEPTH,
        "max_visits_per_route": MAX_VISITS,
        "shape_refinement_counts": dict(sorted(counts.items())),
        "routes": routes,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "target_route_count": report["target_route_count"],
        "shape_refinement_counts": report["shape_refinement_counts"],
        "refined_routes": [
            {"route": row["route"], "shape": row["recursive_shape_refinement"]}
            for row in routes if row["recursive_shape_refinement"] != "helper-unresolved"
        ],
        "indirect_tainted_call_routes": [
            row["route"] for row in routes if row["indirect_tainted_call_count"]
        ],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
