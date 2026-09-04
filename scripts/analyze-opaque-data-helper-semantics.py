#!/usr/bin/env python3
"""C21: refine C20 opaque ``data`` shapes through exact helper semantics.

C20 recovers the first direct managed consumer for fourteen of fifteen opaque
low-complexity routes.  This pass enters that consumer when it is a helper and
taints the exact argument position carrying ``data`` through the helper body.
It records direct LitJson JsonData operations that receive the tainted value,
including string/int get_Item overloads, get_Keys/Count and IsObject/IsArray.

A shape refinement is emitted only from those exact operations.  Helper names by
themselves are context, not proof.  The report remains static parser/helper
evidence and never manufactures response values or untouched-client acceptance.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL

ROOT = Path(__file__).resolve().parents[1]
BASE_SCRIPT = ROOT / "scripts" / "analyze-empty-object-zero-iteration.py"
SPEC = importlib.util.spec_from_file_location("c21_zero_iteration_base", BASE_SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

SCHEMA = 1
INT_HINT = re.compile(r"(?:Int32|UInt32|System_Int32|System_UInt32|\bint\b)", re.I)
STRING_HINT = re.compile(r"(?:System_String|\bstring\b)", re.I)


class HelperSemanticError(ValueError):
    pass


def load_managed(path: Path) -> tuple[list[int], dict[int, list[dict[str, str | None]]]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    starts: set[int] = set()
    methods: dict[int, list[dict[str, str | None]]] = defaultdict(list)
    for row in raw.get("ScriptMethod", []):
        rva = BASE.as_int(row.get("Address", 0))
        if rva <= 0:
            continue
        starts.add(rva)
        name = str(row.get("Name") or "")
        sig = row.get("Signature")
        if name:
            methods[rva].append({"name": name, "signature": str(sig) if sig else None})
    for value in raw.get("Addresses", []):
        rva = BASE.as_int(value)
        if rva > 0:
            starts.add(rva)
    for rows in methods.values():
        rows.sort(key=lambda row: str(row["name"]))
    return sorted(starts), dict(methods)


def item_index_kind(signature: str | None) -> str:
    if not signature:
        return "unknown"
    params = signature.split("(", 1)[1] if "(" in signature else signature
    if STRING_HINT.search(params):
        return "string-key"
    if INT_HINT.search(params):
        return "integer-index"
    return "unknown"


def json_operation(methods: list[dict[str, str | None]]) -> str | None:
    text = "\n".join(f"{row.get('name') or ''} {row.get('signature') or ''}" for row in methods)
    low = text.lower()
    if "litjson.jsondata$$get_item" in low:
        kinds = {item_index_kind(row.get("signature")) for row in methods if "get_Item" in str(row.get("name") or "")}
        if "string-key" in kinds:
            return "json-index-string"
        if "integer-index" in kinds:
            return "json-index-int"
        return "json-index-unknown"
    if "litjson.jsondata$$get_keys" in low:
        return "json-keys"
    if "litjson.jsondata$$get_isobject" in low:
        return "json-is-object"
    if "litjson.jsondata$$get_isarray" in low:
        return "json-is-array"
    if "litjson.jsondata$$get_count" in low:
        return "json-count"
    if "litjson.jsondata$$tojson" in low:
        return "json-to-json"
    return None


def shape_from_operations(operations: list[str]) -> str:
    kinds = set(operations)
    object_ops = {"json-index-string", "json-keys", "json-is-object"}
    array_ops = {"json-index-int", "json-is-array"}
    has_object = bool(kinds & object_ops)
    has_array = bool(kinds & array_ops)
    if has_object and not has_array:
        return "helper-proven-object"
    if has_array and not has_object:
        return "helper-proven-array"
    if has_object and has_array:
        return "helper-mixed-object-array"
    if "json-count" in kinds:
        return "helper-countable-ambiguous"
    if "json-to-json" in kinds:
        return "helper-opaque-json"
    return "helper-unresolved"


def analyze_helper(
    helper_rva: int,
    data_arg_positions: list[int],
    view: Any,
    starts: list[int],
    managed: dict[int, list[dict[str, str | None]]],
) -> list[dict[str, Any]]:
    end = BASE.function_end(starts, helper_rva)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(helper_rva, end - helper_rva), helper_rva))
    regs: dict[str, set[str]] = {f"x{pos}": {"data"} for pos in data_arg_positions if 0 <= pos <= 7}
    stack: dict[tuple[str, int], set[str]] = {}
    operations: list[dict[str, Any]] = []

    for ins in insns:
        if ins.id == ARM64_INS_BL:
            callee = BASE.branch_target(ins)
            methods = managed.get(callee or -1, [])
            arg_positions = [idx for idx in range(8) if "data" in regs.get(f"x{idx}", set())]
            op = json_operation(methods) if arg_positions and methods else None
            if op is not None:
                operations.append({
                    "callsite_rva": int(ins.address),
                    "target_rva": callee,
                    "argument_positions": arg_positions,
                    "operation": op,
                    "target_methods": methods,
                })
            for reg in list(regs):
                if reg in BASE.CALLER_SAVED:
                    regs.pop(reg, None)
            continue
        BASE.propagate_simple(ins, md, regs, stack)
    return operations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--c20", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        c20 = json.loads(args.c20.read_text(encoding="utf-8"))
        if c20.get("schema") != 1 or c20.get("target_route_count") != 15:
            raise HelperSemanticError("unexpected C20 report")
        starts, managed = load_managed(args.script_json)
        view = BASE.BinaryView(args.lib)
        try:
            rows = []
            for route in c20.get("routes", []):
                if not isinstance(route, dict):
                    continue
                first = route.get("first_direct_managed_consumer")
                immediate_ops: list[str] = []
                helper_ops: list[dict[str, Any]] = []
                if isinstance(first, dict):
                    first_methods = first.get("target_methods") if isinstance(first.get("target_methods"), list) else []
                    immediate = json_operation(first_methods)
                    if immediate is not None:
                        immediate_ops.append(immediate)
                    else:
                        target_rva = first.get("target_rva")
                        positions = first.get("argument_positions")
                        if isinstance(target_rva, int) and isinstance(positions, list):
                            helper_ops = analyze_helper(
                                target_rva,
                                [int(x) for x in positions if isinstance(x, int)],
                                view,
                                starts,
                                managed,
                            )
                all_ops = immediate_ops + [str(op["operation"]) for op in helper_ops]
                shape = shape_from_operations(all_ops)
                rows.append({
                    "route": route.get("route"),
                    "endpoint_id": route.get("endpoint_id"),
                    "task": route.get("task"),
                    "first_consumer_resolution": route.get("consumer_resolution"),
                    "first_direct_consumer": first,
                    "immediate_json_operations": immediate_ops,
                    "helper_json_operations": helper_ops,
                    "shape_refinement": shape,
                    "empty_value_promotion": "not-proven-by-c21",
                    "untouched_client_acceptance": False,
                })
        finally:
            view.close()
    except (OSError, json.JSONDecodeError, HelperSemanticError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    counts = Counter(row["shape_refinement"] for row in rows)
    report = {
        "schema": SCHEMA,
        "scope": (
            "C21 exact final-client first-consumer/helper JsonData operations for C20 opaque data; "
            "shape refinement only, no response values or empty-container acceptance"
        ),
        "target_route_count": len(rows),
        "shape_refinement_counts": dict(sorted(counts.items())),
        "routes": sorted(rows, key=lambda row: str(row["route"])),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "target_route_count": report["target_route_count"],
        "shape_refinement_counts": report["shape_refinement_counts"],
        "refined_routes": [
            {"route": row["route"], "shape": row["shape_refinement"]}
            for row in report["routes"] if row["shape_refinement"] not in {"helper-unresolved", "helper-opaque-json"}
        ],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
