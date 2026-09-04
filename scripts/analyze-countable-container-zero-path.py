#!/usr/bin/env python3
"""C19c: refine five C17 Count-only top-level data parsers.

For each ``data-only:countable-collection-ambiguous`` route this pass uses exact
final-client managed call signatures after ``JsonData.get_Count`` to distinguish
integer-index sequence usage from string-key/object usage, then taints the Count
result through registers/stack to find the zero-count loop guard. A parser-local
empty-sequence proof requires a zero-count successor that reaches a known parser
exit without executing a post-count JsonData index call.

This is still static parser evidence. It does not imply callback/UI or untouched-
client acceptance.
"""
from __future__ import annotations

import argparse
import bisect
import importlib.util
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_OP_IMM, ARM64_OP_REG

ROOT = Path(__file__).resolve().parents[1]
BASE_SCRIPT = ROOT / "scripts" / "analyze-empty-object-zero-iteration.py"
SPEC = importlib.util.spec_from_file_location("c19b_zero_iteration_base", BASE_SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

SCHEMA = 1
INT_HINT = re.compile(r"(?:Int32|UInt32|System_Int32|System_UInt32|\bint\b)", re.I)
STRING_HINT = re.compile(r"(?:System_String|\bstring\b)", re.I)
EQ_TRUE_CONDITIONS = {"eq", "ge", "le", "hs", "cs", "ls"}
EQ_FALSE_CONDITIONS = {"ne", "gt", "lt", "hi", "lo", "cc"}


class CountableError(ValueError):
    pass


def load_managed(path: Path) -> tuple[list[int], dict[int, list[dict[str, str | None]]], set[int]]:
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
    return sorted(starts), dict(methods), set(methods)


def load_targets(c17_path: Path, c3_path: Path) -> list[dict[str, Any]]:
    c17 = json.loads(c17_path.read_text(encoding="utf-8"))
    c3 = json.loads(c3_path.read_text(encoding="utf-8"))
    if c17.get("schema") != 1 or c3.get("schema") != 1:
        raise CountableError("C17/C3 schema mismatch")
    by_origin: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in c3.get("accesses", []):
        if isinstance(row, dict):
            by_origin[(str(row.get("task")), str(row.get("method")), str(row.get("field")))].append(row)
    targets = []
    for route in c17.get("routes", []):
        if not isinstance(route, dict) or route.get("route_class") != "data-only:countable-collection-ambiguous":
            continue
        fields = route.get("fields")
        if not isinstance(fields, list) or len(fields) != 1:
            raise CountableError(f"unexpected field layout for {route.get('route')}")
        field = fields[0]
        origin = (str(field.get("task")), str(field.get("method")), str(field.get("field")))
        rows = [row for row in by_origin.get(origin, []) if "get_Count" in str(row.get("conversion_helper") or "")]
        method_rvas = {int(row["method_rva"]) for row in rows if isinstance(row.get("method_rva"), int)}
        count_rvas = {int(row["conversion_rva"]) for row in rows if isinstance(row.get("conversion_rva"), int)}
        if len(method_rvas) != 1 or len(count_rvas) != 1:
            raise CountableError(f"non-unique Count site for {route.get('route')}")
        targets.append({
            "route": route["route"],
            "endpoint_id": route["endpoint_id"],
            "task": origin[0],
            "method": origin[1],
            "method_rva": next(iter(method_rvas)),
            "count_rva": next(iter(count_rvas)),
            "requiredness": field.get("requiredness"),
        })
    return targets


def item_signature_kind(signature: str | None) -> str:
    if not signature:
        return "unknown"
    # Parameter portion is sufficient for overload discrimination.
    params = signature.split("(", 1)[1] if "(" in signature else signature
    if STRING_HINT.search(params):
        return "string-key"
    if INT_HINT.search(params):
        return "integer-index"
    return "unknown"


def zero_cmp_successor(ins: Any, cfg: dict[str, Any], lhs_tags: set[str], rhs_tags: set[str]) -> tuple[int | None, str | None]:
    m = ins.mnemonic.lower()
    target = BASE.branch_target(ins)
    fall = cfg["next"].get(int(ins.address))
    if not m.startswith("b."):
        return None, None
    cond = m[2:]
    # At Count==0 and known-zero counterpart, CMP operands are equal regardless
    # of operand order. Therefore branch truth is determined by equality only.
    if not (("count" in lhs_tags and "zero" in rhs_tags) or ("zero" in lhs_tags and "count" in rhs_tags)):
        return None, None
    if cond in EQ_TRUE_CONDITIONS:
        return target, f"cmp-zero-{cond}-taken"
    if cond in EQ_FALSE_CONDITIONS:
        return fall, f"cmp-zero-{cond}-fallthrough"
    return None, None


def analyze_target(target: dict[str, Any], view: Any, starts: list[int], managed: dict[int, list[dict[str, str | None]]], managed_starts: set[int]) -> dict[str, Any]:
    start = int(target["method_rva"])
    end = BASE.function_end(starts, start)
    cfg = BASE.build_cfg(view, start, end, managed_starts)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, end - start), start))
    count_site = int(target["count_rva"])

    post_item_calls = []
    for ins in insns:
        a = int(ins.address)
        if a <= count_site or ins.id != ARM64_INS_BL:
            continue
        callee = BASE.branch_target(ins)
        for method in managed.get(callee or -1, []):
            name = str(method["name"])
            if "LitJson.JsonData$$get_Item" in name:
                post_item_calls.append({
                    "callsite_rva": a,
                    "target_rva": callee,
                    "target_method": name,
                    "signature": method["signature"],
                    "index_kind": item_signature_kind(method["signature"]),
                })
    kinds = Counter(row["index_kind"] for row in post_item_calls)
    if kinds and set(kinds) == {"integer-index"}:
        usage = "integer-index-sequence"
    elif "string-key" in kinds:
        usage = "string-key-object"
    elif not kinds:
        usage = "count-only-no-index"
    else:
        usage = "mixed-or-unknown-index"

    forbidden = {row["callsite_rva"] for row in post_item_calls}
    regs: dict[str, set[str]] = {}
    stack: dict[tuple[str, int], set[str]] = {}
    seen_count = False
    pending_cmp: tuple[set[str], set[str], int] | None = None
    guards = []

    for ins in insns:
        a = int(ins.address)
        if a < count_site:
            continue
        if ins.id == ARM64_INS_BL:
            if a == count_site:
                regs = {"x0": {"count"}}
                seen_count = True
            else:
                for reg in list(regs):
                    if reg in BASE.CALLER_SAVED:
                        regs.pop(reg, None)
            pending_cmp = None
            continue
        if not seen_count:
            continue
        m = ins.mnemonic.lower()

        # Capture direct zero register branch on Count.
        if m in {"cbz", "cbnz"} and ins.operands and ins.operands[0].type == ARM64_OP_REG:
            reg = BASE.norm_reg(md.reg_name(ins.operands[0].reg))
            if "count" in regs.get(reg, set()):
                target_rva = BASE.branch_target(ins)
                fall = cfg["next"].get(a)
                successor = target_rva if m == "cbz" else fall
                proof = BASE.path_to_exit_avoiding(cfg, successor, forbidden) if successor is not None else None
                guards.append({
                    "guard_rva": a,
                    "guard_kind": f"count-zero-{'taken' if m == 'cbz' else 'fallthrough'}",
                    "zero_successor_rva": successor,
                    "zero_path_avoids_json_index": proof is not None,
                    "zero_exit_block": proof["exit_block"] if proof else None,
                    "zero_path_block_count": len(proof["path_blocks"]) if proof else 0,
                })
            pending_cmp = None
            continue

        if m == "cmp" and len(ins.operands) >= 2:
            def tags(op: Any) -> set[str]:
                if op.type == ARM64_OP_REG:
                    reg = BASE.norm_reg(md.reg_name(op.reg))
                    if reg in {"xzr", "wzr"}:
                        return {"zero"}
                    return set(regs.get(reg, set()))
                if op.type == ARM64_OP_IMM and int(op.imm) == 0:
                    return {"zero"}
                return set()
            lhs, rhs = tags(ins.operands[0]), tags(ins.operands[1])
            if ("count" in lhs and "zero" in rhs) or ("zero" in lhs and "count" in rhs):
                pending_cmp = (lhs, rhs, a)
            else:
                pending_cmp = None
            BASE.propagate_simple(ins, md, regs, stack)
            continue
        if m.startswith("b.") and pending_cmp is not None:
            lhs, rhs, _cmp_rva = pending_cmp
            successor, kind = zero_cmp_successor(ins, cfg, lhs, rhs)
            if successor is not None:
                proof = BASE.path_to_exit_avoiding(cfg, successor, forbidden)
                guards.append({
                    "guard_rva": a,
                    "guard_kind": kind,
                    "zero_successor_rva": successor,
                    "zero_path_avoids_json_index": proof is not None,
                    "zero_exit_block": proof["exit_block"] if proof else None,
                    "zero_path_block_count": len(proof["path_blocks"]) if proof else 0,
                })
            pending_cmp = None
            continue
        if BASE.is_cond(m):
            pending_cmp = None

        # Track literal zero assignment in addition to generic propagation.
        if m == "mov" and len(ins.operands) >= 2 and ins.operands[0].type == ARM64_OP_REG:
            dst = BASE.norm_reg(md.reg_name(ins.operands[0].reg))
            src = ins.operands[1]
            if (src.type == ARM64_OP_IMM and int(src.imm) == 0) or (
                src.type == ARM64_OP_REG and BASE.norm_reg(md.reg_name(src.reg)) in {"xzr", "wzr"}
            ):
                regs[dst] = {"zero"}
                continue
        BASE.propagate_simple(ins, md, regs, stack)

    proven = [g for g in guards if g["zero_path_avoids_json_index"]]
    empty_shape = None
    if usage == "integer-index-sequence" and proven and cfg["complete"]:
        empty_shape = []
        klass = "parser-empty-sequence-zero-path"
    elif usage == "string-key-object" and proven and cfg["complete"]:
        empty_shape = {}
        klass = "parser-empty-object-zero-path"
    else:
        klass = "not-proven"
    return {
        **target,
        "cfg_complete": bool(cfg["complete"]),
        "post_count_json_item_calls": post_item_calls,
        "post_count_index_kind_counts": dict(sorted(kinds.items())),
        "container_usage_class": usage,
        "zero_count_guards": guards,
        "proven_zero_count_guard_count": len(proven),
        "parser_empty_container_class": klass,
        "suggested_empty_data_shape": empty_shape,
        "untouched_client_acceptance": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--c17", type=Path, required=True)
    parser.add_argument("--c3", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        targets = load_targets(args.c17, args.c3)
        starts, managed, managed_starts = load_managed(args.script_json)
        view = BASE.BinaryView(args.lib)
        try:
            routes = [analyze_target(row, view, starts, managed, managed_starts) for row in targets]
        finally:
            view.close()
    except (OSError, json.JSONDecodeError, CountableError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    proven = [row for row in routes if row["parser_empty_container_class"] != "not-proven"]
    report = {
        "schema": SCHEMA,
        "scope": (
            "C19c final-client Count-only container usage plus zero-count CFG proof; "
            "suggested empty shape remains parser-local static evidence only"
        ),
        "target_route_count": len(routes),
        "parser_empty_container_zero_path_route_count": len(proven),
        "usage_class_counts": dict(sorted(Counter(row["container_usage_class"] for row in routes).items())),
        "routes": sorted(routes, key=lambda row: str(row["route"])),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "target_route_count": report["target_route_count"],
        "parser_empty_container_zero_path_route_count": report["parser_empty_container_zero_path_route_count"],
        "usage_class_counts": report["usage_class_counts"],
        "proven_routes": [row["route"] for row in proven],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
