#!/usr/bin/env python3
"""C20: trace opaque C17 ``data`` values into their first direct consumers.

C17 leaves fifteen low-complexity routes at ``data-only:opaque:json`` because the
parser reads the top-level ``data`` value but performs no recognized shape/scalar
conversion at the C3 access site.  This pass keeps the value structural: after
the exact ``JsonData.get_Item(\"data\")`` call, it taints the returned object
through simple ARM64 register copies and stack spills and records direct managed
calls that receive the tainted value in x0..x7.  Indirect BLR consumers are
reported separately without inventing an identity.

The report is sanitized metadata only.  A helper name/signature may refine where
to investigate next, but C20 itself never manufactures a response value and does
not claim untouched-client acceptance.
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
from capstone.arm64 import ARM64_INS_BL, ARM64_INS_BLR, ARM64_OP_REG

ROOT = Path(__file__).resolve().parents[1]
BASE_SCRIPT = ROOT / "scripts" / "analyze-empty-object-zero-iteration.py"
SPEC = importlib.util.spec_from_file_location("c20_zero_iteration_base", BASE_SCRIPT)
assert SPEC is not None and SPEC.loader is not None
BASE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BASE
SPEC.loader.exec_module(BASE)

SCHEMA = 1
ARG_REGS = [f"x{i}" for i in range(8)]
INT_HINT = re.compile(r"(?:Int32|UInt32|Int64|UInt64|System_Int|\bint\b|\blong\b)", re.I)
BOOL_HINT = re.compile(r"(?:Boolean|System_Boolean|\bbool\b)", re.I)
STRING_HINT = re.compile(r"(?:System_String|\bstring\b)", re.I)


class OpaqueConsumerError(ValueError):
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


def load_targets(c17_path: Path, c3_path: Path) -> list[dict[str, Any]]:
    c17 = json.loads(c17_path.read_text(encoding="utf-8"))
    c3 = json.loads(c3_path.read_text(encoding="utf-8"))
    if c17.get("schema") != 1 or c3.get("schema") != 1:
        raise OpaqueConsumerError("C17/C3 schema mismatch")
    accesses: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in c3.get("accesses", []):
        if isinstance(row, dict):
            accesses[(str(row.get("task")), str(row.get("method")), str(row.get("field")))].append(row)

    out = []
    for route in c17.get("routes", []):
        if not isinstance(route, dict) or route.get("route_class") != "data-only:opaque:json":
            continue
        fields = route.get("fields")
        if not isinstance(fields, list) or len(fields) != 1 or fields[0].get("field") != "data":
            raise OpaqueConsumerError(f"unexpected opaque field layout for {route.get('route')}")
        field = fields[0]
        origin = (str(field.get("task")), str(field.get("method")), "data")
        rows = accesses.get(origin, [])
        method_rvas = {int(row["method_rva"]) for row in rows if isinstance(row.get("method_rva"), int)}
        access_rvas = {int(row["access_rva"]) for row in rows if isinstance(row.get("access_rva"), int)}
        if len(method_rvas) != 1 or len(access_rvas) != 1:
            raise OpaqueConsumerError(f"non-unique native data access for {route.get('route')}")
        out.append({
            "route": route["route"],
            "endpoint_id": route.get("endpoint_id"),
            "task": origin[0],
            "method": origin[1],
            "method_rva": next(iter(method_rvas)),
            "data_access_rva": next(iter(access_rvas)),
            "requiredness": field.get("requiredness"),
        })
    return sorted(out, key=lambda row: str(row["route"]))


def classify_consumer(methods: list[dict[str, str | None]]) -> str:
    text = "\n".join(
        f"{row.get('name') or ''} {row.get('signature') or ''}" for row in methods
    )
    low = text.lower()
    if "litjson.jsondata$$get_isarray" in low:
        return "json-is-array"
    if "litjson.jsondata$$get_isobject" in low:
        return "json-is-object"
    if "litjson.jsondata$$get_keys" in low:
        return "json-keys"
    if "litjson.jsondata$$get_count" in low:
        return "json-count"
    if "litjson.jsondata$$get_item" in low:
        return "json-index"
    if "toint" in low or ("op_explicit" in low and INT_HINT.search(text)):
        return "scalar-int-like"
    if "tobool" in low or ("op_explicit" in low and BOOL_HINT.search(text)):
        return "scalar-bool-like"
    if "tostring" in low or ("op_explicit" in low and STRING_HINT.search(text)):
        return "scalar-string-like"
    names = [str(row.get("name") or "") for row in methods]
    if any("$$Parse" in name or "Parser$$" in name or "Parse" in name.split("$$")[-1] for name in names):
        return "managed-parse-helper"
    if any(token in low for token in ("dictionary", "list`", "hashset", "collection", "enumerator")):
        return "managed-collection-helper"
    return "managed-other"


def _arg_positions(regs: dict[str, set[str]]) -> list[int]:
    return [index for index, reg in enumerate(ARG_REGS) if "data" in regs.get(reg, set())]


def analyze_target(
    target: dict[str, Any],
    view: Any,
    starts: list[int],
    managed: dict[int, list[dict[str, str | None]]],
) -> dict[str, Any]:
    start = int(target["method_rva"])
    end = BASE.function_end(starts, start)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(start, end - start), start))
    access = int(target["data_access_rva"])
    regs: dict[str, set[str]] = {}
    stack: dict[tuple[str, int], set[str]] = {}
    seen_access = False
    direct_consumers: list[dict[str, Any]] = []
    indirect_consumers: list[dict[str, Any]] = []

    for ins in insns:
        a = int(ins.address)
        if a < access:
            continue
        if ins.id == ARM64_INS_BL:
            callee = BASE.branch_target(ins)
            if a == access:
                regs = {"x0": {"data"}}
                stack = {}
                seen_access = True
                continue
            if not seen_access:
                continue
            arg_positions = _arg_positions(regs)
            methods = managed.get(callee or -1, [])
            if arg_positions and methods:
                direct_consumers.append({
                    "callsite_rva": a,
                    "target_rva": callee,
                    "argument_positions": arg_positions,
                    "consumer_class": classify_consumer(methods),
                    "target_methods": methods,
                })
            # AAPCS64 caller-saved registers are clobbered by any direct call.
            for reg in list(regs):
                if reg in BASE.CALLER_SAVED:
                    regs.pop(reg, None)
            continue
        if ins.id == ARM64_INS_BLR:
            if not seen_access:
                continue
            arg_positions = _arg_positions(regs)
            if arg_positions:
                reg = None
                if ins.operands and ins.operands[0].type == ARM64_OP_REG:
                    reg = BASE.norm_reg(md.reg_name(ins.operands[0].reg))
                indirect_consumers.append({
                    "callsite_rva": a,
                    "target_register": reg,
                    "argument_positions": arg_positions,
                    "consumer_class": "indirect-call-identity-unresolved",
                })
            for caller_reg in list(regs):
                if caller_reg in BASE.CALLER_SAVED:
                    regs.pop(caller_reg, None)
            continue
        if seen_access:
            BASE.propagate_simple(ins, md, regs, stack)

    first_direct = direct_consumers[0] if direct_consumers else None
    first_indirect = indirect_consumers[0] if indirect_consumers else None
    if first_direct is not None:
        resolution = "direct-managed-consumer"
    elif first_indirect is not None:
        resolution = "indirect-consumer-only"
    else:
        resolution = "no-consumer-recovered"
    return {
        **target,
        "consumer_resolution": resolution,
        "first_direct_managed_consumer": first_direct,
        "direct_managed_consumer_count": len(direct_consumers),
        "first_indirect_consumer": first_indirect,
        "indirect_consumer_count": len(indirect_consumers),
        "direct_consumer_classes": dict(sorted(Counter(row["consumer_class"] for row in direct_consumers).items())),
        "response_value_promotion": "not-proven-by-c20",
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
        starts, managed = load_managed(args.script_json)
        view = BASE.BinaryView(args.lib)
        try:
            routes = [analyze_target(row, view, starts, managed) for row in targets]
        finally:
            view.close()
    except (OSError, json.JSONDecodeError, OpaqueConsumerError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    resolution_counts = Counter(row["consumer_resolution"] for row in routes)
    first_class_counts = Counter(
        row["first_direct_managed_consumer"]["consumer_class"]
        for row in routes if row["first_direct_managed_consumer"] is not None
    )
    report = {
        "schema": SCHEMA,
        "scope": (
            "C20 exact final-client taint from opaque top-level data access into direct/indirect consumers; "
            "structural evidence only, no response values inferred"
        ),
        "target_route_count": len(routes),
        "resolution_counts": dict(sorted(resolution_counts.items())),
        "first_direct_consumer_class_counts": dict(sorted(first_class_counts.items())),
        "routes": routes,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "target_route_count": report["target_route_count"],
        "resolution_counts": report["resolution_counts"],
        "first_direct_consumer_class_counts": report["first_direct_consumer_class_counts"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
