#!/usr/bin/env python3
"""C4: recover request payload field writes from SetParameter ARM64 data flow.

Follow ``this``/arguments through common AArch64 moves, identify the exact object
stored into ``NetworkTask.Params`` at ``this+0x30``, and resolve stores on that
object against sanitized C2 BaseParam/PostParams layouts. Ambiguity is preserved:
a field name is emitted only from an exact payload layout or unanimous surviving
layout candidates. No native bytes or bulk disassembly are emitted.
"""
from __future__ import annotations

import argparse, bisect, json, re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile

SCHEMA = 1
PARAMS_OFFSET = 0x30
MAX_FUNCTION_SIZE = 0x20000
MAX_CANDIDATES = 24


@dataclass
class Arg:
    index: int
    name: str
    c_type: str
    reg: str | None
    is_pointer: bool


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.loads = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                self.loads.append((int(seg["p_vaddr"]), int(seg["p_memsz"]), int(seg["p_offset"]), int(seg["p_filesz"])))

    def close(self) -> None:
        self.stream.close()

    def read(self, address: int, size: int) -> bytes:
        for vaddr, memsz, offset, filesz in self.loads:
            if vaddr <= address < vaddr + memsz:
                rel = address - vaddr
                if rel >= filesz:
                    return b""
                self.stream.seek(offset + rel)
                return self.stream.read(min(size, filesz - rel))
        return b""


def as_int(value: Any) -> int:
    if isinstance(value, int): return value
    if isinstance(value, str): return int(value, 0)
    raise TypeError(value)


def canon(value: str) -> str:
    value = re.sub(r"<.*?>", "", value.replace("/", "."))
    return re.sub(r"[^A-Za-z0-9]", "", value).lower()


def norm_reg(value: str) -> str:
    value = value.lower()
    if len(value) > 1 and value[0] == "w" and value[1:].isdigit(): return "x" + value[1:]
    return value


def parse_args(signature: str) -> list[Arg]:
    if "(" not in signature: return []
    raw = signature.split("(", 1)[1].rsplit(")", 1)[0]
    out = []
    for i, part in enumerate(x.strip() for x in raw.split(",") if x.strip()):
        part = re.sub(r"\s+", " ", part)
        match = re.match(r"(.+?)([A-Za-z_][A-Za-z0-9_]*)$", part)
        if not match: continue
        typ, name = match.group(1).strip(), match.group(2)
        out.append(Arg(i, name, typ, f"x{i}" if i < 8 else None, "*" in typ or typ.endswith("_o")))
    return out


def ctype_managed_candidates(ctype: str) -> set[str]:
    value = ctype.replace("const ", "").replace("*", "").strip()
    for suffix in ("_o", "_array"):
        if value.endswith(suffix): value = value[:-len(suffix)]
    return {value, value.replace("_", ".")}


def load_script(path: Path) -> tuple[list[int], dict[int, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    starts, names = set(), {}
    for row in data.get("ScriptMethod", []):
        address = as_int(row.get("Address", 0))
        if address > 0:
            starts.add(address)
            names.setdefault(address, str(row.get("Name", "")))
    for value in data.get("Addresses", []):
        address = as_int(value)
        if address > 0: starts.add(address)
    return sorted(starts), names


def function_end(starts: list[int], start: int) -> int:
    i = bisect.bisect_right(starts, start)
    end = starts[i] if i < len(starts) else start + MAX_FUNCTION_SIZE
    return min(end, start + MAX_FUNCTION_SIZE)


def request_methods(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for task in inventory.get("tasks", []):
        for method in task.get("role_methods", []):
            if method.get("role") == "request":
                out.append({"task": str(task["type"]), "name": str(method["name"]), "rva": int(method["rva"]), "signature": str(method.get("signature") or "")})
    return out


def endpoint_map(path: Path | None) -> dict[str, list[dict[str, Any]]]:
    if path is None: return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ep in data.get("endpoints", []):
        route = str(ep.get("route") or "")
        if not route: continue
        if not route.startswith("/"): route = "/" + route
        for binding in ep.get("task_bindings", []):
            task = str(binding.get("task") or "")
            if task:
                out[task].append({"route": route, "enum": ep.get("enum"), "status": ep.get("status"), "binding_evidence": binding.get("evidence")})
    for task in out: out[task].sort(key=lambda x: (x["route"], str(x.get("enum"))))
    return dict(out)


def load_layouts(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("types", [])
    by_full = {row["type"]: row for row in rows}
    by_can: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        by_can[canon(row["type"])].append(row["type"])
        by_can[canon(row["type"].rsplit(".", 1)[-1])].append(row["type"])

    def resolve_base(owner: str, base: str) -> str | None:
        hits = []
        keys = [canon(base)]
        if "." in owner: keys.append(canon(owner.rsplit(".", 1)[0] + "." + base))
        for key in keys: hits.extend(by_can.get(key, []))
        hits = list(dict.fromkeys(hits))
        return hits[0] if len(hits) == 1 else None

    cache: dict[str, dict[int, list[dict[str, Any]]]] = {}
    def effective(name: str, seen=None):
        if name in cache: return cache[name]
        seen = set() if seen is None else set(seen)
        if name in seen: return {}
        seen.add(name)
        out: dict[int, list[dict[str, Any]]] = defaultdict(list)
        row = by_full[name]
        for base in row.get("bases", []):
            resolved = resolve_base(name, str(base))
            if resolved:
                for offset, fields in effective(resolved, seen).items(): out[offset].extend(fields)
        for field in row.get("instance_fields", []):
            if "offset" in field:
                out[int(field["offset"])].append({"declaring_type": name, "name": field["name"], "managed_type": field["managed_type"]})
        cache[name] = dict(out)
        return cache[name]
    for name in by_full: effective(name)
    return data, by_full, by_can, cache


def width_for_reg(md: Cs, reg_id: int) -> int | None:
    name = md.reg_name(reg_id).lower()
    if name.startswith("x"): return 8
    if name.startswith("w"): return 4
    return None


def field_compatible(field: dict[str, Any], width: int | None, mnemonic: str) -> bool:
    if width is None: return True
    typ, mn = str(field.get("managed_type", "")).lower(), mnemonic.lower()
    if mn.startswith(("strb", "sturb")): return any(x in typ for x in ("bool", "byte", "sbyte", "int8"))
    if mn.startswith(("strh", "sturh")): return any(x in typ for x in ("int16", "uint16", "char"))
    if width == 8:
        return any(x in typ for x in ("int64", "uint64", "double", "*", "string", "[]", "list<", "dictionary<", "_o")) or not any(x in typ for x in ("int32", "uint32", "bool", "single", "float"))
    if width == 4:
        return any(x in typ for x in ("int32", "uint32", "bool", "single", "float", "enum")) or not any(x in typ for x in ("int64", "uint64", "double", "string", "[]", "list<", "dictionary<"))
    return True


def analyze_method(view: BinaryView, starts: list[int], names: dict[int, str], method: dict[str, Any]) -> dict[str, Any]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN); md.detail = True
    start = method["rva"]
    insns = list(md.disasm(view.read(start, function_end(starts, start) - start), start))
    args = parse_args(method["signature"])
    reg_obj: dict[str, str] = {}
    reg_prov: dict[str, set[str]] = defaultdict(set)
    stack_obj: dict[int, str | None] = {}
    stack_prov: dict[int, set[str]] = {}
    for arg in args:
        if arg.reg:
            reg_prov[arg.reg] = {f"arg:{arg.name}"}
            if arg.index == 0: reg_obj[arg.reg] = "this"
            elif arg.is_pointer: reg_obj[arg.reg] = f"argobj:{arg.name}"
    stores: dict[str, list[dict[str, Any]]] = defaultdict(list)
    assignments, ctor_hints, params_reads, calls = [], defaultdict(list), set(), []

    def setreg(dst: str, prov=None, obj=None) -> None:
        dst = norm_reg(dst); reg_prov[dst] = set(prov or []); reg_obj.pop(dst, None)
        if obj is not None: reg_obj[dst] = obj

    def record_store(ins, src_op, mem, extra=0) -> None:
        if src_op.type != ARM64_OP_REG: return
        src = norm_reg(md.reg_name(src_op.reg)); base = norm_reg(md.reg_name(mem.base)); offset = int(mem.disp) + extra
        base_obj, src_obj = reg_obj.get(base), reg_obj.get(src)
        provenance = sorted(reg_prov.get(src, set()))
        if base_obj:
            item = {"site": int(ins.address), "offset": offset, "mnemonic": ins.mnemonic, "value_reg": src,
                    "value_width": width_for_reg(md, src_op.reg), "value_provenance": provenance, "value_object": src_obj}
            stores[base_obj].append(item)
            if base_obj == "this" and offset == PARAMS_OFFSET and src_obj:
                assignments.append({"site": int(ins.address), "payload_object": src_obj, "source_reg": src, "value_provenance": provenance})

    for ins in insns:
        ops, mnemonic = ins.operands, ins.mnemonic.lower()
        if mnemonic.startswith(("str", "stur")) and len(ops) >= 2 and ops[-1].type == ARM64_OP_MEM:
            record_store(ins, ops[0], ops[-1].mem)
            mem, base = ops[-1].mem, norm_reg(md.reg_name(ops[-1].mem.base))
            if base == "sp" and ops[0].type == ARM64_OP_REG:
                src = norm_reg(md.reg_name(ops[0].reg)); stack_prov[int(mem.disp)] = set(reg_prov.get(src, set())); stack_obj[int(mem.disp)] = reg_obj.get(src)
        elif mnemonic.startswith("stp") and len(ops) >= 3 and ops[-1].type == ARM64_OP_MEM:
            mem = ops[-1].mem; width = width_for_reg(md, ops[0].reg) or 8
            record_store(ins, ops[0], mem, 0); record_store(ins, ops[1], mem, width)
            if norm_reg(md.reg_name(mem.base)) == "sp":
                for op, offset in ((ops[0], int(mem.disp)), (ops[1], int(mem.disp) + width)):
                    if op.type == ARM64_OP_REG:
                        src = norm_reg(md.reg_name(op.reg)); stack_prov[offset] = set(reg_prov.get(src, set())); stack_obj[offset] = reg_obj.get(src)

        if ins.id == ARM64_INS_BL and ops and ops[0].type == ARM64_OP_IMM:
            target = int(ops[0].imm); name = names.get(target); x0_obj = reg_obj.get("x0")
            calls.append({"site": int(ins.address), "target_rva": target, "target_name": name, "x0_object": x0_obj})
            if name and "$$.ctor" in name and x0_obj: ctor_hints[x0_obj].append(name.split("$$.ctor", 1)[0])
            for i in range(19): reg_obj.pop(f"x{i}", None); reg_prov.pop(f"x{i}", None)
            setreg("x0", {f"call:{name or hex(target)}"}, f"ret@{int(ins.address):x}")
            continue

        if mnemonic == "mov" and len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
            dst = norm_reg(md.reg_name(ops[0].reg))
            if ops[1].type == ARM64_OP_REG:
                src = norm_reg(md.reg_name(ops[1].reg)); setreg(dst, reg_prov.get(src, set()), reg_obj.get(src))
            elif ops[1].type == ARM64_OP_IMM: setreg(dst, {f"const:{int(ops[1].imm)}"})
            continue
        if mnemonic in ("movz", "movn") and len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
            setreg(md.reg_name(ops[0].reg), {f"const:{int(ops[1].imm)}"} if ops[1].type == ARM64_OP_IMM else {"const"}); continue
        if mnemonic == "movk" and ops and ops[0].type == ARM64_OP_REG:
            dst = norm_reg(md.reg_name(ops[0].reg)); reg_prov[dst].add("const-part"); reg_obj.pop(dst, None); continue

        if mnemonic.startswith(("ldr", "ldur")) and len(ops) >= 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_MEM:
            dst, mem = norm_reg(md.reg_name(ops[0].reg)), ops[1].mem
            base, offset = norm_reg(md.reg_name(mem.base)), int(mem.disp)
            if base == "sp" and offset in stack_prov: setreg(dst, stack_prov[offset], stack_obj.get(offset))
            elif base in reg_obj:
                base_obj = reg_obj[base]; setreg(dst, {f"load:{base_obj}+0x{offset:x}"}, f"field:{base_obj}+0x{offset:x}")
                if base_obj == "this" and offset == PARAMS_OFFSET: params_reads.add(reg_obj[dst])
            else: setreg(dst, {"memory-load"})
            continue
        if mnemonic.startswith("ldp") and len(ops) >= 3 and ops[-1].type == ARM64_OP_MEM:
            mem, width = ops[-1].mem, width_for_reg(md, ops[0].reg) or 8
            if norm_reg(md.reg_name(mem.base)) == "sp":
                for op, offset in ((ops[0], int(mem.disp)), (ops[1], int(mem.disp) + width)):
                    if op.type == ARM64_OP_REG and offset in stack_prov: setreg(md.reg_name(op.reg), stack_prov[offset], stack_obj.get(offset))
            continue
        if mnemonic in ("add", "sub", "and", "orr", "eor", "lsl", "lsr", "asr") and ops and ops[0].type == ARM64_OP_REG:
            dst, provenance, obj = norm_reg(md.reg_name(ops[0].reg)), set(), None
            for op in ops[1:]:
                if op.type == ARM64_OP_REG: provenance |= reg_prov.get(norm_reg(md.reg_name(op.reg)), set())
            if mnemonic == "add" and len(ops) >= 3 and ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM and int(ops[2].imm) == 0:
                obj = reg_obj.get(norm_reg(md.reg_name(ops[1].reg)))
            if provenance: provenance.add("derived")
            setreg(dst, provenance or {"derived"}, obj); continue

        try: reads, writes = ins.regs_access()
        except Exception: reads, writes = [], []
        provenance = set()
        for reg in reads: provenance |= reg_prov.get(norm_reg(md.reg_name(reg)), set())
        for reg in writes:
            name = norm_reg(md.reg_name(reg))
            if name.startswith("x") and name[1:].isdigit(): setreg(name, (provenance | {"derived"}) if provenance else set())

    payloads, seen = [], set()
    for assignment in assignments:
        obj = assignment["payload_object"]
        if obj not in seen: payloads.append(obj); seen.add(obj)
    for obj in sorted(params_reads):
        if obj not in seen: payloads.append(obj); seen.add(obj)
    return {"args": [arg.__dict__ for arg in args], "instruction_count": len(insns), "params_assignments": assignments,
            "payload_objects": payloads, "stores_by_object": dict(stores), "ctor_hints": dict(ctor_hints), "calls": calls}


def type_from_ctype(ctype: str, by_can: dict[str, list[str]]) -> list[str]:
    hits = []
    for candidate in ctype_managed_candidates(ctype): hits.extend(by_can.get(canon(candidate), []))
    return list(dict.fromkeys(hits))


def resolve_payload(task: str, payload_obj: str, analysis: dict[str, Any], by_full, by_can, effective):
    stores = [x for x in analysis["stores_by_object"].get(payload_obj, []) if int(x["offset"]) >= 0x10]
    offsets = sorted({int(x["offset"]) for x in stores})
    exact, evidence = [], []
    if payload_obj.startswith("argobj:"):
        arg_name = payload_obj.split(":", 1)[1]
        for arg in analysis["args"]:
            if arg["name"] == arg_name:
                exact = type_from_ctype(arg["c_type"], by_can); evidence.append("request-signature-object-type"); break
    hints = analysis["ctor_hints"].get(payload_obj, [])
    specific = []
    for hint in hints:
        if hint.rsplit(".", 1)[-1].lower() in {"baseparam", "postparams"}: continue
        specific.extend(by_can.get(canon(hint), []))
    specific = list(dict.fromkeys(specific))
    if len(specific) == 1: exact = specific; evidence.append("specific-constructor")

    def matches(name: str) -> bool:
        fields = effective.get(name, {})
        for store in stores:
            candidates = fields.get(int(store["offset"]), [])
            if not candidates or not any(field_compatible(field, store.get("value_width"), str(store.get("mnemonic"))) for field in candidates): return False
        return True

    if exact: exact = [name for name in exact if name in by_full and matches(name)]
    candidates = exact or [name for name in by_full if matches(name)]
    if len(candidates) > 1 and offsets:
        task_name = task.rsplit(".", 1)[-1]; stem = task_name[:-4] if task_name.endswith("Task") else task_name
        named = [name for name in candidates if stem.lower() in name.rsplit(".", 1)[-1].lower() and "param" in name.rsplit(".", 1)[-1].lower()]
        if len(named) == 1: candidates = named; evidence.append("unique-task-name-layout-match")
    status, confidence, resolved = "unresolved", "low", None
    if len(candidates) == 1:
        resolved = candidates[0]; status = "exact" if exact or "specific-constructor" in evidence else "unique-layout"; confidence = "high" if status == "exact" else "medium"
    elif candidates: status = "ambiguous-layout"
    return ({"payload_object": payload_obj, "stores": stores, "observed_offsets": offsets, "constructor_hints": hints,
             "resolution": status, "confidence": confidence, "resolved_type": resolved, "candidate_type_count": len(candidates),
             "candidate_types": candidates[:MAX_CANDIDATES], "candidate_types_truncated": len(candidates) > MAX_CANDIDATES,
             "resolution_evidence": evidence}, candidates)


def field_for_store(store: dict[str, Any], candidates: list[str], effective) -> dict[str, Any]:
    rows = []
    for payload_type in candidates:
        for field in effective.get(payload_type, {}).get(int(store["offset"]), []):
            if field_compatible(field, store.get("value_width"), str(store.get("mnemonic"))): rows.append({"payload_type": payload_type, **field})
    pairs = {(row["name"], row["managed_type"]) for row in rows}
    out = {"field_candidates": rows[:MAX_CANDIDATES], "field_candidates_truncated": len(rows) > MAX_CANDIDATES}
    if len(pairs) == 1:
        name, typ = next(iter(pairs)); out.update({"field_name": name, "managed_type": typ, "field_resolution": "consensus-exact" if len(candidates) > 1 else "exact-layout"})
    else: out["field_resolution"] = "ambiguous" if rows else "unresolved"
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True); parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True); parser.add_argument("--layouts", type=Path, required=True)
    parser.add_argument("--endpoint-contracts", type=Path); parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path); args = parser.parse_args()
    inventory = json.loads(args.inventory.read_text(encoding="utf-8")); methods = request_methods(inventory)
    starts, names = load_script(args.script_json); endpoints = endpoint_map(args.endpoint_contracts)
    layout, by_full, by_can, effective = load_layouts(args.layouts)
    view = BinaryView(args.lib); results, contracts = [], []
    try:
        for method in methods:
            analysis = analyze_method(view, starts, names, method); payload_rows = []
            for payload_obj in analysis["payload_objects"]:
                payload, candidates = resolve_payload(method["task"], payload_obj, analysis, by_full, by_can, effective); field_writes = []
                for store in payload["stores"]:
                    row = {**store, **field_for_store(store, candidates, effective)}; field_writes.append(row)
                    if row.get("field_name"):
                        contracts.append({"task": method["task"], "method": method["name"], "method_rva": method["rva"],
                                          "endpoint_candidates": endpoints.get(method["task"], []), "payload_type": payload.get("resolved_type"),
                                          "payload_resolution": payload["resolution"], "field": row["field_name"], "managed_type": row.get("managed_type"),
                                          "field_offset": row["offset"], "value_provenance": row.get("value_provenance", []), "store_rva": row["site"],
                                          "confidence": "high" if payload["resolution"] == "exact" else "medium" if row["field_resolution"] == "consensus-exact" else "low"})
                payload["field_writes"] = field_writes; payload_rows.append(payload)
            results.append({"task": method["task"], "method": method["name"], "method_rva": method["rva"], "signature": method["signature"],
                            "endpoint_candidates": endpoints.get(method["task"], []), "instruction_count": analysis["instruction_count"],
                            "params_assignments": analysis["params_assignments"], "payloads": payload_rows})
    finally: view.close()
    payload_counts = Counter(payload["resolution"] for result in results for payload in result["payloads"])
    report = {"schema": SCHEMA, "scope": "C4 exact NetworkTask.Params object tracking plus C2 layout resolution; ambiguity preserved",
              "request_method_count": len(methods), "method_with_param_assignment_count": sum(bool(row["params_assignments"]) for row in results),
              "method_with_payload_count": sum(bool(row["payloads"]) for row in results), "payload_count": sum(len(row["payloads"]) for row in results),
              "payload_resolution_counts": dict(sorted(payload_counts.items())), "field_write_contract_count": len(contracts),
              "resolved_unique_field_count": len({row["field"] for row in contracts}), "contracts": contracts, "methods": results,
              "source_layout_schema": layout.get("schema")}
    args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.markdown_output:
        lines = ["# C4 request field writes", "", "Exact `NetworkTask.Params` object tracking with C2 managed-layout resolution. Ambiguity is retained rather than guessed.", "",
                 f"- request methods: **{report['request_method_count']}**", f"- methods assigning Params: **{report['method_with_param_assignment_count']}**",
                 f"- methods with payload object evidence: **{report['method_with_payload_count']}**", f"- payload objects: **{report['payload_count']}**",
                 f"- resolved field-write contracts: **{report['field_write_contract_count']}**", f"- unique resolved fields: **{report['resolved_unique_field_count']}**", "", "## Payload resolution", ""]
        lines += [f"- `{key}`: **{value}**" for key, value in sorted(report["payload_resolution_counts"].items())]
        lines += ["", "A field is named only from an exact payload layout or unanimous surviving layout candidates; task-name matching is recorded explicitly as heuristic evidence.", ""]
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True); args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("request_method_count", "method_with_param_assignment_count", "method_with_payload_count", "payload_count", "payload_resolution_counts", "field_write_contract_count", "resolved_unique_field_count")}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
