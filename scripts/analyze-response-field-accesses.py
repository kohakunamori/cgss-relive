#!/usr/bin/env python3
"""Classify C3 response field accesses using exact literal xrefs and native helpers.

For every response-role field-key candidate from the sanitized C0 inventory this
pass resolves the exact managed string literal relocation, maps executable
ADRP+LDR references back into the bounded parser method, and follows the loaded
string register to a nearby LitJson/Stage.JsonHelper access call.

The output contains derived metadata only: field names, method RVAs, access-site
RVAs, helper names and inferred value classes. It deliberately does not export
native bytes or disassembly.

`direct-index` means JsonData.get_Item is executed if the site is reached. It is
NOT automatically labelled globally required because a surrounding branch may
make the site conditional. `try-get` and `defaulted` are stronger optionality
signals and are reported separately.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import (
    ARM64_INS_B, ARM64_INS_BL, ARM64_INS_BR, ARM64_INS_RET,
    ARM64_INS_MOV, ARM64_INS_ORR,
    ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG,
)
from elftools.elf.elffile import ELFFile

SCHEMA = 1
MAX_ADRP_WINDOW = 8
MAX_FLOW_INSTRUCTIONS = 32
MAX_POST_ACCESS_CALLS = 16
MAX_FUNCTION_SIZE = 0x20000
MAX_LITERAL_REFS = 100000


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: str | None = None


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.loads = []
        self.execs = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            row = (
                int(seg["p_vaddr"]), int(seg["p_memsz"]),
                int(seg["p_offset"]), int(seg["p_filesz"]),
            )
            self.loads.append(row)
            if int(seg["p_flags"]) & 1 and row[3]:
                self.execs.append((row[0], row[2], row[3]))

    def close(self) -> None:
        self.stream.close()

    def read(self, address: int, size: int) -> bytes:
        for vaddr, memsz, offset, filesz in self.loads:
            if vaddr <= address < vaddr + memsz:
                rel = address - vaddr
                if rel >= filesz:
                    return b""
                n = min(size, filesz - rel)
                self.stream.seek(offset + rel)
                return self.stream.read(n)
        return b""

    def reloc_by_addend(self, addresses: set[int]) -> list[dict[str, int | str]]:
        out = []
        for sec in self.elf.iter_sections():
            if not hasattr(sec, "iter_relocations"):
                continue
            for rel in sec.iter_relocations():
                if not rel.is_RELA():
                    continue
                addend = int(rel["r_addend"])
                if addend in addresses:
                    out.append({
                        "section": sec.name,
                        "slot": int(rel["r_offset"]),
                        "addend": addend,
                        "type": int(rel["r_info_type"]),
                    })
        return out

    def adrp_candidates(self, pages: set[int]) -> list[tuple[int, int]]:
        out = []
        for vaddr, offset, filesz in self.execs:
            self.stream.seek(offset)
            data = self.stream.read(filesz)
            limit = len(data) - len(data) % 4
            for pos in range(0, limit, 4):
                word = struct.unpack_from("<I", data, pos)[0]
                if word & 0x9F000000 != 0x90000000:
                    continue
                immlo = (word >> 29) & 3
                immhi = (word >> 5) & 0x7FFFF
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                pc = vaddr + pos
                page = (pc & ~0xFFF) + (imm << 12)
                if page in pages:
                    out.append((pc, page))
        return out


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def load_script(path: Path) -> tuple[dict[int, list[Method]], list[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    by_rva: dict[int, list[Method]] = defaultdict(list)
    starts = set()
    for item in raw.get("ScriptMethod", []):
        rva = as_int(item.get("Address", 0))
        if rva <= 0:
            continue
        signature = item.get("Signature")
        by_rva[rva].append(Method(rva, str(item.get("Name", "")), str(signature) if signature else None))
        starts.add(rva)
    for value in raw.get("Addresses", []):
        rva = as_int(value)
        if rva > 0:
            starts.add(rva)
    for rows in by_rva.values():
        rows.sort(key=lambda m: m.name)
    return dict(by_rva), sorted(starts)


def function_end(starts: list[int], rva: int) -> int:
    i = bisect.bisect_right(starts, rva)
    end = starts[i] if i < len(starts) else rva + MAX_FUNCTION_SIZE
    return min(end, rva + MAX_FUNCTION_SIZE)


def response_methods(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for task in inventory.get("tasks", []):
        for method in task.get("role_methods", []):
            if method.get("role") != "response":
                continue
            fields = sorted({
                str(x["value"]) for x in method.get("contract_literals", [])
                if x.get("kind") == "field_key"
            })
            rows.append({
                "task": str(task["type"]),
                "method": str(method["name"]),
                "rva": int(method["rva"]),
                "fields": fields,
            })
    return rows


def load_literal_addresses(path: Path, wanted: set[str]) -> tuple[dict[str, set[int]], dict[int, set[str]]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    items = raw.values() if isinstance(raw, dict) else raw
    by_value: dict[str, set[int]] = defaultdict(set)
    by_address: dict[int, set[str]] = defaultdict(set)
    for item in items:
        if not isinstance(item, dict):
            continue
        value = item.get("value", item.get("Value", item.get("string", item.get("String"))))
        address = item.get("address", item.get("Address"))
        if not isinstance(value, str) or value not in wanted or address is None:
            continue
        addr = as_int(address)
        by_value[value].add(addr)
        by_address[addr].add(value)
    return dict(by_value), dict(by_address)


def exact_slot_refs(view: BinaryView, slots: set[int]) -> list[dict[str, Any]]:
    if not slots:
        return []
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    pages = {slot & ~0xFFF for slot in slots}
    out = []
    slots_by_page: dict[int, set[int]] = defaultdict(set)
    for slot in slots:
        slots_by_page[slot & ~0xFFF].add(slot)

    for adrp_rva, page in view.adrp_candidates(pages):
        insns = list(md.disasm(view.read(adrp_rva, 4 * MAX_ADRP_WINDOW), adrp_rva))
        if not insns or len(insns[0].operands) < 1 or insns[0].operands[0].type != ARM64_OP_REG:
            continue
        base_reg = insns[0].operands[0].reg
        for ins in insns[1:]:
            if len(ins.operands) < 2 or ins.operands[1].type != ARM64_OP_MEM:
                continue
            mem = ins.operands[1].mem
            if mem.base != base_reg:
                continue
            slot = page + int(mem.disp)
            if slot not in slots_by_page[page]:
                continue
            if ins.operands[0].type != ARM64_OP_REG:
                continue
            out.append({
                "adrp_rva": adrp_rva,
                "load_rva": int(ins.address),
                "slot": slot,
                "dest_reg": md.reg_name(ins.operands[0].reg),
            })
            if len(out) > MAX_LITERAL_REFS:
                raise RuntimeError("unexpected response literal reference count")
            break
    return out


def norm_reg(name: str) -> str:
    name = name.lower()
    if len(name) >= 2 and name[0] == "w" and name[1:].isdigit():
        return "x" + name[1:]
    return name


def helper_kind(name: str | None, signature: str | None) -> tuple[str | None, str | None, str | None]:
    if not name:
        return None, None, None
    low = name.lower()
    if "jsonhelper$$trygetint" in low:
        return "try-get", "int", "optional-helper"
    if "jsonhelper$$trygetlong" in low:
        return "try-get", "long", "optional-helper"
    if "jsonhelper$$trygetbool" in low:
        return "try-get", "bool", "optional-helper"
    if "jsonhelper$$trygetvalue" in low:
        return "try-get", "json", "optional-helper"
    if "jsonhelper$$getintordefault" in low:
        return "defaulted", "int", "defaulted-helper"
    if "jsondata$$get_item" in low:
        return "direct-index", "json", "conditional-or-required"
    return None, None, None


def conversion_type(name: str | None, signature: str | None) -> str | None:
    if not name:
        return None
    low = name.lower()
    if "jsondata$$toint" in low:
        return "int"
    if "jsondata$$tolong" in low:
        return "long"
    if "jsondata$$toboolean" in low:
        return "bool"
    if "jsondata$$get_count" in low or "jsondata$$get_keys" in low:
        return "collection"
    if "jsondata$$get_isarray" in low:
        return "array"
    if "jsondata$$get_isobject" in low:
        return "object"
    if "jsondata$$op_explicit" in low and signature:
        sig = signature.lower()
        if "system_string" in sig or "string" in sig.split("(", 1)[0]:
            return "string"
        if sig.startswith("bool") or " boolean" in sig.split("(", 1)[0]:
            return "bool"
        if sig.startswith("int64") or sig.startswith("uint64"):
            return "long"
        if sig.startswith("int32") or sig.startswith("uint32"):
            return "int"
        return "explicit-cast"
    return None


def propagate_taint(ins: Any, md: Cs, tainted: set[str]) -> set[str]:
    out = set(tainted)

    # Register copies/aliases. Capstone commonly renders MOV aliases directly,
    # while some compiler forms use ORR xD, xzr, xS. The two-register case is
    # sufficient for literal-pointer propagation here.
    if ins.id in {ARM64_INS_MOV, ARM64_INS_ORR} and len(ins.operands) >= 2:
        if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_REG:
            dst = norm_reg(md.reg_name(ins.operands[0].reg))
            src = norm_reg(md.reg_name(ins.operands[1].reg))
            if src in out:
                out.add(dst)
            else:
                out.discard(dst)
            return out

    # IL2CPP managed string literals are typically two-level loads:
    #   ADRP/LDR xN, [GOT slot]   <- exact relocation reference found earlier
    #   LDR      x1, [xN]         <- managed String* used as helper key
    # Propagate taint through memory dereferences whose address base is tainted.
    mnemonic = ins.mnemonic.lower()
    if mnemonic.startswith(("ldr", "ldur")) and len(ins.operands) >= 2:
        if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_MEM:
            dst = norm_reg(md.reg_name(ins.operands[0].reg))
            base = norm_reg(md.reg_name(ins.operands[1].mem.base))
            if base in out:
                out.add(dst)
            else:
                out.discard(dst)
            return out

    # Preserve pointer taint across simple address arithmetic used for GOT/data
    # addressing. Do not propagate through arbitrary arithmetic.
    if mnemonic == "add" and len(ins.operands) >= 2:
        if ins.operands[0].type == ARM64_OP_REG and ins.operands[1].type == ARM64_OP_REG:
            dst = norm_reg(md.reg_name(ins.operands[0].reg))
            src = norm_reg(md.reg_name(ins.operands[1].reg))
            if src in out:
                out.add(dst)
            else:
                out.discard(dst)
            return out

    try:
        _reads, writes = ins.regs_access()
    except Exception:
        writes = []
    for reg_id in writes:
        reg = norm_reg(md.reg_name(reg_id))
        if reg:
            out.discard(reg)
    return out


def classify_ref(
    view: BinaryView,
    md: Cs,
    load_rva: int,
    end_rva: int,
    initial_reg: str,
    by_rva: dict[int, list[Method]],
) -> dict[str, Any] | None:
    size = min(end_rva - (load_rva + 4), 4 * MAX_FLOW_INSTRUCTIONS)
    if size <= 0:
        return None
    insns = list(md.disasm(view.read(load_rva + 4, size), load_rva + 4))
    tainted = {norm_reg(initial_reg)}
    branch_between = False
    calls_after_access: list[dict[str, Any]] = []
    access: dict[str, Any] | None = None

    for ins in insns:
        if ins.id == ARM64_INS_RET:
            break
        if ins.id in {ARM64_INS_B, ARM64_INS_BR}:
            branch_between = True
            if ins.id == ARM64_INS_BR or ins.mnemonic == "b":
                break
        if ins.id == ARM64_INS_BL and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            target = int(ins.operands[0].imm)
            methods = by_rva.get(target, [])
            candidates = methods or [Method(target, "", None)]
            if access is None:
                # Require the exact field-key taint to reach x1, the key argument
                # used by JsonData.get_Item/Stage.JsonHelper in this client.
                for method in candidates:
                    kind, value_type, optionality = helper_kind(method.name or None, method.signature)
                    if kind and "x1" in tainted:
                        access = {
                            "access_rva": int(ins.address),
                            "helper_rva": target,
                            "helper": method.name,
                            "helper_signature": method.signature,
                            "access_style": kind,
                            "value_type": value_type,
                            "optionality": optionality,
                            "branch_between_literal_and_access": branch_between,
                        }
                        break
            else:
                for method in candidates:
                    calls_after_access.append({
                        "rva": int(ins.address),
                        "target_rva": target,
                        "name": method.name or None,
                        "signature": method.signature,
                    })
                    inferred = conversion_type(method.name or None, method.signature)
                    if inferred and access["value_type"] in {"json", "explicit-cast"}:
                        access["value_type"] = inferred
                        access["conversion_helper"] = method.name
                        access["conversion_rva"] = int(ins.address)
                        return access
                    if len(calls_after_access) >= MAX_POST_ACCESS_CALLS:
                        return access
            if access is None:
                tainted = {r for r in tainted if not (r.startswith("x") and r[1:].isdigit() and int(r[1:]) <= 17)}
            else:
                tainted = {"x0"}
            continue
        tainted = propagate_taint(ins, md, tainted)
    return access


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--lib", type=Path, required=True)
    p.add_argument("--script-json", type=Path, required=True)
    p.add_argument("--stringliteral-json", type=Path, required=True)
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--markdown-output", type=Path)
    args = p.parse_args()

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    methods = response_methods(inventory)
    wanted = {field for method in methods for field in method["fields"]}
    literal_by_value, values_by_address = load_literal_addresses(args.stringliteral_json, wanted)
    missing_literals = sorted(wanted - set(literal_by_value))
    by_rva, starts = load_script(args.script_json)

    method_bounds = []
    for method in methods:
        method_bounds.append((method["rva"], function_end(starts, method["rva"]), method))
    method_bounds.sort(key=lambda x: x[0])
    method_starts = [x[0] for x in method_bounds]

    view = BinaryView(args.lib)
    try:
        rels = view.reloc_by_addend(set(values_by_address))
        slot_to_address = {int(r["slot"]): int(r["addend"]) for r in rels}
        refs = exact_slot_refs(view, set(slot_to_address))
        md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        md.detail = True
        accesses = []
        mapped_literal_refs = 0
        unclassified_refs = []
        for ref in refs:
            i = bisect.bisect_right(method_starts, ref["load_rva"]) - 1
            if i < 0:
                continue
            start, end, method = method_bounds[i]
            if not (start <= ref["load_rva"] < end):
                continue
            address = slot_to_address[ref["slot"]]
            values = values_by_address.get(address, set())
            fields = values & set(method["fields"])
            if not fields:
                continue
            mapped_literal_refs += 1
            result = classify_ref(view, md, ref["load_rva"], end, ref["dest_reg"], by_rva)
            for field in sorted(fields):
                base = {
                    "task": method["task"],
                    "method": method["method"],
                    "method_rva": start,
                    "field": field,
                    "literal_load_rva": ref["load_rva"],
                }
                if result:
                    accesses.append({**base, **result})
                else:
                    unclassified_refs.append(base)
    finally:
        view.close()

    unique = {}
    for row in accesses:
        key = (row["method_rva"], row["field"], row["literal_load_rva"], row["access_rva"])
        unique[key] = row
    accesses = sorted(unique.values(), key=lambda r: (r["task"], r["method_rva"], r["literal_load_rva"], r["field"]))

    style_counts = Counter(r["access_style"] for r in accesses)
    type_counts = Counter(r["value_type"] for r in accesses)
    optionality_counts = Counter(r["optionality"] for r in accesses)
    classified_fields = {r["field"] for r in accesses}
    classified_methods = {(r["task"], r["method_rva"]) for r in accesses}

    by_field: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in accesses:
        by_field[row["field"]].append({
            k: row[k] for k in (
                "task", "method", "method_rva", "literal_load_rva", "access_rva",
                "helper", "access_style", "value_type", "optionality",
                "branch_between_literal_and_access",
            )
        })

    report = {
        "schema": SCHEMA,
        "scope": "C3 exact field-literal-to-parser-helper associations; direct-index sites remain conditional-or-required until CFG guard analysis",
        "response_method_count": len(methods),
        "field_candidate_count": len(wanted),
        "field_candidates_missing_stringliteral": missing_literals,
        "literal_relocation_count": len(rels),
        "exact_literal_reference_count": len(refs),
        "response_method_literal_reference_count": mapped_literal_refs,
        "classified_access_count": len(accesses),
        "classified_unique_field_count": len(classified_fields),
        "classified_method_count": len(classified_methods),
        "access_style_counts": dict(sorted(style_counts.items())),
        "value_type_counts": dict(sorted(type_counts.items())),
        "optionality_counts": dict(sorted(optionality_counts.items())),
        "unclassified_response_literal_reference_count": len(unclassified_refs),
        "accesses": accesses,
        "by_field": dict(sorted(by_field.items())),
        "unclassified_refs": unclassified_refs[:5000],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = [
            "# C3 response field access classification", "",
            "Exact string-literal xrefs are associated only when the loaded key register reaches a recognized parser helper.", "",
            f"- response methods: **{len(methods)}**",
            f"- unique field candidates: **{len(wanted)}**",
            f"- mapped response literal refs: **{mapped_literal_refs}**",
            f"- classified access sites: **{len(accesses)}**",
            f"- classified unique fields: **{len(classified_fields)}**",
            f"- classified methods: **{len(classified_methods)}**",
            f"- access styles: `{dict(style_counts)}`",
            f"- inferred value types: `{dict(type_counts)}`",
            f"- optionality evidence: `{dict(optionality_counts)}`", "",
            "`direct-index` is an unconditional lookup only *if its basic block is reached*; CFG guard analysis is still required before calling that field globally required.", "",
        ]
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
