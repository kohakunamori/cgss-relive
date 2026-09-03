#!/usr/bin/env python3
"""Prove the final-client NetworkTask API-key field and recover task key writes.

This pass closes the gap between a high-correlation constructor pattern and an
actual field-level proof. It combines three independent surfaces from the exact
11.6.3 specimen:

* managed field layout from Il2CppDumper ``dump.cs``;
* native reads/writes of the candidate field in ``Cute.NetworkTask`` methods;
* small-integer writes to the same offset across NetworkTask descendants.

The output is sanitized derived metadata only. No decompiler bodies or arbitrary
strings are emitted.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import (
    ARM64_INS_ADD,
    ARM64_INS_BL,
    ARM64_INS_BLR,
    ARM64_INS_LDR,
    ARM64_INS_LDUR,
    ARM64_INS_MOV,
    ARM64_INS_MOVK,
    ARM64_INS_MOVN,
    ARM64_INS_MOVZ,
    ARM64_INS_RET,
    ARM64_INS_STR,
    ARM64_INS_STUR,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
)
from elftools.elf.elffile import ELFFile

SCHEMA = 1
API_FIELD_OFFSET = 0x50
MAX_KEY = 515
MAX_FUNCTION_SIZE = 0x10000
MAX_TYPE_BLOCK_LINES = 4096
MAX_METHODS_PER_TASK = 160
MAX_CALLS_PER_METHOD = 128

_TYPE_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)?\s*"
    r"(?:(?:sealed|abstract|static|partial|readonly)\s+)*"
    r"(?:class|struct)\s+([^\s:{]+)"
)
_NAMESPACE_RE = re.compile(r"^\s*//\s*Namespace:\s*(.*)\s*$")
_FIELD_OFFSET_RE = re.compile(r"//\s*0x([0-9A-Fa-f]+)\s*$")
_SUFFIXES = ("NetworkTask", "Task", "Api", "Request", "Response")


@dataclass(frozen=True)
class Method:
    address: int
    name: str

    @property
    def owner(self) -> str:
        return self.name.split("$$", 1)[0] if "$$" in self.name else ""

    @property
    def member(self) -> str:
        return self.name.split("$$", 1)[1] if "$$" in self.name else self.name


@dataclass
class TypeBlock:
    full_name: str
    name: str
    namespace: str
    base: str | None
    line: int
    fields: list[dict[str, Any]]


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.segments: list[tuple[int, int, int, int]] = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            self.segments.append(
                (
                    int(segment["p_vaddr"]),
                    int(segment["p_memsz"]),
                    int(segment["p_offset"]),
                    int(segment["p_filesz"]),
                )
            )

    def close(self) -> None:
        self.stream.close()

    def read(self, address: int, size: int) -> bytes:
        for vaddr, memsz, offset, filesz in self.segments:
            if vaddr <= address < vaddr + memsz:
                rel = address - vaddr
                if rel >= filesz:
                    return b""
                count = min(size, filesz - rel)
                self.stream.seek(offset + rel)
                return self.stream.read(count)
        return b""


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def normalize(value: str) -> str:
    value = value.rsplit(".", 1)[-1]
    changed = True
    while changed:
        changed = False
        for suffix in _SUFFIXES:
            if value.endswith(suffix):
                value = value[: -len(suffix)]
                changed = True
                break
    return re.sub(r"[^a-z0-9]", "", value.lower())


def parse_type_header(line: str, namespace: str) -> tuple[str, str | None] | None:
    match = _TYPE_RE.match(line)
    if not match:
        return None
    name = match.group(1)
    tail = line[match.end():]
    base = None
    if ":" in tail:
        raw = tail.split(":", 1)[1].split("//", 1)[0].split("{", 1)[0].strip()
        if raw:
            base = raw.split(",", 1)[0].strip()
    full = f"{namespace}.{name}" if namespace else name
    return full, base


def parse_field(line: str) -> dict[str, Any] | None:
    off = _FIELD_OFFSET_RE.search(line)
    if not off or ";" not in line:
        return None
    offset = int(off.group(1), 16)
    decl = line[: off.start()].strip()
    decl = decl[:-1].strip() if decl.endswith(";") else decl
    if not decl or "(" in decl or ")" in decl:
        return None
    decl = decl.split("=", 1)[0].strip()
    tokens = decl.split()
    if len(tokens) < 2:
        return None
    name = tokens[-1]
    modifiers = {
        "public", "private", "protected", "internal", "static", "readonly",
        "volatile", "const", "new", "unsafe",
    }
    type_tokens = [tok for tok in tokens[:-1] if tok not in modifiers]
    field_type = " ".join(type_tokens) if type_tokens else None
    return {
        "offset": offset,
        "name": name,
        "type": field_type,
        "declaration": decl[:240],
    }


def parse_types(path: Path) -> dict[str, TypeBlock]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    namespace = ""
    result: dict[str, TypeBlock] = {}
    i = 0
    while i < len(lines):
        ns = _NAMESPACE_RE.match(lines[i])
        if ns:
            namespace = ns.group(1).strip()
            i += 1
            continue
        header = parse_type_header(lines[i], namespace)
        if not header:
            i += 1
            continue
        full, base = header
        name = full.rsplit(".", 1)[-1]
        fields: list[dict[str, Any]] = []
        cursor = i + 1
        depth = 0
        opened = False
        for _ in range(MAX_TYPE_BLOCK_LINES):
            if cursor >= len(lines):
                break
            line = lines[cursor]
            depth += line.count("{")
            if "{" in line:
                opened = True
            field = parse_field(line)
            if field is not None:
                fields.append(field)
            depth -= line.count("}")
            if opened and depth <= 0 and line.strip() == "}":
                break
            cursor += 1
        result[full] = TypeBlock(
            full_name=full,
            name=name,
            namespace=namespace,
            base=base,
            line=i + 1,
            fields=fields,
        )
        i = max(i + 1, cursor + 1)
    return result


def load_methods(path: Path) -> tuple[list[Method], list[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    methods: list[Method] = []
    starts: set[int] = set()
    for item in raw.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        method = Method(address=address, name=str(item.get("Name", "")))
        methods.append(method)
        starts.add(address)
    for item in raw.get("Addresses", []):
        address = as_int(item)
        if address > 0:
            starts.add(address)
    return methods, sorted(starts)


def methods_by_owner(methods: list[Method]) -> dict[str, list[Method]]:
    result: dict[str, list[Method]] = defaultdict(list)
    for method in methods:
        if method.owner:
            result[method.owner].append(method)
    for values in result.values():
        values.sort(key=lambda item: item.address)
    return result


def function_end(starts: list[int], address: int) -> int:
    idx = bisect.bisect_right(starts, address)
    end = starts[idx] if idx < len(starts) else address + MAX_FUNCTION_SIZE
    return min(end, address + MAX_FUNCTION_SIZE)


def canon_reg(name: str) -> str:
    name = name.lower()
    if len(name) >= 2 and name[0] in {"w", "x"} and name[1:].isdigit():
        return "x" + name[1:]
    return name


def reg_name(md: Cs, operand: Any) -> str:
    return canon_reg(md.reg_name(int(operand.reg)))


def small_key(value: int | None) -> int | None:
    return value if value is not None and 0 <= value <= MAX_KEY else None


def scan_method(
    view: BinaryView,
    starts: list[int],
    method: Method,
    method_name_by_address: dict[int, str],
) -> dict[str, Any]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    end = function_end(starts, method.address)
    insns = list(md.disasm(view.read(method.address, end - method.address), method.address))

    constants: dict[str, int] = {}
    this_aliases: set[str] = {"x0"}
    accesses: list[dict[str, Any]] = []
    calls: list[dict[str, Any]] = []

    def invalidate(reg: str) -> None:
        constants.pop(reg, None)
        if reg != "x0":
            this_aliases.discard(reg)

    for ins in insns:
        ops = ins.operands
        mnem = ins.mnemonic.lower()
        if ins.id == ARM64_INS_RET:
            break

        if ins.id == ARM64_INS_MOV and len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
            dst = reg_name(md, ops[0])
            if ops[1].type == ARM64_OP_IMM:
                constants[dst] = int(ops[1].imm) & 0xFFFFFFFFFFFFFFFF
                this_aliases.discard(dst)
                continue
            if ops[1].type == ARM64_OP_REG:
                src = reg_name(md, ops[1])
                if src in constants:
                    constants[dst] = constants[src]
                else:
                    constants.pop(dst, None)
                if src in this_aliases:
                    this_aliases.add(dst)
                else:
                    this_aliases.discard(dst)
                continue
            invalidate(dst)
            continue

        if ins.id in {ARM64_INS_MOVZ, ARM64_INS_MOVN, ARM64_INS_MOVK} and len(ops) >= 2:
            if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
                dst = reg_name(md, ops[0])
                imm = int(ops[1].imm)
                shift_obj = getattr(ops[1], "shift", None)
                shift = int(shift_obj.value) if shift_obj is not None else 0
                if ins.id == ARM64_INS_MOVZ:
                    constants[dst] = imm << shift
                elif ins.id == ARM64_INS_MOVN:
                    constants[dst] = (~(imm << shift)) & 0xFFFFFFFFFFFFFFFF
                else:
                    old = constants.get(dst, 0)
                    mask = ~(0xFFFF << shift) & 0xFFFFFFFFFFFFFFFF
                    constants[dst] = (old & mask) | ((imm & 0xFFFF) << shift)
                this_aliases.discard(dst)
            continue

        if ins.id == ARM64_INS_ADD and len(ops) >= 3 and ops[0].type == ARM64_OP_REG:
            dst = reg_name(md, ops[0])
            if ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
                src = reg_name(md, ops[1])
                imm = int(ops[2].imm)
                if src in constants:
                    constants[dst] = constants[src] + imm
                else:
                    constants.pop(dst, None)
                if src in this_aliases and imm == 0:
                    this_aliases.add(dst)
                else:
                    this_aliases.discard(dst)
                continue
            invalidate(dst)
            continue

        if ins.id in {ARM64_INS_LDR, ARM64_INS_LDUR, ARM64_INS_STR, ARM64_INS_STUR} and len(ops) >= 2:
            if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_MEM:
                base = canon_reg(md.reg_name(int(ops[1].mem.base)))
                disp = int(ops[1].mem.disp)
                if base in this_aliases and disp == API_FIELD_OFFSET:
                    reg = reg_name(md, ops[0])
                    item = {
                        "kind": "read" if ins.id in {ARM64_INS_LDR, ARM64_INS_LDUR} else "write",
                        "rva": int(ins.address),
                        "register": reg,
                    }
                    if item["kind"] == "write":
                        value = small_key(constants.get(reg))
                        if value is not None:
                            item["constant"] = value
                    accesses.append(item)
            if ins.id in {ARM64_INS_LDR, ARM64_INS_LDUR} and ops[0].type == ARM64_OP_REG:
                invalidate(reg_name(md, ops[0]))
            continue

        if ins.id == ARM64_INS_BL and ops and ops[0].type == ARM64_OP_IMM:
            target = int(ops[0].imm)
            args = {}
            for arg_index in range(1, 8):
                value = small_key(constants.get(f"x{arg_index}"))
                if value is not None:
                    args[f"x{arg_index}"] = value
            if len(calls) < MAX_CALLS_PER_METHOD:
                calls.append(
                    {
                        "rva": int(ins.address),
                        "target": target,
                        "target_name": method_name_by_address.get(target),
                        "small_args": args,
                    }
                )
            for idx in range(18):
                reg = f"x{idx}"
                constants.pop(reg, None)
                if idx != 0:
                    this_aliases.discard(reg)
            continue

        if ins.id == ARM64_INS_BLR:
            for idx in range(18):
                reg = f"x{idx}"
                constants.pop(reg, None)
                if idx != 0:
                    this_aliases.discard(reg)
            continue

        if ops and ops[0].type == ARM64_OP_REG and mnem not in {
            "cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz"
        } and not mnem.startswith("b."):
            invalidate(reg_name(md, ops[0]))

    return {
        "name": method.name,
        "member": method.member,
        "rva": method.address,
        "api_field_accesses": accesses,
        "calls": calls,
    }


def enum_a_entries(report: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = report.get("a_candidates", [])
    if len(candidates) != 1:
        raise RuntimeError("expected exactly one normal ApiType enum")
    return [
        {"name": str(name), "key": int(value), "group": "A"}
        for name, value in candidates[0]["entries"]
    ]


def find_type(types: dict[str, TypeBlock], full: str) -> TypeBlock | None:
    if full in types:
        return types[full]
    short = full.rsplit(".", 1)[-1]
    matches = [item for item in types.values() if item.name == short]
    return matches[0] if len(matches) == 1 else None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--api-type-enums", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    enum_report = json.loads(args.api_type_enums.read_text(encoding="utf-8"))
    task_rows = inventory.get("tasks", [])
    tasks = [str(item["type"]) for item in task_rows]
    if not tasks:
        raise RuntimeError("empty NetworkTask inventory")

    types = parse_types(args.dump_cs)
    network_task = find_type(types, "Cute.NetworkTask")
    if network_task is None:
        raise RuntimeError("Cute.NetworkTask not found in dump.cs")
    field_matches = [f for f in network_task.fields if f["offset"] == API_FIELD_OFFSET]

    methods, starts = load_methods(args.script_json)
    by_owner = methods_by_owner(methods)
    name_by_addr = {method.address: method.name for method in methods}

    enum_entries = enum_a_entries(enum_report)
    enum_by_norm: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in enum_entries:
        enum_by_norm[normalize(entry["name"])].append(entry)

    network_methods = by_owner.get("Cute.NetworkTask", [])
    view = BinaryView(args.lib)
    try:
        network_method_evidence = []
        for method in network_methods:
            rec = scan_method(view, starts, method, name_by_addr)
            if rec["api_field_accesses"]:
                rec["calls"] = [
                    c for c in rec["calls"]
                    if c["target_name"] and (
                        "NetworkTask" in c["target_name"]
                        or "ApiType" in c["target_name"]
                        or c["target_name"].endswith("$$.ctor")
                    )
                ]
                network_method_evidence.append(rec)

        records = []
        for task in tasks:
            owner_methods = by_owner.get(task, [])
            if len(owner_methods) > MAX_METHODS_PER_TASK:
                raise RuntimeError(f"too many methods for {task}: {len(owner_methods)}")
            evidence = []
            for method in owner_methods:
                rec = scan_method(view, starts, method, name_by_addr)
                if rec["api_field_accesses"]:
                    rec["calls"] = [
                        c for c in rec["calls"]
                        if c["target_name"] and (
                            c["target_name"].endswith("$$.ctor")
                            or "NetworkTask" in c["target_name"]
                            or "BaseTask" in c["target_name"]
                            or "Arcade" in c["target_name"]
                            or "ApiType" in c["target_name"]
                        )
                    ]
                    evidence.append(rec)

            anchors = enum_by_norm.get(normalize(task), [])
            anchor = anchors[0] if len(anchors) == 1 else None
            writes = []
            for rec in evidence:
                for access in rec["api_field_accesses"]:
                    if access["kind"] == "write" and "constant" in access:
                        writes.append(
                            {
                                "member": rec["member"],
                                "method_rva": rec["rva"],
                                "write_rva": access["rva"],
                                "value": int(access["constant"]),
                            }
                        )
            unique_values = sorted({item["value"] for item in writes})
            records.append(
                {
                    "task": task,
                    "anchor": anchor,
                    "constant_write_values": unique_values,
                    "field_touching_methods": evidence,
                }
            )
    finally:
        view.close()

    anchored_with_write = 0
    anchored_match_any = 0
    anchored_mismatch = []
    for rec in records:
        if rec["anchor"] is None or not rec["constant_write_values"]:
            continue
        anchored_with_write += 1
        expected = int(rec["anchor"]["key"])
        if expected in rec["constant_write_values"]:
            anchored_match_any += 1
        else:
            anchored_mismatch.append(
                {
                    "task": rec["task"],
                    "expected": expected,
                    "values": rec["constant_write_values"],
                }
            )

    typed_api_field = False
    if len(field_matches) == 1:
        text = ((field_matches[0].get("type") or "") + " " + field_matches[0]["name"]).lower()
        typed_api_field = "apitype" in text or ("type" in text and "api" in text)

    report = {
        "schema": SCHEMA,
        "api_field_offset": API_FIELD_OFFSET,
        "network_task": {
            "type": network_task.full_name,
            "base": network_task.base,
            "line": network_task.line,
            "field_at_offset": field_matches,
            "typed_api_field": typed_api_field,
            "field_access_methods": network_method_evidence,
        },
        "task_count": len(records),
        "anchor_count": sum(rec["anchor"] is not None for rec in records),
        "anchored_with_constant_write": anchored_with_write,
        "anchored_expected_value_seen": anchored_match_any,
        "anchored_expected_value_missing": len(anchored_mismatch),
        "anchored_mismatches": anchored_mismatch,
        "tasks": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    if len(field_matches) != 1:
        raise RuntimeError(f"expected one NetworkTask field at +0x50, got {len(field_matches)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
