#!/usr/bin/env python3
"""Build a sanitized server-facing contract inventory from the final CGSS IL2CPP client.

This pass is intentionally broad but bounded.  It does not attempt to decompile the
whole client.  Instead it identifies NetworkTask descendants, classifies methods that
construct requests or parse responses, and records only contract-like managed string
literals referenced by those methods.

Inputs are ephemeral Il2CppDumper products plus the exact arm64 libil2cpp.so.  Output
contains derived metadata only: type/method names, RVAs, inheritance, endpoint-like
paths and identifier-like field/header strings.  Arbitrary localized strings and
binary/decompiler bodies are never emitted.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import (
    ARM64_INS_ADD,
    ARM64_INS_ADR,
    ARM64_INS_ADRP,
    ARM64_INS_B,
    ARM64_INS_BL,
    ARM64_INS_BLR,
    ARM64_INS_BR,
    ARM64_INS_LDR,
    ARM64_INS_RET,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
)
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

SCHEMA = 1
MAX_FUNCTION_SIZE = 0x10000
MAX_METHOD_LITERALS = 96
MAX_TASK_METHODS = 128
MAX_TASK_TYPES = 2048
LITERAL_LOOKAHEAD = 24

_TYPE_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)?\s*"
    r"(?:(?:sealed|abstract|static|partial|readonly)\s+)*"
    r"(?:class|struct)\s+([^\s:{]+)"
)
_NAMESPACE_RE = re.compile(r"^\s*//\s*Namespace:\s*(.*)\s*$")

_API_PATH_RE = re.compile(r"^[a-z0-9_]+(?:/[a-z0-9_]+)+$")
_FIELD_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,79}$")
_HEADER_RE = re.compile(r"^[A-Z][A-Z0-9-]{1,63}$")
_IDENTIFIER_PATH_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")

REQUEST_ROLE_HINTS = (
    "SetParameter",
    "PreparePostData",
    "PrepareHeaders",
    "CreateBody",
    "GetPost",
    "Request",
)
RESPONSE_ROLE_HINTS = (
    "Parse",
    "SetResponseData",
    "CheckResult",
    "Response",
)


@dataclass(frozen=True)
class TypeInfo:
    name: str
    full_name: str
    namespace: str
    base: str | None
    line: int


@dataclass(frozen=True)
class MethodInfo:
    address: int
    name: str
    signature: str | None

    @property
    def member_name(self) -> str:
        if "$$" in self.name:
            return self.name.split("$$", 1)[1]
        return self.name.rsplit(".", 1)[-1]


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
        self.relocations: dict[int, int] = {}
        for section in self.elf.iter_sections():
            if not isinstance(section, RelocationSection):
                continue
            for relocation in section.iter_relocations():
                if relocation.is_RELA():
                    addend = int(relocation.entry.get("r_addend", 0))
                    if addend:
                        self.relocations[int(relocation.entry["r_offset"])] = addend

    def close(self) -> None:
        self.stream.close()

    def read(self, address: int, size: int) -> bytes:
        for vaddr, memsz, offset, filesz in self.segments:
            if vaddr <= address < vaddr + memsz:
                relative = address - vaddr
                if relative >= filesz:
                    return b""
                count = min(size, filesz - relative)
                self.stream.seek(offset + relative)
                return self.stream.read(count)
        return b""

    def qword(self, address: int) -> int | None:
        if address in self.relocations:
            return self.relocations[address]
        blob = self.read(address, 8)
        return struct.unpack("<Q", blob)[0] if len(blob) == 8 else None


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(value)


def parse_type_header(line: str, namespace: str) -> TypeInfo | None:
    match = _TYPE_RE.match(line)
    if not match:
        return None
    name = match.group(1)
    tail = line[match.end() :]
    base: str | None = None
    if ":" in tail:
        raw = tail.split(":", 1)[1].split("//", 1)[0].split("{", 1)[0].strip()
        if raw:
            base = raw.split(",", 1)[0].strip()
    full_name = f"{namespace}.{name}" if namespace else name
    return TypeInfo(name=name, full_name=full_name, namespace=namespace, base=base, line=0)


def parse_types(path: Path) -> list[TypeInfo]:
    namespace = ""
    types: list[TypeInfo] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        ns = _NAMESPACE_RE.match(line)
        if ns:
            namespace = ns.group(1).strip()
            continue
        parsed = parse_type_header(line, namespace)
        if parsed is not None:
            types.append(
                TypeInfo(
                    name=parsed.name,
                    full_name=parsed.full_name,
                    namespace=parsed.namespace,
                    base=parsed.base,
                    line=line_no,
                )
            )
    if not types:
        raise RuntimeError("no type definitions parsed from dump.cs")
    return types


def short_type_name(value: str) -> str:
    value = value.strip()
    value = value.split("<", 1)[0]
    value = value.replace("[]", "")
    return value.rsplit(".", 1)[-1]


def type_indexes(types: Iterable[TypeInfo]) -> tuple[dict[str, TypeInfo], dict[str, list[TypeInfo]]]:
    by_full: dict[str, TypeInfo] = {}
    by_short: dict[str, list[TypeInfo]] = {}
    for item in types:
        by_full[item.full_name] = item
        by_short.setdefault(short_type_name(item.name), []).append(item)
    return by_full, by_short


def resolve_base(
    owner: TypeInfo,
    by_full: dict[str, TypeInfo],
    by_short: dict[str, list[TypeInfo]],
) -> TypeInfo | None:
    if not owner.base:
        return None
    raw = owner.base.strip()
    if raw in by_full:
        return by_full[raw]
    same_namespace = f"{owner.namespace}.{raw}" if owner.namespace else raw
    if same_namespace in by_full:
        return by_full[same_namespace]
    candidates = by_short.get(short_type_name(raw), [])
    if len(candidates) == 1:
        return candidates[0]
    same_ns_candidates = [item for item in candidates if item.namespace == owner.namespace]
    if len(same_ns_candidates) == 1:
        return same_ns_candidates[0]
    return None


def inheritance_chain(
    owner: TypeInfo,
    by_full: dict[str, TypeInfo],
    by_short: dict[str, list[TypeInfo]],
    max_depth: int = 16,
) -> list[str]:
    chain = [owner.full_name]
    current = owner
    seen = {owner.full_name}
    for _ in range(max_depth):
        parent = resolve_base(current, by_full, by_short)
        if parent is None or parent.full_name in seen:
            if current.base and (not chain or chain[-1] != current.base):
                chain.append(current.base)
            break
        chain.append(parent.full_name)
        seen.add(parent.full_name)
        current = parent
    return chain


def is_network_task(
    owner: TypeInfo,
    by_full: dict[str, TypeInfo],
    by_short: dict[str, list[TypeInfo]],
) -> bool:
    chain = inheritance_chain(owner, by_full, by_short)
    return any(short_type_name(item) == "NetworkTask" for item in chain)


def load_methods(path: Path) -> tuple[list[MethodInfo], list[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    methods: list[MethodInfo] = []
    starts: set[int] = set()
    for item in raw.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        methods.append(
            MethodInfo(
                address=address,
                name=str(item.get("Name", "")),
                signature=item.get("Signature"),
            )
        )
        starts.add(address)
    for value in raw.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    if not methods:
        raise RuntimeError("no ScriptMethod entries parsed from script.json")
    return methods, sorted(starts)


def methods_by_type(methods: Iterable[MethodInfo]) -> dict[str, list[MethodInfo]]:
    result: dict[str, list[MethodInfo]] = {}
    for method in methods:
        if "$$" not in method.name:
            continue
        owner = method.name.split("$$", 1)[0]
        result.setdefault(owner, []).append(method)
    for values in result.values():
        values.sort(key=lambda item: item.address)
    return result


def method_role(method: MethodInfo) -> str:
    member = method.member_name
    if any(hint in member for hint in RESPONSE_ROLE_HINTS):
        return "response"
    if any(hint in member for hint in REQUEST_ROLE_HINTS):
        return "request"
    if member in {".ctor", ".cctor", "ctor", "cctor"}:
        return "lifecycle"
    return "other"


def load_literals(path: Path) -> dict[int, str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise RuntimeError("unexpected stringliteral.json root")
    result: dict[int, str] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        address_raw = item.get("address", item.get("Address"))
        if address_raw is None:
            continue
        value = item.get("value", item.get("Value", item.get("string", item.get("String"))))
        if not isinstance(value, str):
            continue
        result[as_int(address_raw)] = value
    return result


def classify_contract_literal(value: str) -> str | None:
    if not value or len(value) > 128 or any(ord(ch) < 0x20 for ch in value):
        return None
    if _API_PATH_RE.fullmatch(value):
        return "api_path"
    if _HEADER_RE.fullmatch(value):
        return "header"
    if _FIELD_KEY_RE.fullmatch(value):
        return "field_key"
    if _IDENTIFIER_PATH_RE.fullmatch(value) and (
        "." in value or ":" in value or value.startswith("http")
    ):
        return "identifier"
    return None


def function_bounds(starts: list[int], address: int) -> tuple[int, int]:
    index = bisect.bisect_right(starts, address)
    end = starts[index] if index < len(starts) else address + MAX_FUNCTION_SIZE
    return address, min(end, address + MAX_FUNCTION_SIZE)


def disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def invalidate_destination(state: dict[int, int], ins: Any) -> None:
    if ins.operands and ins.operands[0].type == ARM64_OP_REG:
        state.pop(int(ins.operands[0].reg), None)


def scan_method_literals(
    view: BinaryView,
    starts: list[int],
    method: MethodInfo,
    literals: dict[int, str],
) -> list[dict[str, str]]:
    start, end = function_bounds(starts, method.address)
    instructions = list(disassembler().disasm(view.read(start, end - start), start))
    found: dict[tuple[str, str], dict[str, str]] = {}

    for start_index, first in enumerate(instructions):
        if first.id not in {ARM64_INS_ADR, ARM64_INS_ADRP}:
            continue
        state: dict[int, int] = {}
        for ins in instructions[start_index : min(len(instructions), start_index + LITERAL_LOOKAHEAD)]:
            ops = ins.operands
            if ins.id in {ARM64_INS_B, ARM64_INS_BR, ARM64_INS_RET}:
                break
            if ins.id in {ARM64_INS_ADR, ARM64_INS_ADRP} and len(ops) >= 2:
                if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
                    state[int(ops[0].reg)] = int(ops[1].imm)
                    continue
            if ins.id == ARM64_INS_ADD and len(ops) >= 3:
                if (
                    ops[0].type == ARM64_OP_REG
                    and ops[1].type == ARM64_OP_REG
                    and ops[2].type == ARM64_OP_IMM
                ):
                    base = state.get(int(ops[1].reg))
                    if base is not None:
                        state[int(ops[0].reg)] = base + int(ops[2].imm)
                        continue
                invalidate_destination(state, ins)
                continue
            if ins.id == ARM64_INS_LDR and len(ops) >= 2:
                if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_MEM:
                    mem = ops[1].mem
                    base = state.get(int(mem.base))
                    if base is not None and int(mem.index) == 0:
                        loaded = view.qword(base + int(mem.disp))
                        if loaded is not None:
                            value = literals.get(loaded)
                            if value is not None:
                                kind = classify_contract_literal(value)
                                if kind is not None:
                                    found[(kind, value)] = {"kind": kind, "value": value}
                            state[int(ops[0].reg)] = loaded
                            continue
                invalidate_destination(state, ins)
                continue
            if ins.id in {ARM64_INS_BL, ARM64_INS_BLR}:
                state.clear()
                continue
            if (
                ops
                and ops[0].type == ARM64_OP_REG
                and ins.mnemonic.lower()
                not in {"cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz"}
                and not ins.mnemonic.lower().startswith("b.")
            ):
                invalidate_destination(state, ins)

    values = sorted(found.values(), key=lambda item: (item["kind"], item["value"]))
    if len(values) > MAX_METHOD_LITERALS:
        values = values[:MAX_METHOD_LITERALS]
    return values


def normalize_endpoint_name(value: str) -> str:
    value = short_type_name(value)
    for suffix in ("NetworkTask", "Task", "Api", "Request", "Response"):
        if value.endswith(suffix):
            value = value[: -len(suffix)]
    return re.sub(r"[^a-z0-9]", "", value.lower())


def load_api_map(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise RuntimeError("API map root must be an object")
    endpoints: list[dict[str, Any]] = []
    for group, entries in raw.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, list) or len(entry) < 3:
                continue
            name, key, endpoint_path = entry[:3]
            if isinstance(name, str) and isinstance(key, int) and isinstance(endpoint_path, str):
                endpoints.append(
                    {
                        "group": str(group),
                        "name": name,
                        "key": key,
                        "path": endpoint_path,
                    }
                )
    return endpoints


def correlate_endpoints(
    task: TypeInfo,
    role_literals: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_identity: dict[tuple[str, int], dict[str, Any]] = {}
    literal_paths = {
        literal["value"]
        for method in role_literals
        for literal in method.get("contract_literals", [])
        if literal["kind"] == "api_path"
    }
    for endpoint in endpoints:
        if endpoint["path"] in literal_paths:
            record = dict(endpoint)
            record["evidence"] = "literal_path"
            by_identity[(record["group"], record["key"])] = record

    task_norm = normalize_endpoint_name(task.name)
    if task_norm:
        matches = [
            endpoint
            for endpoint in endpoints
            if normalize_endpoint_name(endpoint["name"]) == task_norm
        ]
        if len(matches) == 1:
            endpoint = matches[0]
            identity = (endpoint["group"], endpoint["key"])
            if identity not in by_identity:
                record = dict(endpoint)
                record["evidence"] = "normalized_type_name"
                by_identity[identity] = record

    return sorted(by_identity.values(), key=lambda item: (item["group"], item["key"]))


def summarize_task(
    task: TypeInfo,
    chain: list[str],
    methods: list[MethodInfo],
    view: BinaryView,
    starts: list[int],
    literals: dict[int, str],
    endpoints: list[dict[str, Any]],
) -> dict[str, Any]:
    if len(methods) > MAX_TASK_METHODS:
        raise RuntimeError(f"unexpectedly many methods on {task.full_name}: {len(methods)}")

    role_records: list[dict[str, Any]] = []
    all_contract_literals: dict[tuple[str, str], dict[str, str]] = {}
    for method in methods:
        role = method_role(method)
        if role not in {"request", "response"}:
            continue
        contract_literals = scan_method_literals(view, starts, method, literals)
        for item in contract_literals:
            all_contract_literals[(item["kind"], item["value"])] = item
        role_records.append(
            {
                "name": method.name,
                "member": method.member_name,
                "rva": method.address,
                "role": role,
                "signature": method.signature,
                "contract_literals": contract_literals,
            }
        )

    endpoint_candidates = correlate_endpoints(task, role_records, endpoints)
    return {
        "type": task.full_name,
        "base": task.base,
        "inheritance": chain,
        "method_count": len(methods),
        "request_method_count": sum(1 for item in role_records if item["role"] == "request"),
        "response_method_count": sum(1 for item in role_records if item["role"] == "response"),
        "role_methods": role_records,
        "contract_literals": sorted(
            all_contract_literals.values(), key=lambda item: (item["kind"], item["value"])
        ),
        "endpoint_candidates": endpoint_candidates,
    }


def markdown_summary(report: dict[str, Any]) -> str:
    lines = [
        "# CGSS 11.6.3 server-facing contract inventory",
        "",
        "Sanitized broad static inventory generated from the exact final client.",
        "",
        f"- NetworkTask descendants: **{report['network_task_type_count']}**",
        f"- Task methods: **{report['network_task_method_count']}**",
        f"- Request-role methods: **{report['request_role_method_count']}**",
        f"- Response-role methods: **{report['response_role_method_count']}**",
        f"- Tasks with contract-like literals: **{report['tasks_with_contract_literals']}**",
        f"- Tasks with endpoint candidates: **{report['tasks_with_endpoint_candidates']}**",
        "",
        "## Highest-signal task types",
        "",
    ]
    ranked = sorted(
        report["tasks"],
        key=lambda item: (
            len(item["endpoint_candidates"]),
            len(item["contract_literals"]),
            item["request_method_count"] + item["response_method_count"],
        ),
        reverse=True,
    )
    for item in ranked[:80]:
        suffix: list[str] = []
        if item["endpoint_candidates"]:
            suffix.append(
                "endpoints="
                + ", ".join(
                    f"{endpoint['group']}:{endpoint['key']}:{endpoint['path']}"
                    for endpoint in item["endpoint_candidates"][:4]
                )
            )
        fields = [
            literal["value"]
            for literal in item["contract_literals"]
            if literal["kind"] == "field_key"
        ][:8]
        if fields:
            suffix.append("keys=" + ", ".join(fields))
        detail = "; ".join(suffix) if suffix else "no contract literal recovered yet"
        lines.append(f"- `{item['type']}` — {detail}")
    lines += [
        "",
        "This is an inventory, not proof that every candidate endpoint or field is required at runtime.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--api-map", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    types = parse_types(args.dump_cs)
    by_full, by_short = type_indexes(types)
    methods, starts = load_methods(args.script_json)
    owner_methods = methods_by_type(methods)
    literals = load_literals(args.stringliteral_json)
    endpoints = load_api_map(args.api_map)

    task_types = [
        item
        for item in types
        if item.full_name != "Cute.NetworkTask" and is_network_task(item, by_full, by_short)
    ]
    if len(task_types) > MAX_TASK_TYPES:
        raise RuntimeError(f"unexpected NetworkTask type count: {len(task_types)}")

    view = BinaryView(args.lib)
    try:
        tasks: list[dict[str, Any]] = []
        for task in sorted(task_types, key=lambda item: item.full_name):
            task_methods = owner_methods.get(task.full_name, [])
            if not task_methods:
                short_candidates = by_short.get(short_type_name(task.name), [])
                if len(short_candidates) == 1:
                    task_methods = owner_methods.get(task.name, [])
            tasks.append(
                summarize_task(
                    task,
                    inheritance_chain(task, by_full, by_short),
                    task_methods,
                    view,
                    starts,
                    literals,
                    endpoints,
                )
            )
    finally:
        view.close()

    report = {
        "schema": SCHEMA,
        "scope": "server-facing NetworkTask descendants",
        "network_task_type_count": len(tasks),
        "network_task_method_count": sum(item["method_count"] for item in tasks),
        "request_role_method_count": sum(item["request_method_count"] for item in tasks),
        "response_role_method_count": sum(item["response_method_count"] for item in tasks),
        "tasks_with_contract_literals": sum(bool(item["contract_literals"]) for item in tasks),
        "tasks_with_endpoint_candidates": sum(bool(item["endpoint_candidates"]) for item in tasks),
        "api_map_loaded": bool(endpoints),
        "api_map_endpoint_count": len(endpoints),
        "tasks": tasks,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.markdown_output is not None:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(markdown_summary(report), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
