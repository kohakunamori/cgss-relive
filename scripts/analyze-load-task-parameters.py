#!/usr/bin/env python3
"""Bounded clean-room analysis of final LoadTask ``load_state`` / ``next_api``.

Exact metadata declares both target fields on ``LoadTaskParam`` while final
``Stage.LoadTask.SetParameter`` has no explicit arguments. Earlier passes proved
that SetParameter directly touches only ``this+0x30`` rather than target offsets
0x40/0x50. This pass keeps that result, records the actual read/write semantics
of the 0x30 access, follows a child only when 0x30 is genuinely loaded, traces
the small LoadTask inheritance chain, and inspects only methods structurally
related to ``LoadTaskParam`` for direct target-offset or ``next_api`` literal
references.

Only declarations, RVAs, aggregate offsets, method signatures and tiny ARM64
contexts are emitted. No response data or bulk decompiler output is emitted.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import struct
from pathlib import Path
from typing import Any

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
    ARM64_INS_MOV,
    ARM64_INS_RET,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
)
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

SET_PARAMETER_START = 0x04877A14
PARAM_CHILD_SELF_OFFSET = 0x30
TARGET_VALUES = ("load_state", "next_api")
MAX_FUNCTION_SIZE = 0x4000
CONTEXT_RADIUS = 5
MAX_OFFSETS = 160
MAX_RELATED_METHODS = 96
MAX_RELATED_OFFSET_HITS = 64
MAX_LITERAL_HITS = 32
MAX_INHERITANCE_DEPTH = 8
LITERAL_LOOKAHEAD = 20
_TYPE_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)?\s*"
    r"(?:(?:sealed|abstract|static|partial)\s+)*"
    r"(?:class|struct)\s+([^\s:{]+)"
)
_OFFSET_RE = re.compile(r"//\s*0x([0-9A-Fa-f]+)\s*$")
_RVA_RE = re.compile(r"//\s*RVA:\s*0x([0-9A-Fa-f]+)")


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


def load_script(path: Path) -> tuple[list[int], dict[int, str]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    starts: set[int] = set()
    methods: dict[int, str] = {}
    for item in data.get("ScriptMethod", []):
        value = as_int(item.get("Address", 0))
        if value > 0:
            starts.add(value)
            methods.setdefault(value, str(item.get("Name", "")))
    for value in data.get("Addresses", []):
        parsed = as_int(value)
        if parsed > 0:
            starts.add(parsed)
    return sorted(starts), methods


def next_function_start(starts: list[int], address: int) -> int:
    index = bisect.bisect_right(starts, address)
    if index >= len(starts) or starts[index] - address > MAX_FUNCTION_SIZE:
        raise RuntimeError(f"could not safely bound function after 0x{address:X}")
    return starts[index]


def target_string_literal_addresses(path: Path) -> dict[str, list[int]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise RuntimeError("unexpected stringliteral.json root")
    result = {target: [] for target in TARGET_VALUES}
    for item in data:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value"))
        if value not in result or item.get("address") is None:
            continue
        result[value].append(as_int(item["address"]))
    return {key: sorted(set(values)) for key, values in result.items()}


def dump_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


def parse_type_header(line: str) -> dict[str, Any] | None:
    match = _TYPE_RE.match(line)
    if not match:
        return None
    name = match.group(1)
    tail = line[match.end() :]
    bases: list[str] = []
    if ":" in tail:
        raw = tail.split(":", 1)[1].split("//", 1)[0].split("{", 1)[0].strip()
        if raw:
            bases = [raw]
    return {"name": name, "declaration": line.strip(), "bases": bases}


def short_type_name(value: str) -> str:
    value = value.strip()
    value = value.split("<", 1)[0]
    value = value.rsplit(".", 1)[-1]
    return value


def type_catalog(lines: list[str]) -> dict[str, list[dict[str, Any]]]:
    catalog: dict[str, list[dict[str, Any]]] = {}
    for index, line in enumerate(lines):
        header = parse_type_header(line)
        if header is None:
            continue
        entry = {**header, "line": index + 1, "index": index}
        catalog.setdefault(short_type_name(str(header["name"])), []).append(entry)
    return catalog


def find_target_declarations(lines: list[str]) -> list[dict[str, Any]]:
    owner: str | None = None
    matches: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        type_match = _TYPE_RE.match(line)
        if type_match:
            owner = type_match.group(1)
        for target in TARGET_VALUES:
            if not re.search(rf"\b{re.escape(target)}\b", line):
                continue
            offset_match = _OFFSET_RE.search(line)
            matches.append(
                {
                    "target": target,
                    "owner": owner,
                    "line": line_number,
                    "declaration": line.strip(),
                    "offset": int(offset_match.group(1), 16) if offset_match else None,
                }
            )
    return matches


def find_method_metadata(lines: list[str], rva: int) -> tuple[str | None, str | None, int | None]:
    for index, line in enumerate(lines):
        match = _RVA_RE.search(line)
        if not match or int(match.group(1), 16) != rva:
            continue
        signature = lines[index + 1].strip() if index + 1 < len(lines) else None
        owner = None
        owner_line = None
        for back in range(index, -1, -1):
            type_match = _TYPE_RE.match(lines[back])
            if type_match:
                owner = type_match.group(1)
                owner_line = back
                break
        return owner, signature, owner_line
    return None, None, None


def find_offset_field_in_type(
    lines: list[str], type_index: int | None, offset: int
) -> dict[str, Any] | None:
    if type_index is None:
        return None
    for index in range(type_index + 1, min(len(lines), type_index + 400)):
        if index > type_index + 1 and _TYPE_RE.match(lines[index]):
            break
        match = _OFFSET_RE.search(lines[index])
        if match and int(match.group(1), 16) == offset:
            return {
                "line": index + 1,
                "offset": offset,
                "declaration": lines[index].strip(),
            }
    return None


def choose_type_entry(
    catalog: dict[str, list[dict[str, Any]]], name: str, *, preferred_index: int | None = None
) -> dict[str, Any] | None:
    entries = catalog.get(short_type_name(name), [])
    if not entries:
        return None
    if preferred_index is None:
        return entries[0]
    return min(entries, key=lambda item: abs(int(item["index"]) - preferred_index))


def inheritance_summary(
    lines: list[str],
    catalog: dict[str, list[dict[str, Any]]],
    owner_line: int | None,
) -> list[dict[str, Any]]:
    if owner_line is None:
        return []
    current = parse_type_header(lines[owner_line])
    current_index = owner_line
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for _ in range(MAX_INHERITANCE_DEPTH):
        if current is None:
            break
        name = str(current["name"])
        short = short_type_name(name)
        if short in seen:
            break
        seen.add(short)
        result.append(
            {
                "name": name,
                "line": current_index + 1,
                "declaration": str(current["declaration"]),
                "bases": list(current.get("bases", [])),
                "field_at_0x30": find_offset_field_in_type(
                    lines, current_index, PARAM_CHILD_SELF_OFFSET
                ),
                "mentions_load_task_param": "LoadTaskParam" in str(current["declaration"]),
            }
        )
        bases = list(current.get("bases", []))
        if not bases:
            break
        entry = choose_type_entry(catalog, bases[0])
        if entry is None:
            break
        current = entry
        current_index = int(entry["index"])
    return result


def find_related_methods(
    lines: list[str], relevant_owner_names: set[str]
) -> list[dict[str, Any]]:
    owner: str | None = None
    methods: list[dict[str, Any]] = []
    for index, line in enumerate(lines):
        type_match = _TYPE_RE.match(line)
        if type_match:
            owner = type_match.group(1)
            continue
        rva_match = _RVA_RE.search(line)
        if not rva_match:
            continue
        signature = lines[index + 1].strip() if index + 1 < len(lines) else ""
        owner_short = short_type_name(owner or "")
        if owner_short not in relevant_owner_names and "LoadTaskParam" not in signature:
            continue
        methods.append(
            {
                "rva": int(rva_match.group(1), 16),
                "owner": owner,
                "signature": signature,
                "line": index + 2,
                "owner_is_structurally_related": owner_short in relevant_owner_names,
                "signature_mentions_load_task_param": "LoadTaskParam" in signature,
            }
        )
        if len(methods) > MAX_RELATED_METHODS:
            raise RuntimeError("unexpectedly many LoadTaskParam-related methods")
    return methods


def md() -> Cs:
    dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    dis.detail = True
    return dis


def canonical_register(dis: Cs, reg_id: int) -> str:
    name = dis.reg_name(reg_id)
    if name.startswith("w") and name[1:].isdigit():
        return "x" + name[1:]
    return name


def memory_access_kind(ins: Any) -> str | None:
    mnemonic = ins.mnemonic.lower()
    if mnemonic.startswith(("ldr", "ldur", "ldp")):
        return "read"
    if mnemonic.startswith(("str", "stur", "stp")):
        return "write"
    return None


def written_registers(dis: Cs, ins: Any) -> set[str]:
    try:
        _, writes = ins.regs_access()
    except Exception:
        return set()
    return {canonical_register(dis, int(reg)) for reg in writes}


def load_destination_registers(dis: Cs, ins: Any) -> list[str]:
    if memory_access_kind(ins) != "read":
        return []
    destinations: list[str] = []
    for operand in ins.operands:
        if operand.type == ARM64_OP_MEM:
            break
        if operand.type == ARM64_OP_REG:
            destinations.append(canonical_register(dis, int(operand.reg)))
    return destinations


def context(instructions: list[Any], index: int) -> list[str]:
    lo = max(0, index - CONTEXT_RADIUS)
    hi = min(len(instructions), index + CONTEXT_RADIUS + 1)
    return [
        f"0x{item.address:X}: {item.mnemonic} {item.op_str}" for item in instructions[lo:hi]
    ]


def scan_parameter_chain(
    view: BinaryView,
    start: int,
    end: int,
    target_offsets: dict[int, list[str]],
) -> dict[str, Any]:
    dis = md()
    instructions = list(dis.disasm(view.read(start, end - start), start))
    self_aliases = {"x0"}
    child_aliases: set[str] = set()
    self_offsets: set[int] = set()
    child_offsets: set[int] = set()
    self_0x30_accesses: list[dict[str, Any]] = []
    child_load_sites: list[dict[str, Any]] = []
    target_hits: list[dict[str, Any]] = []

    for index, ins in enumerate(instructions):
        ops = ins.operands
        access_kind = memory_access_kind(ins)
        loaded_child_destinations: list[str] = []

        if access_kind is not None:
            for operand in ops:
                if operand.type != ARM64_OP_MEM:
                    continue
                mem = operand.mem
                base = canonical_register(dis, int(mem.base))
                displacement = int(mem.disp)
                if base in self_aliases:
                    self_offsets.add(displacement)
                    if displacement == PARAM_CHILD_SELF_OFFSET:
                        destinations = (
                            load_destination_registers(dis, ins) if access_kind == "read" else []
                        )
                        self_0x30_accesses.append(
                            {
                                "site": ins.address,
                                "mnemonic": ins.mnemonic,
                                "access": access_kind,
                                "base": base,
                                "destinations": destinations,
                                "context": context(instructions, index),
                            }
                        )
                        if access_kind == "read":
                            loaded_child_destinations = destinations
                            child_load_sites.append(
                                {
                                    "site": ins.address,
                                    "offset": displacement,
                                    "destinations": destinations,
                                    "context": context(instructions, index),
                                }
                            )
                if base in child_aliases:
                    child_offsets.add(displacement)
                    if displacement in target_offsets:
                        target_hits.append(
                            {
                                "site": ins.address,
                                "mnemonic": ins.mnemonic,
                                "access": access_kind,
                                "offset": displacement,
                                "targets": sorted(target_offsets[displacement]),
                                "context": context(instructions, index),
                            }
                        )

        self_copy: str | None = None
        child_copy: str | None = None
        if ins.id in {ARM64_INS_MOV, ARM64_INS_ADD} and len(ops) >= 2:
            if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG:
                destination = canonical_register(dis, int(ops[0].reg))
                source = canonical_register(dis, int(ops[1].reg))
                is_copy = ins.id == ARM64_INS_MOV
                if ins.id == ARM64_INS_ADD:
                    is_copy = (
                        len(ops) >= 3
                        and ops[2].type == ARM64_OP_IMM
                        and int(ops[2].imm) == 0
                    )
                if is_copy and source in self_aliases:
                    self_copy = destination
                if is_copy and source in child_aliases:
                    child_copy = destination

        writes = written_registers(dis, ins)
        for register in writes:
            self_aliases.discard(register)
            child_aliases.discard(register)
        if ins.id in {ARM64_INS_BL, ARM64_INS_BLR}:
            self_aliases.discard("x0")
            child_aliases.discard("x0")

        if self_copy is not None:
            self_aliases.add(self_copy)
        if child_copy is not None:
            child_aliases.add(child_copy)
        for destination in loaded_child_destinations:
            child_aliases.add(destination)

    if len(self_offsets) > MAX_OFFSETS or len(child_offsets) > MAX_OFFSETS:
        raise RuntimeError("unexpectedly many LoadTask parameter-chain offsets")

    return {
        "self_memory_offsets": [f"0x{offset:X}" for offset in sorted(self_offsets)],
        "self_offset_0x30_accesses": self_0x30_accesses,
        "parameter_child_self_offset": f"0x{PARAM_CHILD_SELF_OFFSET:X}",
        "parameter_child_load_sites": child_load_sites,
        "child_memory_offsets": [f"0x{offset:X}" for offset in sorted(child_offsets)],
        "target_field_accesses": target_hits,
        "observed_targets": sorted({target for hit in target_hits for target in hit["targets"]}),
        "written_targets": sorted(
            {
                target
                for hit in target_hits
                if hit["access"] == "write"
                for target in hit["targets"]
            }
        ),
        "read_targets": sorted(
            {
                target
                for hit in target_hits
                if hit["access"] == "read"
                for target in hit["targets"]
            }
        ),
    }


def scan_direct_target_offsets(
    view: BinaryView,
    start: int,
    end: int,
    target_offsets: dict[int, list[str]],
) -> list[dict[str, Any]]:
    dis = md()
    instructions = list(dis.disasm(view.read(start, end - start), start))
    hits: list[dict[str, Any]] = []
    for index, ins in enumerate(instructions):
        access_kind = memory_access_kind(ins)
        if access_kind is None:
            continue
        for operand in ins.operands:
            if operand.type != ARM64_OP_MEM:
                continue
            displacement = int(operand.mem.disp)
            if displacement not in target_offsets:
                continue
            hits.append(
                {
                    "site": ins.address,
                    "mnemonic": ins.mnemonic,
                    "access": access_kind,
                    "base": canonical_register(dis, int(operand.mem.base)),
                    "offset": displacement,
                    "targets": sorted(target_offsets[displacement]),
                    "context": context(instructions, index),
                }
            )
            if len(hits) > MAX_RELATED_OFFSET_HITS:
                raise RuntimeError("unexpectedly many related-method target offset hits")
    return hits


def invalidate_destination(state: dict[int, int], ins: Any) -> None:
    if ins.operands and ins.operands[0].type == ARM64_OP_REG:
        state.pop(int(ins.operands[0].reg), None)


def scan_literal_xrefs(
    view: BinaryView,
    start: int,
    end: int,
    targets: set[int],
) -> list[dict[str, Any]]:
    if not targets:
        return []
    dis = md()
    instructions = list(dis.disasm(view.read(start, end - start), start))
    raw_hits: set[int] = set()
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
                        if loaded in targets:
                            raw_hits.add(ins.address)
                        if loaded is not None:
                            state[int(ops[0].reg)] = loaded
                            continue
                invalidate_destination(state, ins)
                continue
            if (
                ops
                and ops[0].type == ARM64_OP_REG
                and ins.mnemonic.lower()
                not in {"cmp", "cmn", "tst", "cbz", "cbnz", "tbz", "tbnz"}
                and not ins.mnemonic.lower().startswith("b.")
            ):
                invalidate_destination(state, ins)

    if len(raw_hits) > MAX_LITERAL_HITS:
        raise RuntimeError("unexpectedly many next_api literal xrefs in related methods")
    indexes = {ins.address: index for index, ins in enumerate(instructions)}
    return [
        {"site": address, "context": context(instructions, indexes[address])}
        for address in sorted(raw_hits)
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lines = dump_lines(args.dump_cs)
    declarations = find_target_declarations(lines)
    if not declarations:
        raise RuntimeError("dump.cs did not contain load_state/next_api metadata declarations")

    param_offsets: dict[int, list[str]] = {}
    for item in declarations:
        owner = str(item.get("owner") or "")
        offset = item.get("offset")
        if "LoadTaskParam" in owner and isinstance(offset, int):
            param_offsets.setdefault(offset, []).append(str(item["target"]))

    owner, signature, owner_line = find_method_metadata(lines, SET_PARAMETER_START)
    catalog = type_catalog(lines)
    inheritance = inheritance_summary(lines, catalog, owner_line)
    direct_owner_field = find_offset_field_in_type(lines, owner_line, PARAM_CHILD_SELF_OFFSET)

    relevant_owner_names = {"LoadTaskParam", "LoadTask"}
    relevant_owner_names.update(short_type_name(str(item["name"])) for item in inheritance)
    related_methods = find_related_methods(lines, relevant_owner_names)

    starts, methods = load_script(args.script_json)
    set_parameter_end = next_function_start(starts, SET_PARAMETER_START)
    literals = target_string_literal_addresses(args.stringliteral_json)
    next_api_targets = set(literals.get("next_api", []))

    view = BinaryView(args.lib)
    try:
        chain = scan_parameter_chain(view, SET_PARAMETER_START, set_parameter_end, param_offsets)
        related_offset_accesses: list[dict[str, Any]] = []
        next_api_xrefs: list[dict[str, Any]] = []
        for item in related_methods:
            rva = int(item["rva"])
            try:
                end = next_function_start(starts, rva)
            except RuntimeError:
                continue
            offset_hits = scan_direct_target_offsets(view, rva, end, param_offsets)
            if offset_hits:
                related_offset_accesses.append(
                    {
                        "rva": rva,
                        "resolved_name": methods.get(rva),
                        "owner": item.get("owner"),
                        "signature": item.get("signature"),
                        "hits": offset_hits,
                    }
                )
            literal_hits = scan_literal_xrefs(view, rva, end, next_api_targets)
            if literal_hits:
                next_api_xrefs.append(
                    {
                        "rva": rva,
                        "resolved_name": methods.get(rva),
                        "owner": item.get("owner"),
                        "signature": item.get("signature"),
                        "hits": literal_hits,
                    }
                )
    finally:
        view.close()

    report = {
        "schema": 7,
        "targets": list(TARGET_VALUES),
        "string_literal_present": {key: bool(value) for key, value in literals.items()},
        "dump_declarations": declarations,
        "load_task_param_offsets": {
            f"0x{offset:X}": sorted(values) for offset, values in sorted(param_offsets.items())
        },
        "load_task_inheritance": inheritance,
        "related_method_count": len(related_methods),
        "related_methods": related_methods,
        "related_method_target_offset_accesses": related_offset_accesses,
        "next_api_related_method_xrefs": next_api_xrefs,
        "set_parameter": {
            "start": SET_PARAMETER_START,
            "end": set_parameter_end,
            "resolved_name": methods.get(SET_PARAMETER_START),
            "dump_owner": owner,
            "dump_signature": signature,
            "direct_owner_field_at_0x30": direct_owner_field,
            **chain,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "string_literal_present": report["string_literal_present"],
                "load_task_param_offsets": report["load_task_param_offsets"],
                "set_parameter_owner": owner,
                "set_parameter_signature": signature,
                "direct_owner_field_at_0x30": direct_owner_field,
                "inheritance_depth": len(inheritance),
                "inheritance_mentions_load_task_param": any(
                    bool(item.get("mentions_load_task_param")) for item in inheritance
                ),
                "self_memory_offsets": chain["self_memory_offsets"],
                "self_offset_0x30_access_count": len(chain["self_offset_0x30_accesses"]),
                "child_memory_offsets": chain["child_memory_offsets"],
                "written_targets": chain["written_targets"],
                "read_targets": chain["read_targets"],
                "related_method_count": len(related_methods),
                "related_method_target_access_count": sum(
                    len(item["hits"]) for item in related_offset_accesses
                ),
                "next_api_related_method_xref_count": sum(
                    len(item["hits"]) for item in next_api_xrefs
                ),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
