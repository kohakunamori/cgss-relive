#!/usr/bin/env python3
"""Bounded clean-room analysis of final LoadTask ``load_state`` / ``next_api``.

Exact metadata declares both target fields on ``LoadTaskParam`` while final
``Stage.LoadTask.SetParameter`` has no explicit arguments. Earlier passes proved
that SetParameter directly touches only ``this+0x30`` rather than target offsets
0x40/0x50. This pass follows exactly one object edge loaded from that self offset:

    LoadTask this -> field at 0x30 -> child object -> target offsets 0x40/0x50

It records read/write direction and emits only the two target declarations, the
owner field at 0x30 when recoverable from dump.cs, aggregate offsets, and tiny
instruction contexts. No response data or bulk decompiler output is emitted.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import (
    ARM64_INS_ADD,
    ARM64_INS_BL,
    ARM64_INS_BLR,
    ARM64_INS_MOV,
    ARM64_OP_IMM,
    ARM64_OP_MEM,
    ARM64_OP_REG,
)
from elftools.elf.elffile import ELFFile

SET_PARAMETER_START = 0x04877A14
PARAM_CHILD_SELF_OFFSET = 0x30
TARGET_VALUES = ("load_state", "next_api")
MAX_FUNCTION_SIZE = 0x4000
CONTEXT_RADIUS = 5
MAX_OFFSETS = 160
_TYPE_RE = re.compile(r"^\s*(?:public|private|internal|protected)?\s*(?:sealed\s+|abstract\s+|static\s+)?(?:class|struct)\s+([^\s:{]+)")
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
    later = [value for value in starts if value > address]
    if not later or later[0] - address > MAX_FUNCTION_SIZE:
        raise RuntimeError(f"could not safely bound function after 0x{address:X}")
    return later[0]


def target_string_literals(path: Path) -> dict[str, bool]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise RuntimeError("unexpected stringliteral.json root")
    values = {str(item.get("value")) for item in data if isinstance(item, dict)}
    return {target: target in values for target in TARGET_VALUES}


def dump_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8", errors="replace").splitlines()


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


def find_owner_offset_field(
    lines: list[str], owner_line: int | None, offset: int
) -> dict[str, Any] | None:
    if owner_line is None:
        return None
    for index in range(owner_line + 1, min(len(lines), owner_line + 300)):
        if index > owner_line + 1 and _TYPE_RE.match(lines[index]):
            break
        match = _OFFSET_RE.search(lines[index])
        if match and int(match.group(1), 16) == offset:
            return {
                "line": index + 1,
                "offset": offset,
                "declaration": lines[index].strip(),
            }
    return None


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
                    if access_kind == "read" and displacement == PARAM_CHILD_SELF_OFFSET:
                        loaded_child_destinations = load_destination_registers(dis, ins)
                        child_load_sites.append(
                            {
                                "site": ins.address,
                                "offset": displacement,
                                "destinations": loaded_child_destinations,
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
                    is_copy = len(ops) >= 3 and ops[2].type == ARM64_OP_IMM and int(ops[2].imm) == 0
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
    owner_field = find_owner_offset_field(lines, owner_line, PARAM_CHILD_SELF_OFFSET)

    starts, methods = load_script(args.script_json)
    set_parameter_end = next_function_start(starts, SET_PARAMETER_START)
    view = BinaryView(args.lib)
    try:
        chain = scan_parameter_chain(view, SET_PARAMETER_START, set_parameter_end, param_offsets)
    finally:
        view.close()

    report = {
        "schema": 6,
        "targets": list(TARGET_VALUES),
        "string_literal_present": target_string_literals(args.stringliteral_json),
        "dump_declarations": declarations,
        "load_task_param_offsets": {
            f"0x{offset:X}": sorted(values) for offset, values in sorted(param_offsets.items())
        },
        "set_parameter": {
            "start": SET_PARAMETER_START,
            "end": set_parameter_end,
            "resolved_name": methods.get(SET_PARAMETER_START),
            "dump_owner": owner,
            "dump_signature": signature,
            "owner_field_at_0x30": owner_field,
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
                "owner_field_at_0x30": owner_field,
                "self_memory_offsets": chain["self_memory_offsets"],
                "child_memory_offsets": chain["child_memory_offsets"],
                "written_targets": chain["written_targets"],
                "read_targets": chain["read_targets"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
