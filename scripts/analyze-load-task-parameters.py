#!/usr/bin/env python3
"""Bounded clean-room analysis of final LoadTask ``load_state`` / ``next_api``.

Those names are present in the IL2CPP metadata-derived dump but are not guaranteed
to exist as managed string literals. This pass treats dump.cs field metadata as
the primary evidence, records string-literal presence separately, and tracks
memory reads from the LoadTask.SetParameter argument object by field offset. It
emits only the two target declarations, aggregate argument offsets, and tiny
contexts around matching target-offset reads.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_ADD, ARM64_INS_MOV, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile

SET_PARAMETER_START = 0x04877A14
TARGET_VALUES = ("load_state", "next_api")
MAX_FUNCTION_SIZE = 0x4000
CONTEXT_RADIUS = 5
MAX_ARGUMENT_OFFSETS = 96
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


def find_target_declarations(path: Path) -> list[dict[str, Any]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
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


def find_method_signature(path: Path, rva: int) -> str | None:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for index, line in enumerate(lines):
        match = _RVA_RE.search(line)
        if not match or int(match.group(1), 16) != rva:
            continue
        if index + 1 < len(lines):
            return lines[index + 1].strip()
    return None


def md() -> Cs:
    dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    dis.detail = True
    return dis


def canonical_pointer_register(dis: Cs, reg_id: int) -> str:
    name = dis.reg_name(reg_id)
    if name.startswith("w") and name[1:].isdigit():
        return "x" + name[1:]
    return name


def is_memory_load(ins: Any) -> bool:
    mnemonic = ins.mnemonic.lower()
    return mnemonic.startswith(("ldr", "ldur", "ldp"))


def scan_argument_memory_reads(
    view: BinaryView,
    start: int,
    end: int,
    target_offsets: dict[int, list[str]],
) -> tuple[list[int], list[dict[str, Any]]]:
    dis = md()
    instructions = list(dis.disasm(view.read(start, end - start), start))
    aliases = {"x1"}
    observed_offsets: set[int] = set()
    target_hits: list[dict[str, Any]] = []

    for index, ins in enumerate(instructions):
        ops = ins.operands
        if is_memory_load(ins):
            for operand in ops:
                if operand.type != ARM64_OP_MEM:
                    continue
                mem = operand.mem
                base = canonical_pointer_register(dis, int(mem.base))
                if base not in aliases:
                    continue
                displacement = int(mem.disp)
                observed_offsets.add(displacement)
                if displacement in target_offsets:
                    lo = max(0, index - CONTEXT_RADIUS)
                    hi = min(len(instructions), index + CONTEXT_RADIUS + 1)
                    target_hits.append(
                        {
                            "site": ins.address,
                            "mnemonic": ins.mnemonic,
                            "offset": displacement,
                            "targets": sorted(target_offsets[displacement]),
                            "context": [
                                f"0x{item.address:X}: {item.mnemonic} {item.op_str}"
                                for item in instructions[lo:hi]
                            ],
                        }
                    )

        if ins.id in {ARM64_INS_MOV, ARM64_INS_ADD} and len(ops) >= 2:
            if ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG:
                destination = canonical_pointer_register(dis, int(ops[0].reg))
                source = canonical_pointer_register(dis, int(ops[1].reg))
                is_alias_copy = ins.id == ARM64_INS_MOV
                if ins.id == ARM64_INS_ADD:
                    is_alias_copy = len(ops) >= 3 and ops[2].type == ARM64_OP_IMM and int(ops[2].imm) == 0
                if is_alias_copy and source in aliases:
                    aliases.add(destination)
                elif destination in aliases and destination != "x1":
                    aliases.discard(destination)
        elif ops and ops[0].type == ARM64_OP_REG:
            destination = canonical_pointer_register(dis, int(ops[0].reg))
            if destination in aliases and destination != "x1" and not is_memory_load(ins):
                aliases.discard(destination)

    if len(observed_offsets) > MAX_ARGUMENT_OFFSETS:
        raise RuntimeError("unexpectedly many parameter-object memory offsets")
    return sorted(observed_offsets), target_hits


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--stringliteral-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    declarations = find_target_declarations(args.dump_cs)
    if not declarations:
        raise RuntimeError("dump.cs did not contain load_state/next_api metadata declarations")

    param_offsets: dict[int, list[str]] = {}
    for item in declarations:
        owner = str(item.get("owner") or "")
        offset = item.get("offset")
        if "LoadTaskParam" in owner and isinstance(offset, int):
            param_offsets.setdefault(offset, []).append(str(item["target"]))

    starts, methods = load_script(args.script_json)
    set_parameter_end = next_function_start(starts, SET_PARAMETER_START)
    view = BinaryView(args.lib)
    try:
        offsets, reads = scan_argument_memory_reads(
            view, SET_PARAMETER_START, set_parameter_end, param_offsets
        )
    finally:
        view.close()

    report = {
        "schema": 3,
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
            "dump_signature": find_method_signature(args.dump_cs, SET_PARAMETER_START),
            "argument_memory_offsets": [f"0x{offset:X}" for offset in offsets],
            "target_field_reads": reads,
            "observed_targets": sorted(
                {target for hit in reads for target in hit["targets"]}
            ),
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
                "set_parameter_signature": report["set_parameter"]["dump_signature"],
                "argument_memory_offsets": report["set_parameter"]["argument_memory_offsets"],
                "set_parameter_observed_targets": report["set_parameter"]["observed_targets"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
