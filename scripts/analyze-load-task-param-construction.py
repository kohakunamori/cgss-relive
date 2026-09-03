#!/usr/bin/env python3
"""Bounded exact-specimen analysis of ``Stage.LoadTask.SetParameter`` construction.

Schema 7 established that ``LoadTask`` inherits ``NetworkTask.Params`` at
``this+0x30`` and that SetParameter *writes* that field instead of loading a
child from it. This pass answers the remaining narrow question: what object is
constructed, and how are ``LoadTaskParam.load_state`` / ``next_api`` populated
before it is assigned to ``NetworkTask.Params``?

The report contains only type declarations, the two target field declarations,
method RVAs/names, direct target-offset accesses inside SetParameter, call
targets, and tiny instruction contexts. It never emits bulk disassembly or
runtime/account data.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile

SET_PARAMETER_START = 0x04877A14
PARAMS_OFFSET = 0x30
TARGET_OFFSETS = {0x40: "load_state", 0x50: "next_api"}
CONTEXT_RADIUS = 6
MAX_FUNCTION_SIZE = 0x4000
MAX_CALLS = 96
MAX_TARGET_HITS = 32
MAX_TYPE_BLOCK_LINES = 180

_TYPE_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)?\s*"
    r"(?:(?:sealed|abstract|static|partial)\s+)*"
    r"(?:class|struct)\s+([^\s:{]+)"
)
_RVA_RE = re.compile(r"//\s*RVA:\s*0x([0-9A-Fa-f]+)")
_OFFSET_RE = re.compile(r"//\s*0x([0-9A-Fa-f]+)\s*$")


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.segments: list[tuple[int, int, int, int]] = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
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
                self.stream.seek(offset + relative)
                return self.stream.read(min(size, filesz - relative))
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
    names: dict[int, str] = {}
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address > 0:
            starts.add(address)
            names.setdefault(address, str(item.get("Name", "")))
    for value in data.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    return sorted(starts), names


def next_function_start(starts: list[int], start: int) -> int:
    index = bisect.bisect_right(starts, start)
    if index >= len(starts):
        raise RuntimeError("could not bound SetParameter")
    end = starts[index]
    if end <= start or end - start > MAX_FUNCTION_SIZE:
        raise RuntimeError("unsafe SetParameter bound")
    return end


def type_header(line: str) -> dict[str, Any] | None:
    match = _TYPE_RE.match(line)
    if not match:
        return None
    # Strip the trailing Il2CppDumper comment *before* looking for a base-class
    # colon. Otherwise ``// TypeDefIndex: 123`` is falsely parsed as inheritance.
    tail = line[match.end() :].split("//", 1)[0]
    bases: list[str] = []
    if ":" in tail:
        raw = tail.split(":", 1)[1].split("{", 1)[0].strip()
        if raw:
            bases = [part.strip() for part in raw.split(",") if part.strip()]
    return {"name": match.group(1), "declaration": line.strip(), "bases": bases}


def find_type_blocks(lines: list[str], wanted: str) -> list[tuple[int, int, dict[str, Any]]]:
    blocks: list[tuple[int, int, dict[str, Any]]] = []
    for index, line in enumerate(lines):
        header = type_header(line)
        if header is None or str(header["name"]).rsplit(".", 1)[-1] != wanted:
            continue
        end = min(len(lines), index + MAX_TYPE_BLOCK_LINES)
        for cursor in range(index + 1, end):
            if type_header(lines[cursor]) is not None:
                end = cursor
                break
        blocks.append((index, end, header))
    if not blocks:
        raise RuntimeError(f"dump.cs did not contain type {wanted}")
    return blocks


def summarize_type_block(
    lines: list[str], wanted: str, start: int, end: int, header: dict[str, Any]
) -> dict[str, Any]:
    fields: list[dict[str, Any]] = []
    methods: list[dict[str, Any]] = []
    for index in range(start + 1, end):
        line = lines[index]
        offset_match = _OFFSET_RE.search(line)
        if offset_match:
            offset = int(offset_match.group(1), 16)
            is_target_field = wanted == "LoadTaskParam" and offset in TARGET_OFFSETS
            is_params_field = wanted == "NetworkTask" and offset == PARAMS_OFFSET
            if is_target_field or is_params_field:
                fields.append(
                    {
                        "line": index + 1,
                        "offset": offset,
                        "target": TARGET_OFFSETS.get(offset) if is_target_field else None,
                        "declaration": line.strip(),
                    }
                )
        rva_match = _RVA_RE.search(line)
        if rva_match and index + 1 < end:
            signature = lines[index + 1].strip()
            if ".ctor(" in signature:
                methods.append(
                    {
                        "rva": int(rva_match.group(1), 16),
                        "signature": signature,
                        "line": index + 2,
                    }
                )
    return {
        "line": start + 1,
        "declaration": header["declaration"],
        "bases": header["bases"],
        "selected_fields": fields,
        "constructors": methods,
    }


def summarize_type(
    lines: list[str],
    wanted: str,
    *,
    method_names: dict[int, str] | None = None,
    constructor_name: str | None = None,
) -> dict[str, Any]:
    candidates = [
        summarize_type_block(lines, wanted, start, end, header)
        for start, end, header in find_type_blocks(lines, wanted)
    ]
    if constructor_name is not None:
        if method_names is None:
            raise RuntimeError("constructor disambiguation requires script method names")
        matches = [
            candidate
            for candidate in candidates
            if any(
                method_names.get(int(ctor["rva"])) == constructor_name
                for ctor in candidate["constructors"]
            )
        ]
        if len(matches) != 1:
            raise RuntimeError(
                f"expected one {wanted} block owning {constructor_name}, found {len(matches)}"
            )
        return matches[0]
    if len(candidates) != 1:
        raise RuntimeError(
            f"type name {wanted} is ambiguous ({len(candidates)} blocks); explicit disambiguation required"
        )
    return candidates[0]


def memory_access_kind(mnemonic: str) -> str | None:
    mnemonic = mnemonic.lower()
    if mnemonic.startswith(("ldr", "ldur", "ldp")):
        return "read"
    if mnemonic.startswith(("str", "stur", "stp")):
        return "write"
    return None


def md() -> Cs:
    dis = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    dis.detail = True
    return dis


def context(instructions: list[Any], index: int) -> list[str]:
    lo = max(0, index - CONTEXT_RADIUS)
    hi = min(len(instructions), index + CONTEXT_RADIUS + 1)
    return [
        f"0x{item.address:X}: {item.mnemonic} {item.op_str}" for item in instructions[lo:hi]
    ]


def register_name(dis: Cs, reg: int) -> str:
    name = dis.reg_name(reg)
    if name.startswith("w") and name[1:].isdigit():
        return "x" + name[1:]
    return name


def analyze_set_parameter(
    view: BinaryView,
    start: int,
    end: int,
    method_names: dict[int, str],
    load_task_param_ctor_rvas: set[int],
) -> dict[str, Any]:
    dis = md()
    instructions = list(dis.disasm(view.read(start, end - start), start))
    calls: list[dict[str, Any]] = []
    target_hits: list[dict[str, Any]] = []
    params_assignments: list[dict[str, Any]] = []
    load_task_param_ctor_calls: list[dict[str, Any]] = []
    x20_definitions: list[dict[str, Any]] = []

    for index, ins in enumerate(instructions):
        access = memory_access_kind(ins.mnemonic)
        if access is not None:
            for operand in ins.operands:
                if operand.type != ARM64_OP_MEM:
                    continue
                displacement = int(operand.mem.disp)
                base = register_name(dis, int(operand.mem.base))
                if displacement in TARGET_OFFSETS:
                    target_hits.append(
                        {
                            "site": ins.address,
                            "mnemonic": ins.mnemonic,
                            "access": access,
                            "base": base,
                            "offset": displacement,
                            "target": TARGET_OFFSETS[displacement],
                            "context": context(instructions, index),
                        }
                    )
                if displacement == PARAMS_OFFSET and access == "write":
                    params_assignments.append(
                        {
                            "site": ins.address,
                            "mnemonic": ins.mnemonic,
                            "base": base,
                            "context": context(instructions, index),
                        }
                    )
        if len(target_hits) > MAX_TARGET_HITS:
            raise RuntimeError("unexpectedly many target-offset accesses")

        # Record the small number of x20 definitions because schema 7 showed x20
        # is the value ultimately stored into NetworkTask.Params.
        if ins.operands and ins.operands[0].type == ARM64_OP_REG:
            if register_name(dis, int(ins.operands[0].reg)) == "x20":
                x20_definitions.append(
                    {
                        "site": ins.address,
                        "mnemonic": ins.mnemonic,
                        "op_str": ins.op_str,
                        "context": context(instructions, index),
                    }
                )

        if ins.id == ARM64_INS_BL and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            target = int(ins.operands[0].imm)
            item = {
                "site": ins.address,
                "target": target,
                "resolved_name": method_names.get(target),
            }
            calls.append(item)
            if target in load_task_param_ctor_rvas:
                load_task_param_ctor_calls.append({**item, "context": context(instructions, index)})
            if len(calls) > MAX_CALLS:
                raise RuntimeError("unexpectedly many SetParameter calls")

    return {
        "target_offset_accesses": target_hits,
        "params_assignment_sites": params_assignments,
        "x20_definitions": x20_definitions,
        "load_task_param_ctor_calls": load_task_param_ctor_calls,
        "calls": calls,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    lines = args.dump_cs.read_text(encoding="utf-8", errors="replace").splitlines()
    starts, method_names = load_script(args.script_json)

    # BaseParam is not globally unique in the metadata. Pin the Stage variant by
    # its exact constructor name observed at the SetParameter call site. The
    # other involved type names are unique in the exact specimen and are left
    # unqualified deliberately so a future ambiguity fails closed.
    load_param = summarize_type(lines, "LoadTaskParam")
    base_param = summarize_type(
        lines,
        "BaseParam",
        method_names=method_names,
        constructor_name="Stage.BaseParam$$.ctor",
    )
    post_params = summarize_type(lines, "PostParams")
    network_task = summarize_type(lines, "NetworkTask")

    end = next_function_start(starts, SET_PARAMETER_START)
    ctor_rvas = {int(item["rva"]) for item in load_param["constructors"]}

    view = BinaryView(args.lib)
    try:
        set_parameter = analyze_set_parameter(
            view,
            SET_PARAMETER_START,
            end,
            method_names,
            ctor_rvas,
        )
    finally:
        view.close()

    report = {
        "schema": 4,
        "load_task_param": load_param,
        "base_param": base_param,
        "post_params": post_params,
        "network_task": network_task,
        "set_parameter": {
            "start": SET_PARAMETER_START,
            "end": end,
            "resolved_name": method_names.get(SET_PARAMETER_START),
            **set_parameter,
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
                "load_task_param_bases": load_param["bases"],
                "base_param_bases": base_param["bases"],
                "post_params_bases": post_params["bases"],
                "network_task_bases": network_task["bases"],
                "load_task_param_ctor_rvas": sorted(ctor_rvas),
                "target_offset_access_count": len(set_parameter["target_offset_accesses"]),
                "params_assignment_count": len(set_parameter["params_assignment_sites"]),
                "load_task_param_ctor_call_count": len(set_parameter["load_task_param_ctor_calls"]),
                "call_count": len(set_parameter["calls"]),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
