#!/usr/bin/env python3
"""Recover caller-assigned ``Cute.NetworkTask.type`` keys with object provenance.

Some endpoint-specific operations reuse a shared task class and assign ``type`` from
the caller rather than writing a constant in the task constructor.  This pass scans
native method bodies for the exact ``Cute.NetworkTask$$set_type`` call and tracks a
small, conservative AArch64 register provenance domain:

* task-object identity is learned when an object token is passed to a known concrete
  NetworkTask constructor;
* integer constants are tracked through MOV/MOVZ/MOVK/MOVN/ADD-immediate;
* register aliases are tracked through MOV;
* caller-saved state is invalidated across calls;
* constants and untyped aliases are invalidated at control-flow boundaries so a
  branch-linear observation is not silently promoted across divergent paths.

The report is derived metadata only: caller/method RVAs, concrete task names, keys and
setter call sites.  It does not export native bodies.
"""
from __future__ import annotations

import argparse
import bisect
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import (
    ARM64_INS_ADD,
    ARM64_INS_B,
    ARM64_INS_BL,
    ARM64_INS_BLR,
    ARM64_INS_BR,
    ARM64_INS_CBZ,
    ARM64_INS_CBNZ,
    ARM64_INS_MOV,
    ARM64_INS_MOVK,
    ARM64_INS_MOVN,
    ARM64_INS_MOVZ,
    ARM64_INS_RET,
    ARM64_INS_TBZ,
    ARM64_INS_TBNZ,
    ARM64_OP_IMM,
    ARM64_OP_REG,
)
from elftools.elf.elffile import ELFFile

SCHEMA = 1
SETTER_NAME = "Cute.NetworkTask$$set_type"
MAX_KEY = 515
MAX_FUNCTION_SIZE = 0x20000
MAX_OBSERVATIONS = 20000
BRANCH_IDS = {
    ARM64_INS_B,
    ARM64_INS_BR,
    ARM64_INS_CBZ,
    ARM64_INS_CBNZ,
    ARM64_INS_TBZ,
    ARM64_INS_TBNZ,
}


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


def canon_reg(name: str) -> str:
    name = name.lower()
    if len(name) >= 2 and name[0] in {"w", "x"} and name[1:].isdigit():
        return "x" + name[1:]
    return name


def reg_name(md: Cs, operand: Any) -> str:
    return canon_reg(md.reg_name(int(operand.reg)))


def load_methods(path: Path) -> tuple[list[Method], list[int], dict[int, str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    methods: list[Method] = []
    starts: set[int] = set()
    names: dict[int, str] = {}
    for item in raw.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        name = str(item.get("Name", ""))
        methods.append(Method(address, name))
        starts.add(address)
        names.setdefault(address, name)
    for item in raw.get("Addresses", []):
        address = as_int(item)
        if address > 0:
            starts.add(address)
    return methods, sorted(starts), names


def function_end(starts: list[int], address: int) -> int:
    idx = bisect.bisect_right(starts, address)
    end = starts[idx] if idx < len(starts) else address + MAX_FUNCTION_SIZE
    return min(end, address + MAX_FUNCTION_SIZE)


def new_token(counter: list[int]) -> int:
    counter[0] += 1
    return counter[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    task_types = {str(row["type"]) for row in inventory.get("tasks", [])}
    if not task_types:
        raise RuntimeError("empty NetworkTask inventory")

    methods, starts, name_by_address = load_methods(args.script_json)
    setter_matches = [m for m in methods if m.name == SETTER_NAME]
    if len(setter_matches) != 1:
        raise RuntimeError(f"expected one {SETTER_NAME}, got {len(setter_matches)}")
    setter_rva = setter_matches[0].address

    ctor_owner_by_rva: dict[int, str] = {}
    for method in methods:
        if method.owner in task_types and method.member in {".ctor", "ctor"}:
            ctor_owner_by_rva[method.address] = method.owner

    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    view = BinaryView(args.lib)
    observations: list[dict[str, Any]] = []
    try:
        for method in methods:
            if method.address == setter_rva:
                continue
            end = function_end(starts, method.address)
            if end <= method.address:
                continue

            counter = [0]
            token_for_reg = {f"x{i}": new_token(counter) for i in range(31)}
            type_for_token: dict[int, set[str]] = defaultdict(set)
            constants: dict[str, int] = {}
            # A NetworkTask instance method has a statically known `this` object.
            if method.owner in task_types:
                type_for_token[token_for_reg["x0"]].add(method.owner)

            def invalidate(reg: str) -> None:
                constants.pop(reg, None)
                token_for_reg[reg] = new_token(counter)

            def clobber_callers() -> None:
                for i in range(18):
                    reg = f"x{i}"
                    constants.pop(reg, None)
                    token_for_reg[reg] = new_token(counter)

            data = view.read(method.address, end - method.address)
            for ins in md.disasm(data, method.address):
                ops = ins.operands
                if ins.id == ARM64_INS_RET:
                    break

                if ins.id in BRANCH_IDS:
                    # Keep only typed object tokens living in callee-saved registers;
                    # drop branch-sensitive constants and caller-saved aliases.
                    constants.clear()
                    for i in range(18):
                        token_for_reg[f"x{i}"] = new_token(counter)
                    continue

                if ins.id == ARM64_INS_MOV and len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
                    dst = reg_name(md, ops[0])
                    if ops[1].type == ARM64_OP_IMM:
                        constants[dst] = int(ops[1].imm) & 0xFFFFFFFFFFFFFFFF
                        token_for_reg[dst] = new_token(counter)
                    elif ops[1].type == ARM64_OP_REG:
                        src = reg_name(md, ops[1])
                        token_for_reg[dst] = token_for_reg.get(src, new_token(counter))
                        if src in constants:
                            constants[dst] = constants[src]
                        else:
                            constants.pop(dst, None)
                    else:
                        invalidate(dst)
                    continue

                if (
                    ins.id in {ARM64_INS_MOVZ, ARM64_INS_MOVN, ARM64_INS_MOVK}
                    and len(ops) >= 2
                    and ops[0].type == ARM64_OP_REG
                    and ops[1].type == ARM64_OP_IMM
                ):
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
                    token_for_reg[dst] = new_token(counter)
                    continue

                if (
                    ins.id == ARM64_INS_ADD
                    and len(ops) >= 3
                    and ops[0].type == ARM64_OP_REG
                ):
                    dst = reg_name(md, ops[0])
                    if ops[1].type == ARM64_OP_REG and ops[2].type == ARM64_OP_IMM:
                        src = reg_name(md, ops[1])
                        imm = int(ops[2].imm)
                        if src in constants:
                            constants[dst] = constants[src] + imm
                        else:
                            constants.pop(dst, None)
                        if imm == 0:
                            token_for_reg[dst] = token_for_reg.get(src, new_token(counter))
                        else:
                            token_for_reg[dst] = new_token(counter)
                    else:
                        invalidate(dst)
                    continue

                if ins.id == ARM64_INS_BL and ops and ops[0].type == ARM64_OP_IMM:
                    target = int(ops[0].imm)
                    if target in ctor_owner_by_rva:
                        token = token_for_reg.get("x0")
                        if token is not None:
                            type_for_token[token].add(ctor_owner_by_rva[target])
                    elif target == setter_rva:
                        token = token_for_reg.get("x0")
                        key = constants.get("x1")
                        types = sorted(type_for_token.get(token, set())) if token is not None else []
                        if key is not None and 0 <= key <= MAX_KEY and types:
                            observations.append(
                                {
                                    "caller": method.name,
                                    "caller_rva": method.address,
                                    "set_type_call_rva": int(ins.address),
                                    "key": int(key),
                                    "task_types": types,
                                }
                            )
                            if len(observations) > MAX_OBSERVATIONS:
                                raise RuntimeError("unexpectedly many set_type observations")
                    clobber_callers()
                    continue

                if ins.id == ARM64_INS_BLR:
                    clobber_callers()
                    continue

                # Conservative invalidation for instructions that write a register
                # but are not modeled above.
                if ops and ops[0].type == ARM64_OP_REG:
                    mnem = ins.mnemonic.lower()
                    if mnem not in {"cmp", "cmn", "tst"} and not mnem.startswith("b."):
                        invalidate(reg_name(md, ops[0]))
    finally:
        view.close()

    dedup: dict[tuple[str, int, str, int], dict[str, Any]] = {}
    for row in observations:
        for task in row["task_types"]:
            key = (task, row["key"], row["caller"], row["set_type_call_rva"])
            dedup[key] = {
                "task": task,
                "key": row["key"],
                "caller": row["caller"],
                "caller_rva": row["caller_rva"],
                "set_type_call_rva": row["set_type_call_rva"],
                "evidence": "branch-local-object-provenance-to-NetworkTask.set_type",
            }

    rows = sorted(
        dedup.values(),
        key=lambda row: (row["key"], row["task"], row["caller_rva"], row["set_type_call_rva"]),
    )
    by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_key[str(row["key"])].append(row)

    report = {
        "schema": SCHEMA,
        "setter": SETTER_NAME,
        "setter_rva": setter_rva,
        "task_type_count": len(task_types),
        "observation_count": len(rows),
        "key_count": len(by_key),
        "by_key": dict(by_key),
        "observations": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
