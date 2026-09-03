#!/usr/bin/env python3
"""Recover the targeted ArcadePhaseBaseTask.ConvertType bridge.

The five Arcade phase tasks are the only exact-name anchors whose constructors
first write ApiType.Load (11) before calling ConvertType and storing its return value
back into NetworkTask.type. This bounded pass records only that bridge function and
the five constructor call sites so the exception can be closed without broad native
body export.
"""
from __future__ import annotations

import argparse
import bisect
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_INS_MOV, ARM64_INS_MOVK, ARM64_INS_MOVN, ARM64_INS_MOVZ, ARM64_OP_IMM, ARM64_OP_REG
from elftools.elf.elffile import ELFFile

SCHEMA = 1
TARGET = "Stage.ArcadePhaseBaseTask$$ConvertType"
TASKS = [
    "Stage.ArcadeRoundStartPhaseTask",
    "Stage.ArcadeCharaTradePhaseTask",
    "Stage.ArcadeCharaDeployPhaseTask",
    "Stage.ArcadeSkillAtBuyingPhaseTask",
    "Stage.ArcadeTradableCharaReloadPhaseTask",
]
MAX_FUNCTION_SIZE = 0x1000
MAX_INSNS = 256


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
        self.segments = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                self.segments.append((int(segment["p_vaddr"]), int(segment["p_memsz"]), int(segment["p_offset"]), int(segment["p_filesz"])))

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


def load_methods(path: Path) -> tuple[list[Method], list[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    methods = []
    starts = set()
    for item in raw.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        methods.append(Method(address, str(item.get("Name", ""))))
        starts.add(address)
    for value in raw.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    return methods, sorted(starts)


def function_end(starts: list[int], address: int) -> int:
    i = bisect.bisect_right(starts, address)
    end = starts[i] if i < len(starts) else address + MAX_FUNCTION_SIZE
    return min(end, address + MAX_FUNCTION_SIZE)


def disasm(view: BinaryView, starts: list[int], method: Method) -> list[dict[str, Any]]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    end = function_end(starts, method.address)
    result = []
    for ins in md.disasm(view.read(method.address, end - method.address), method.address):
        result.append({"rva": int(ins.address), "mnemonic": ins.mnemonic, "op_str": ins.op_str})
        if len(result) >= MAX_INSNS:
            raise RuntimeError("ConvertType unexpectedly large")
    return result


def canon_reg(name: str) -> str:
    name = name.lower()
    if len(name) >= 2 and name[0] in {"w", "x"} and name[1:].isdigit():
        return "x" + name[1:]
    return name


def ctor_call_args(view: BinaryView, starts: list[int], ctor: Method, target: int) -> list[dict[str, Any]]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    end = function_end(starts, ctor.address)
    constants: dict[str, int] = {}
    calls = []
    for ins in md.disasm(view.read(ctor.address, end - ctor.address), ctor.address):
        ops = ins.operands
        if ins.id == ARM64_INS_MOV and len(ops) >= 2 and ops[0].type == ARM64_OP_REG:
            dst = canon_reg(md.reg_name(int(ops[0].reg)))
            if ops[1].type == ARM64_OP_IMM:
                constants[dst] = int(ops[1].imm) & 0xFFFFFFFFFFFFFFFF
            elif ops[1].type == ARM64_OP_REG:
                src = canon_reg(md.reg_name(int(ops[1].reg)))
                if src in constants:
                    constants[dst] = constants[src]
                else:
                    constants.pop(dst, None)
            continue
        if ins.id in {ARM64_INS_MOVZ, ARM64_INS_MOVN, ARM64_INS_MOVK} and len(ops) >= 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_IMM:
            dst = canon_reg(md.reg_name(int(ops[0].reg)))
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
            continue
        if ins.id == ARM64_INS_BL and ops and ops[0].type == ARM64_OP_IMM:
            call_target = int(ops[0].imm)
            if call_target == target:
                args = {reg: value for reg, value in sorted(constants.items()) if reg in {f"x{i}" for i in range(8)} and 0 <= value <= 0xFFFF}
                calls.append({"call_rva": int(ins.address), "small_args": args})
            for i in range(18):
                constants.pop(f"x{i}", None)
    return calls


def find_dump_signature(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    result = []
    for i, line in enumerate(lines):
        if "ConvertType(" not in line:
            continue
        nearby = lines[max(0, i - 2): i + 1]
        for item in nearby:
            text = item.strip()
            if text and ("RVA:" in text or "ConvertType(" in text):
                result.append(text[:300])
    return result[:8]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    methods, starts = load_methods(args.script_json)
    exact = [m for m in methods if m.name == TARGET]
    if len(exact) != 1:
        raise RuntimeError(f"expected one {TARGET}, got {len(exact)}")
    target = exact[0]

    by_owner: dict[str, list[Method]] = {}
    for method in methods:
        by_owner.setdefault(method.owner, []).append(method)

    view = BinaryView(args.lib)
    try:
        target_insns = disasm(view, starts, target)
        constructors = []
        for owner in TASKS:
            ctors = [m for m in by_owner.get(owner, []) if m.member in {".ctor", "ctor"}]
            if len(ctors) != 1:
                raise RuntimeError(f"expected one ctor for {owner}, got {len(ctors)}")
            ctor = ctors[0]
            constructors.append({
                "task": owner,
                "ctor_rva": ctor.address,
                "convert_calls": ctor_call_args(view, starts, ctor, target.address),
            })
    finally:
        view.close()

    report = {
        "schema": SCHEMA,
        "target": TARGET,
        "target_rva": target.address,
        "dump_signature": find_dump_signature(args.dump_cs),
        "instructions": target_insns,
        "constructors": constructors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
