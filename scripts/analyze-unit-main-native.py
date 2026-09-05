#!/usr/bin/env python3
"""Resolve the tiny final-client flow that produces A:19 ``main_unit_id``.

The enclosing caller and bounds were already recovered by the UnitEdit native pass.
This script emits only the 0x4090F0C..0x4090F50 instruction window: GetMainUnit,
the UnitData field load, its scalar conversion and the resulting integer move.
Direct branch targets are replaced with managed names when Il2CppDumper exposes
one. No raw bytes or surrounding function disassembly are emitted.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_B, ARM64_INS_BL, ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

START_RVA = 0x4090F0C
END_RVA = 0x4090F50


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def methods(path: Path) -> dict[int, list[str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    result: dict[int, list[str]] = {}
    for row in raw.get("ScriptMethod", []):
        address = as_int(row.get("Address", 0))
        name = str(row.get("Name") or "")
        if address > 0 and name:
            result.setdefault(address, []).append(name)
    return result


def read_va(path: Path, address: int, size: int) -> bytes:
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            start = int(segment["p_vaddr"])
            filesz = int(segment["p_filesz"])
            if start <= address < start + filesz:
                relative = address - start
                stream.seek(int(segment["p_offset"]) + relative)
                return stream.read(min(size, filesz - relative))
    raise RuntimeError(f"RVA 0x{address:X} not mapped")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    by_rva = methods(args.script_json)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(read_va(args.lib, START_RVA, END_RVA - START_RVA), START_RVA))
    if not insns or insns[0].address != START_RVA:
        raise RuntimeError("main-unit bounded disassembly failed")

    listing: list[str] = []
    named_calls: list[dict[str, Any]] = []
    for ins in insns:
        names: list[str] = []
        target: int | None = None
        if ins.id in (ARM64_INS_BL, ARM64_INS_B) and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            target = int(ins.operands[0].imm)
            names = by_rva.get(target, [])
        if names:
            listing.append(f"0x{ins.address:X}: {ins.mnemonic} {' | '.join(names)}")
            named_calls.append({"site": int(ins.address), "target": target, "names": names})
        else:
            listing.append(f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}")

    report = {
        "schema": 1,
        "target": "unit-edit-main-unit-native",
        "region": {"start": START_RVA, "end": END_RVA, "size": END_RVA - START_RVA},
        "instructions": listing,
        "named_calls": named_calls,
        "evidence_boundary": {
            "bounded_exact_final_native_window": True,
            "runtime_acceptance": False,
            "ui_visible_success": False,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
