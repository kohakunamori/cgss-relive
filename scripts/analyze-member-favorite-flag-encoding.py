#!/usr/bin/env python3
"""Bounded exact-final proof for A:22 favorite/edit change_flags wire encoding.

The broader favorite pass already proves that MemberFavoriteEditTask.SetParameter()
reads WorkFavoriteData.FavoriteData.GetUnitChangeFlag(index), while managed metadata
proves the request DTO field is int[] change_flags.  This pass exports only a tiny
sanitized native slice beginning at that getter call and ending shortly after the
conversion/store sequence.  It is intentionally not a general disassembler.
"""
from __future__ import annotations

import argparse
import bisect
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

TASK_SUFFIX = "MemberFavoriteEditTask$$SetParameter"
GETTER_SUFFIX = "WorkFavoriteData.FavoriteData$$GetUnitChangeFlag"
BOOL_IMPLICIT_SUFFIX = "ObscuredBool$$op_Implicit"
MAX_TASK_SIZE = 0x1000
SLICE_AFTER_GETTER = 40


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: str | None


def as_int(value: Any) -> int:
    return value if isinstance(value, int) else int(str(value), 0)


def load_methods(path: Path) -> tuple[dict[int, list[Method]], list[int], Method, Method, Method]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    by_rva: dict[int, list[Method]] = {}
    starts: set[int] = set()
    task = getter = implicit = None
    for row in raw.get("ScriptMethod", []):
        address = as_int(row.get("Address", 0))
        name = str(row.get("Name") or "")
        if address <= 0 or not name:
            continue
        method = Method(address, name, row.get("Signature"))
        by_rva.setdefault(address, []).append(method)
        starts.add(address)
        if name.endswith(TASK_SUFFIX):
            task = method
        elif name.endswith(GETTER_SUFFIX):
            getter = method
        elif name.endswith(BOOL_IMPLICIT_SUFFIX):
            implicit = method
    for value in raw.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    if task is None or getter is None or implicit is None:
        raise RuntimeError(
            f"required methods missing: task={task is not None} getter={getter is not None} "
            f"implicit={implicit is not None}"
        )
    return by_rva, sorted(starts), task, getter, implicit


class BinaryView:
    def __init__(self, path: Path) -> None:
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.loads: list[tuple[int, int, int, int]] = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                self.loads.append(
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
        for vaddr, memsz, offset, filesz in self.loads:
            if vaddr <= address < vaddr + memsz:
                rel = address - vaddr
                if rel >= filesz:
                    return b""
                self.stream.seek(offset + rel)
                return self.stream.read(min(size, filesz - rel))
        return b""


def function_end(starts: list[int], start: int) -> int:
    index = bisect.bisect_right(starts, start)
    if index >= len(starts):
        return start + MAX_TASK_SIZE
    return min(starts[index], start + MAX_TASK_SIZE)


def disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def direct_target(ins: Any) -> int | None:
    if ins.id != ARM64_INS_BL or not ins.operands or ins.operands[0].type != ARM64_OP_IMM:
        return None
    return int(ins.operands[0].imm)


def sanitize(ins: Any, by_rva: dict[int, list[Method]]) -> str:
    target = direct_target(ins)
    if target is not None and target in by_rva:
        return f"0x{ins.address:X}: bl {' | '.join(row.name for row in by_rva[target])}"
    return f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    by_rva, starts, task, getter, implicit = load_methods(args.script_json)
    view = BinaryView(args.lib)
    try:
        end = function_end(starts, task.address)
        insns = list(disassembler().disasm(view.read(task.address, end - task.address), task.address))
    finally:
        view.close()

    getter_index = next(
        (i for i, ins in enumerate(insns) if direct_target(ins) == getter.address),
        None,
    )
    if getter_index is None:
        raise RuntimeError("A:22 SetParameter does not directly call GetUnitChangeFlag")
    selected = insns[getter_index : min(len(insns), getter_index + SLICE_AFTER_GETTER)]
    implicit_indexes = [
        i for i, ins in enumerate(selected) if direct_target(ins) == implicit.address
    ]
    if not implicit_indexes:
        raise RuntimeError("bounded A:22 flag slice does not call ObscuredBool.op_Implicit")

    implicit_index = implicit_indexes[0]
    stores_after_implicit = [
        ins for ins in selected[implicit_index + 1 :] if ins.mnemonic == "str" and ins.op_str.startswith("w")
    ]
    if not stores_after_implicit:
        raise RuntimeError("bounded A:22 flag slice has no 32-bit store after bool conversion")

    report = {
        "schema": 1,
        "target": "A:22 MemberFavoriteEdit change_flags encoding",
        "task": {"name": task.name, "rva": task.address},
        "getter": {"name": getter.name, "rva": getter.address},
        "bool_conversion": {"name": implicit.name, "rva": implicit.address},
        "slice": [sanitize(ins, by_rva) for ins in selected],
        "first_32bit_store_after_conversion": sanitize(stores_after_implicit[0], by_rva),
        "limits": {
            "bounded_to_A22_SetParameter": True,
            "slice_instructions": len(selected),
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
