#!/usr/bin/env python3
"""Exact-final bounded analysis of WorkFavoriteData.FavoriteData state semantics.

A:22 MemberFavoriteEdit.SetParameter is already proven to copy
``GetUnitSerial(i)`` and ``GetUnitChangeFlag(i)`` into the request's parallel
arrays. This pass closes the remaining integer-flag meaning by inspecting only the
managed type that owns those methods and a bounded set of its state/mutation
methods.

Outputs derived/sanitized metadata and short disassembly only. No raw specimen,
bulk dump, script.json or full callgraph is exported.
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
from capstone.arm64 import ARM64_INS_B, ARM64_INS_BL, ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

TYPE_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)?\s*"
    r"(?:(?:sealed|abstract|static|partial)\s+)*"
    r"(?:class|struct|enum)\s+([^\s:{]+)"
)
RVA_RE = re.compile(r"//\s*RVA:\s*0x([0-9A-Fa-f]+)")
TARGET_TYPE = "WorkFavoriteData.FavoriteData"
TARGET_SCRIPT_PREFIX = "Stage.WorkFavoriteData.FavoriteData$$"
METHOD_HINTS = (
    "ChangeFlag",
    "Favorite",
    "UnitSerial",
    "SetUnit",
    "ResetUnit",
    "ClearUnit",
    "ChangeUnit",
)
MAX_BLOCK_LINES = 500
MAX_METHODS = 100
MAX_NATIVE_METHODS = 32
MAX_FUNCTION_SIZE = 0x1800
MAX_FULL_INSTRUCTIONS = 96
CONTEXT_RADIUS = 5


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: str | None


class BinaryView:
    def __init__(self, path: Path) -> None:
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.loads: list[tuple[int, int, int, int]] = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
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


def as_int(value: Any) -> int:
    return value if isinstance(value, int) else int(str(value), 0)


def managed_type_block(path: Path) -> dict[str, Any]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = None
    declaration = None
    for index, line in enumerate(lines):
        match = TYPE_RE.match(line)
        if match and match.group(1) == TARGET_TYPE:
            start = index
            declaration = line.strip()
            break
    if start is None or declaration is None:
        raise RuntimeError(f"managed type not found: {TARGET_TYPE}")

    end = min(len(lines), start + MAX_BLOCK_LINES)
    for cursor in range(start + 1, end):
        if TYPE_RE.match(lines[cursor]):
            end = cursor
            break

    fields: list[str] = []
    methods: list[dict[str, Any]] = []
    for index in range(start + 1, end):
        stripped = lines[index].strip()
        if ";" in stripped and "(" not in stripped and not stripped.startswith("//"):
            fields.append(stripped)
        match = RVA_RE.search(lines[index])
        if match and index + 1 < end:
            signature = lines[index + 1].strip()
            if "(" in signature:
                methods.append({"rva": int(match.group(1), 16), "signature": signature})
    if len(methods) > MAX_METHODS:
        raise RuntimeError("WorkFavoriteData.FavoriteData method surface unexpectedly large")
    return {
        "type": TARGET_TYPE,
        "declaration": declaration,
        "fields": fields,
        "methods": methods,
    }


def load_script(path: Path) -> tuple[dict[int, list[Method]], list[int], list[Method]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    by_rva: dict[int, list[Method]] = defaultdict(list)
    starts: set[int] = set()
    selected: list[Method] = []
    for row in raw.get("ScriptMethod", []):
        address = as_int(row.get("Address", 0))
        name = str(row.get("Name") or "")
        if address <= 0 or not name:
            continue
        method = Method(address, name, row.get("Signature"))
        by_rva[address].append(method)
        starts.add(address)
        if name.startswith(TARGET_SCRIPT_PREFIX) and any(hint in name for hint in METHOD_HINTS):
            selected.append(method)
    for value in raw.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            starts.add(address)
    dedup: dict[tuple[int, str], Method] = {(m.address, m.name): m for m in selected}
    selected = sorted(dedup.values(), key=lambda m: (m.address, m.name))
    if not selected:
        raise RuntimeError("no targeted WorkFavoriteData.FavoriteData methods found")
    if len(selected) > MAX_NATIVE_METHODS:
        raise RuntimeError(f"targeted favorite-state method surface too large: {len(selected)}")
    return dict(by_rva), sorted(starts), selected


def function_end(starts: list[int], start: int) -> int:
    index = bisect.bisect_right(starts, start)
    if index >= len(starts):
        return start + MAX_FUNCTION_SIZE
    return min(starts[index], start + MAX_FUNCTION_SIZE)


def direct_branch(ins: Any, by_rva: dict[int, list[Method]], *, include_tail: bool = False):
    allowed = (ARM64_INS_BL, ARM64_INS_B) if include_tail else (ARM64_INS_BL,)
    if ins.id not in allowed or not ins.operands or ins.operands[0].type != ARM64_OP_IMM:
        return None
    target = int(ins.operands[0].imm)
    return target, [row.name for row in by_rva.get(target, ())]


def sanitize(ins: Any, by_rva: dict[int, list[Method]]) -> str:
    branch = direct_branch(ins, by_rva, include_tail=True)
    if branch is not None and branch[1]:
        mnemonic = "bl" if ins.id == ARM64_INS_BL else "b"
        return f"0x{ins.address:X}: {mnemonic} {' | '.join(branch[1])}"
    return f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}"


def analyze_native(
    method: Method,
    *,
    view: BinaryView,
    starts: list[int],
    by_rva: dict[int, list[Method]],
) -> dict[str, Any]:
    end = function_end(starts, method.address)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    insns = list(md.disasm(view.read(method.address, end - method.address), method.address))
    calls: list[dict[str, Any]] = []
    for index, ins in enumerate(insns):
        branch = direct_branch(ins, by_rva)
        if branch is None or not branch[1]:
            continue
        lo = max(0, index - CONTEXT_RADIUS)
        hi = min(len(insns), index + CONTEXT_RADIUS + 1)
        calls.append(
            {
                "site": int(ins.address),
                "target": branch[0],
                "names": branch[1],
                "context": [sanitize(row, by_rva) for row in insns[lo:hi]],
            }
        )
    return {
        "name": method.name,
        "rva": method.address,
        "end_rva": end,
        "signature": method.signature,
        "instruction_count": len(insns),
        "full_listing": (
            [sanitize(ins, by_rva) for ins in insns]
            if len(insns) <= MAX_FULL_INSTRUCTIONS
            else []
        ),
        "named_direct_calls": calls,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    managed = managed_type_block(args.dump_cs)
    by_rva, starts, selected = load_script(args.script_json)
    view = BinaryView(args.lib)
    try:
        native = [
            analyze_native(method, view=view, starts=starts, by_rva=by_rva)
            for method in selected
        ]
    finally:
        view.close()

    report = {
        "schema": 1,
        "target": "work-favorite-data-state",
        "managed": managed,
        "native_methods": native,
        "limits": {
            "exact_type_only": TARGET_TYPE,
            "method_name_hints": METHOD_HINTS,
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
