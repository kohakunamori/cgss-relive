#!/usr/bin/env python3
"""Expose the bounded native surface around the final client's Common.ApiType.

The separate 22-entry VR/login route dictionary has no external managed declaration
consumer, so C1 must pivot to native storage/use evidence.  This pass is deliberately
small: it emits the `Common.ApiType` declaration block, its two ScriptMethod entries,
a bounded disassembly of `.cctor`/`.ctor`, and direct BL callers of those methods.
That is enough to identify the static dictionary/type-info storage and select the next
xref target without exporting broad native bodies.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_INS_RET, ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

SCHEMA = 1
OWNER = "Common.ApiType"
CCTOR = "Common.ApiType$$.cctor"
CTOR = "Common.ApiType$$.ctor"
MAX_BLOCK_LINES = 512
MAX_FUNCTION_SIZE = 0x4000
MAX_INSNS = 1024
MAX_CALLERS = 256

_NAMESPACE_RE = re.compile(r"^\s*//\s*Namespace:\s*(.*)\s*$")
_TYPE_RE = re.compile(
    r"^\s*(?:public|private|internal|protected)?\s*"
    r"(?:(?:sealed|abstract|static|partial|readonly)\s+)*class\s+([^\s:{]+)"
)


@dataclass(frozen=True)
class Method:
    address: int
    name: str


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.segments: list[tuple[int, int, int, int]] = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                self.segments.append((
                    int(segment["p_vaddr"]), int(segment["p_memsz"]),
                    int(segment["p_offset"]), int(segment["p_filesz"]),
                ))

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
    methods: list[Method] = []
    starts: set[int] = set()
    for item in raw.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        methods.append(Method(address, str(item.get("Name", ""))))
        starts.add(address)
    for item in raw.get("Addresses", []):
        address = as_int(item)
        if address > 0:
            starts.add(address)
    return methods, sorted(starts)


def function_end(starts: list[int], address: int) -> int:
    i = bisect.bisect_right(starts, address)
    end = starts[i] if i < len(starts) else address + MAX_FUNCTION_SIZE
    return min(end, address + MAX_FUNCTION_SIZE)


def find_type_block(path: Path) -> dict[str, Any]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    namespace = ""
    for i, line in enumerate(lines):
        ns = re.match(r"^\s*//\s*Namespace:\s*(.*)\s*$", line)
        if ns:
            namespace = ns.group(1).strip()
            continue
        match = _TYPE_RE.match(line)
        if not match:
            continue
        full = f"{namespace}.{match.group(1)}" if namespace else match.group(1)
        if full != OWNER:
            continue
        block = [line.strip()[:500]]
        depth = 0
        opened = False
        for j in range(i + 1, min(len(lines), i + 1 + MAX_BLOCK_LINES)):
            text = lines[j]
            depth += text.count("{")
            if "{" in text:
                opened = True
            stripped = text.strip()
            if stripped:
                block.append(stripped[:500])
            depth -= text.count("}")
            if opened and depth <= 0 and stripped == "}":
                break
        return {"type": full, "line": i + 1, "declarations": block}
    raise RuntimeError(f"{OWNER} block not found")


def disassemble(view: BinaryView, starts: list[int], method: Method) -> list[dict[str, Any]]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    end = function_end(starts, method.address)
    result = []
    for ins in md.disasm(view.read(method.address, end - method.address), method.address):
        result.append({"rva": int(ins.address), "mnemonic": ins.mnemonic, "op_str": ins.op_str})
        if ins.id == ARM64_INS_RET:
            break
        if len(result) >= MAX_INSNS:
            raise RuntimeError(f"{method.name} unexpectedly large")
    return result


def scan_direct_callers(
    view: BinaryView,
    methods: list[Method],
    starts: list[int],
    targets: dict[int, str],
) -> list[dict[str, Any]]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    callers = []
    for method in methods:
        if method.address in targets:
            continue
        end = function_end(starts, method.address)
        if end <= method.address:
            continue
        for ins in md.disasm(view.read(method.address, end - method.address), method.address):
            if ins.id != ARM64_INS_BL or not ins.operands or ins.operands[0].type != ARM64_OP_IMM:
                continue
            target = int(ins.operands[0].imm)
            if target not in targets:
                continue
            callers.append({
                "caller": method.name,
                "caller_rva": method.address,
                "call_rva": int(ins.address),
                "target": targets[target],
                "target_rva": target,
            })
            if len(callers) > MAX_CALLERS:
                raise RuntimeError("unexpectedly many Common.ApiType direct callers")
    return sorted(callers, key=lambda row: (row["target_rva"], row["caller_rva"], row["call_rva"]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    methods, starts = load_methods(args.script_json)
    selected = {m.name: m for m in methods if m.name in {CCTOR, CTOR}}
    if set(selected) != {CCTOR, CTOR}:
        raise RuntimeError(f"missing Common.ApiType methods: {selected!r}")

    view = BinaryView(args.lib)
    try:
        bodies = {
            name: {"rva": method.address, "instructions": disassemble(view, starts, method)}
            for name, method in selected.items()
        }
        targets = {method.address: name for name, method in selected.items()}
        callers = scan_direct_callers(view, methods, starts, targets)
    finally:
        view.close()

    report = {
        "schema": SCHEMA,
        "type_block": find_type_block(args.dump_cs),
        "methods": bodies,
        "direct_callers": callers,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
