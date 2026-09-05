#!/usr/bin/env python3
"""Expose the bounded native surface around final 11.6.3 `Common.ApiType`.

The B-group VR/login dictionary has no external managed declaration consumer. This
pass emits the Common.ApiType declaration block, bounded `.cctor`/`.ctor`
disassembly, and exact AArch64 direct-BL xrefs found by scanning executable words.
No broad native method bodies are exported.
"""
from __future__ import annotations

import argparse
import bisect
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_RET
from elftools.elf.elffile import ELFFile

SCHEMA = 2
OWNER = "Common.ApiType"
CCTOR = "Common.ApiType$$.cctor"
CTOR = "Common.ApiType$$.ctor"
MAX_BLOCK_LINES = 512
MAX_FUNCTION_SIZE = 0x4000
MAX_INSNS = 1024
MAX_CALLERS = 256

_TYPE_RE = re.compile(r"^\s*(?:public|private|internal|protected)?\s*(?:(?:sealed|abstract|static|partial|readonly)\s+)*class\s+([^\s:{]+)")
_NAMESPACE_RE = re.compile(r"^\s*//\s*Namespace:\s*(.*)\s*$")


@dataclass(frozen=True)
class Method:
    address: int
    name: str


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.segments: list[tuple[int, int, int, int]] = []
        self.exec_segments: list[tuple[int, int, int]] = []
        for segment in self.elf.iter_segments():
            if segment["p_type"] != "PT_LOAD":
                continue
            vaddr = int(segment["p_vaddr"]); memsz = int(segment["p_memsz"])
            offset = int(segment["p_offset"]); filesz = int(segment["p_filesz"])
            self.segments.append((vaddr, memsz, offset, filesz))
            if int(segment["p_flags"]) & 1 and filesz:
                self.exec_segments.append((vaddr, offset, filesz))

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

    def find_bl_xrefs(self, targets: set[int]) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        for vaddr, offset, filesz in self.exec_segments:
            self.stream.seek(offset)
            data = self.stream.read(filesz)
            limit = len(data) - len(data) % 4
            for pos in range(0, limit, 4):
                word = struct.unpack_from("<I", data, pos)[0]
                if word & 0xFC000000 != 0x94000000:
                    continue
                imm26 = word & 0x03FFFFFF
                if imm26 & 0x02000000:
                    imm26 -= 1 << 26
                call = vaddr + pos
                target = call + (imm26 << 2)
                if target in targets:
                    out.append((call, target))
                    if len(out) > MAX_CALLERS:
                        raise RuntimeError("unexpectedly many Common.ApiType direct BL xrefs")
        return sorted(out)


def as_int(value: Any) -> int:
    if isinstance(value, int): return value
    if isinstance(value, str): return int(value, 0)
    raise TypeError(value)


def load_methods(path: Path) -> tuple[list[Method], list[int]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    methods: list[Method] = []
    starts: set[int] = set()
    for item in raw.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0: continue
        methods.append(Method(address, str(item.get("Name", ""))))
        starts.add(address)
    for item in raw.get("Addresses", []):
        address = as_int(item)
        if address > 0: starts.add(address)
    methods.sort(key=lambda m: (m.address, m.name))
    return methods, sorted(starts)


def function_end(starts: list[int], address: int) -> int:
    i = bisect.bisect_right(starts, address)
    end = starts[i] if i < len(starts) else address + MAX_FUNCTION_SIZE
    return min(end, address + MAX_FUNCTION_SIZE)


def containing_methods(methods: list[Method], starts: list[int], rva: int) -> list[Method]:
    addrs = [m.address for m in methods]
    i = bisect.bisect_right(addrs, rva) - 1
    if i < 0: return []
    start = methods[i].address
    if not (start <= rva < function_end(starts, start)): return []
    l = bisect.bisect_left(addrs, start); r = bisect.bisect_right(addrs, start)
    return methods[l:r]


def find_type_block(path: Path) -> dict[str, Any]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    namespace = ""
    for i, line in enumerate(lines):
        ns = _NAMESPACE_RE.match(line)
        if ns:
            namespace = ns.group(1).strip(); continue
        match = _TYPE_RE.match(line)
        if not match: continue
        full = f"{namespace}.{match.group(1)}" if namespace else match.group(1)
        if full != OWNER: continue
        block = [line.strip()[:500]]
        depth = 0; opened = False
        for j in range(i + 1, min(len(lines), i + 1 + MAX_BLOCK_LINES)):
            text = lines[j]; stripped = text.strip()
            depth += text.count("{"); opened = opened or "{" in text
            if stripped: block.append(stripped[:500])
            depth -= text.count("}")
            if opened and depth <= 0 and stripped == "}": break
        return {"type": full, "line": i + 1, "declarations": block}
    raise RuntimeError(f"{OWNER} block not found")


def disassemble(view: BinaryView, starts: list[int], method: Method) -> list[dict[str, Any]]:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    end = function_end(starts, method.address)
    out = []
    for ins in md.disasm(view.read(method.address, end - method.address), method.address):
        out.append({"rva": int(ins.address), "mnemonic": ins.mnemonic, "op_str": ins.op_str})
        if ins.id == ARM64_INS_RET: break
        if len(out) >= MAX_INSNS: raise RuntimeError(f"{method.name} unexpectedly large")
    return out


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
        bodies = {name: {"rva": m.address, "instructions": disassemble(view, starts, m)} for name, m in selected.items()}
        target_names = {m.address: name for name, m in selected.items()}
        xrefs = view.find_bl_xrefs(set(target_names))
        callers = []
        unmapped = []
        for call_rva, target in xrefs:
            owners = containing_methods(methods, starts, call_rva)
            if not owners:
                unmapped.append({"call_rva": call_rva, "target": target_names[target], "target_rva": target})
            for owner in owners:
                callers.append({"caller": owner.name, "caller_rva": owner.address, "call_rva": call_rva, "target": target_names[target], "target_rva": target})
    finally:
        view.close()

    report = {
        "schema": SCHEMA,
        "type_block": find_type_block(args.dump_cs),
        "methods": bodies,
        "exact_bl_xref_count": len(xrefs),
        "direct_callers": callers,
        "unmapped_bl_xrefs": unmapped,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
