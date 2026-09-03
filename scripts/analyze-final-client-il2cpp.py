#!/usr/bin/env python3
from __future__ import annotations

import argparse
import bisect
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_INS_BLR, ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

KNOWN_RVAS = {
    "Stage.LoadTask.Parse": 0x04850A94,
    "Stage.SceneManager.ChangeView": 0x0373BD8C,
    "Stage.BootMain.FinishLoad": 0x039C6FBC,
    "Stage.BootMain.Initialize": 0x039C6FDC,
    "Stage.BootMain.ChangeView": 0x039C9960,
    "Stage.BootMain.CallbackOnSuccessLoad": 0x039C9AB4,
    "Stage.BootMain.LastInitialized": 0x039CBA98,
    "Stage.BootMain.<Initialize>d__14.MoveNext": 0x039CE78C,
    "Stage.BootMain.StartConnect": 0x039C9A24,
    "Stage.BootMain.<StartConnect>d__15.MoveNext": 0x039D157C,
    "Cute.Certification.VersionCheckTaskExec": 0x050BF3C8,
    "Cute.VersionCheckTask.Parse": 0x050C5400,
    "Cute.BootNetwork.Update": 0x050C6F8C,
    "Cute.BootNetwork.<SetupNetworkCoroutine>d__11.MoveNext": 0x050C74DC,
    "Stage.ResourcesManager.<GameInitialize>d__85.MoveNext": 0x0374EED8,
}

INTEREST = (
    "Boot", "Version", "Resource", "Manifest", "Download", "Asset", "Scene",
    "LoadTask", "Network", "Certification", "CustomPreference", "Home", "Title",
)


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: str | None


def as_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(f"unsupported address value: {value!r}")


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.segments: list[tuple[int, int, int, int]] = []
        self._exec_ranges: list[tuple[int, bytes]] | None = None
        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            self.segments.append(
                (int(seg["p_vaddr"]), int(seg["p_memsz"]), int(seg["p_offset"]), int(seg["p_filesz"]))
            )

    def close(self) -> None:
        self.stream.close()

    def read(self, rva: int, size: int) -> bytes:
        for vaddr, memsz, off, filesz in self.segments:
            if vaddr <= rva < vaddr + memsz:
                rel = rva - vaddr
                if rel >= filesz:
                    return b""
                n = min(size, filesz - rel)
                self.stream.seek(off + rel)
                return self.stream.read(n)
        return b""

    def exec_ranges(self) -> list[tuple[int, bytes]]:
        if self._exec_ranges is None:
            self._exec_ranges = []
            for seg in self.elf.iter_segments():
                if seg["p_type"] != "PT_LOAD" or not (int(seg["p_flags"]) & 1):
                    continue
                self._exec_ranges.append((int(seg["p_vaddr"]), seg.data()))
        return self._exec_ranges


def load_methods(script_path: Path) -> tuple[list[Method], dict[int, Method], list[int], list[int]]:
    data = json.loads(script_path.read_text(encoding="utf-8"))
    methods: list[Method] = []
    for item in data.get("ScriptMethod", []):
        address = as_int(item.get("Address", 0))
        if address <= 0:
            continue
        methods.append(Method(address, str(item["Name"]), item.get("Signature")))

    by_addr: dict[int, Method] = {}
    for method in methods:
        by_addr.setdefault(method.address, method)
    method_starts = sorted(by_addr)

    function_starts = set(method_starts)
    for value in data.get("Addresses", []):
        address = as_int(value)
        if address > 0:
            function_starts.add(address)
    return methods, by_addr, method_starts, sorted(function_starts)


def method_at(address: int, by_addr: dict[int, Method], method_starts: list[int]) -> Method | None:
    i = bisect.bisect_right(method_starts, address) - 1
    return by_addr.get(method_starts[i]) if i >= 0 else None


def function_bounds(address: int, starts: list[int], max_size: int = 0x10000) -> tuple[int, int]:
    i = bisect.bisect_right(starts, address)
    end = starts[i] if i < len(starts) else address + max_size
    return address, min(end, address + max_size)


def make_disassembler() -> Cs:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def disasm_function(view: BinaryView, address: int, starts: list[int]):
    start, end = function_bounds(address, starts)
    return list(make_disassembler().disasm(view.read(start, end - start), start))


def direct_calls(view: BinaryView, address: int, starts: list[int], by_addr: dict[int, Method]) -> list[dict[str, Any]]:
    calls = []
    for ins in disasm_function(view, address, starts):
        if ins.id == ARM64_INS_BL and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            target = int(ins.operands[0].imm)
            method = by_addr.get(target)
            calls.append({"site": ins.address, "target": target, "name": method.name if method else None})
        elif ins.id == ARM64_INS_BLR:
            calls.append({"site": ins.address, "target": None, "name": "<indirect blr>"})
    return calls


def infer_w1(context: Iterable[Any]) -> int | None:
    for prev in reversed(list(context)):
        ops = prev.op_str.replace(" ", "")
        match = re.match(r"(?:mov|movz)w1,#(0x[0-9a-f]+|\d+)$", ops, re.I)
        if match:
            return int(match.group(1), 0)
    return None


def local_context(view: BinaryView, site: int, before: int = 8):
    start = max(0, site - before * 4)
    blob = view.read(start, (before + 1) * 4)
    return list(make_disassembler().disasm(blob, start))


def build_caller_index(
    view: BinaryView,
    targets: set[int],
    by_addr: dict[int, Method],
    method_starts: list[int],
) -> dict[int, list[dict[str, Any]]]:
    """Find direct ARM64 BL callers using vectorized opcode/imm26 decoding."""
    found: dict[int, list[dict[str, Any]]] = {target: [] for target in targets}
    target_array = np.array(sorted(targets), dtype=np.int64)

    for base, blob in view.exec_ranges():
        usable = len(blob) - (len(blob) % 4)
        if not usable:
            continue
        words = np.frombuffer(memoryview(blob)[:usable], dtype="<u4")
        bl_indices = np.flatnonzero((words & np.uint32(0xFC000000)) == np.uint32(0x94000000))
        if bl_indices.size == 0:
            continue

        imms = (words[bl_indices] & np.uint32(0x03FFFFFF)).astype(np.int64)
        imms = np.where((imms & 0x02000000) != 0, imms - (1 << 26), imms)
        sites = np.int64(base) + bl_indices.astype(np.int64) * 4
        call_targets = sites + (imms << 2)
        matched = np.isin(call_targets, target_array)

        for site, target in zip(sites[matched].tolist(), call_targets[matched].tolist()):
            site = int(site)
            target = int(target)
            parent = method_at(site, by_addr, method_starts)
            context = local_context(view, site)
            previous = [ins for ins in context if ins.address < site]
            found[target].append({
                "site": site,
                "parent": parent.name if parent else None,
                "parent_rva": parent.address if parent else None,
                "inferred_w1": infer_w1(previous),
                "context": [f"0x{ins.address:X}: {ins.mnemonic} {ins.op_str}" for ins in context],
            })
    return found


def dump_method_signature(dump_text: str, rva: int) -> str | None:
    pattern = re.compile(rf"// RVA: 0x0*{rva:X}\b[^\n]*\n([^\n]+)", re.I)
    match = pattern.search(dump_text)
    return match.group(1).strip() if match else None


def enum_candidates(dump_text: str) -> list[dict[str, Any]]:
    out = []
    pattern = re.compile(r"(?:public|private|internal|protected)?\s*enum\s+([\w.<>]+)\s*\{(.*?)\n\}", re.S)
    for match in pattern.finditer(dump_text):
        name, body = match.group(1), match.group(2)
        if not any(key in name.lower() for key in ("view", "scene", "stage", "main")):
            continue
        values: dict[str, int] = {}
        for line in body.splitlines():
            value_match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*[,;]?", line)
            if value_match:
                values[value_match.group(1)] = int(value_match.group(2), 0)
        if 6 in values.values() or 7 in values.values():
            out.append({"enum": name, "values": values})
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--dump-cs", type=Path, required=True)
    parser.add_argument("--script-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    methods, by_addr, method_starts, function_starts = load_methods(args.script_json)
    dump_text = args.dump_cs.read_text(encoding="utf-8", errors="replace")
    view = BinaryView(args.lib)
    try:
        caller_index = build_caller_index(view, set(KNOWN_RVAS.values()), by_addr, method_starts)
        known: dict[str, Any] = {}
        for label, rva in KNOWN_RVAS.items():
            method = by_addr.get(rva)
            known[label] = {
                "rva": rva,
                "resolved_name": method.name if method else None,
                "signature": method.signature if method else None,
                "dump_signature": dump_method_signature(dump_text, rva),
                "calls": direct_calls(view, rva, function_starts, by_addr),
                "callers": caller_index[rva],
            }

        change_calls = known["Stage.SceneManager.ChangeView"]["callers"]
        interesting_edges: dict[str, Any] = {}
        for label, record in known.items():
            edges = [edge for edge in record["calls"] if edge["name"] and any(key in edge["name"] for key in INTEREST)]
            if edges:
                interesting_edges[label] = edges

        report = {
            "schema": 4,
            "method_count": len(methods),
            "known": known,
            "change_view_callsites": change_calls,
            "enum_candidates": enum_candidates(dump_text),
            "interesting_direct_edges": interesting_edges,
        }
    finally:
        view.close()

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    markdown = [
        "# Final 11.6.3 targeted IL2CPP analysis", "",
        "Generated from an ephemeral hash-verified specimen; no game binary is retained.", "",
        "## Known method resolution", "",
    ]
    for label, record in report["known"].items():
        markdown.append(f"- `{label}` @ `0x{record['rva']:X}` → `{record['resolved_name'] or 'unresolved'}`")
        if record["dump_signature"]:
            markdown.append(f"  - dump: `{record['dump_signature']}`")

    markdown += ["", "## SceneManager.ChangeView callsites", ""]
    for call in change_calls:
        markdown.append(f"- `0x{call['site']:X}` in `{call['parent']}`; inferred `w1={call['inferred_w1']}`")
        for line in call["context"]:
            markdown.append(f"  - `{line}`")

    markdown += ["", "## View/scene enum candidates containing 6 or 7", ""]
    for enum in report["enum_candidates"]:
        markdown.append(f"- `{enum['enum']}`: " + ", ".join(f"{key}={value}" for key, value in enum["values"].items()))

    markdown += ["", "## Interesting direct edges from bootstrap seeds", ""]
    for label, edges in report["interesting_direct_edges"].items():
        markdown.append(f"### {label}")
        for edge in edges:
            markdown.append(f"- `0x{edge['site']:X}` → `0x{edge['target']:X}` `{edge['name']}`")

    args.output.with_suffix(".md").write_text("\n".join(markdown) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
