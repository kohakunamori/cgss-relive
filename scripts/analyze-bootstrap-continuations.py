#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

WINDOWS = {
    "Stage.ResourcesManager.<GameInitialize>d__85.MoveNext": (0x0374ED34, 0x350),
    "Stage.BootMain.<Initialize>d__14.MoveNext": (0x039CE78C, 0x3C0),
    "Cute.Certification.<Login>d__42.MoveNext": (0x050BEDEC, 0x5E0),
    "Cute.Certification.<VersionCheckTaskExec>d__43.MoveNext": (0x050BF3C8, 0x8C0),
    "Cute.BootNetwork.<SetupNetworkCoroutine>d__11.MoveNext": (0x050C74DC, 0xE0),
    "Cute.AssetManager.<InitializeManifest>d__65.MoveNext.prefix": (0x050B0E9C, 0x4C0),
}

MARKERS = {
    0x050C6C84: "Cute.BootNetwork.SetupNetwork",
    0x050A9000: "Cute.AssetManager.InitializeManifest",
    0x039C9A24: "Stage.BootMain.StartConnect",
    0x050BDD9C: "Cute.Certification.Login",
    0x050BDE1C: "Cute.Certification.VersionCheckTaskExec",
    0x050B38F8: "Cute.NetworkManager.Connect",
    0x050A8EC4: "Cute.AssetManager.DownloadOrLoadForInitialize",
}


def make_md() -> Cs:
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.segments = []
        for seg in self.elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                self.segments.append(
                    (int(seg["p_vaddr"]), int(seg["p_memsz"]), int(seg["p_offset"]), int(seg["p_filesz"]))
                )

    def close(self) -> None:
        self.stream.close()

    def read(self, rva: int, size: int) -> bytes:
        for vaddr, memsz, offset, filesz in self.segments:
            if vaddr <= rva < vaddr + memsz:
                rel = rva - vaddr
                if rel >= filesz:
                    return b""
                n = min(size, filesz - rel)
                self.stream.seek(offset + rel)
                return self.stream.read(n)
        return b""


def analyze_window(view: BinaryView, rva: int, size: int) -> dict[str, Any]:
    insns = list(make_md().disasm(view.read(rva, size), rva))
    lines = []
    marker_calls = []
    for ins in insns:
        target = None
        marker = None
        if ins.id == ARM64_INS_BL and ins.operands and ins.operands[0].type == ARM64_OP_IMM:
            target = int(ins.operands[0].imm)
            marker = MARKERS.get(target)
            if marker:
                marker_calls.append({"site": ins.address, "target": target, "marker": marker})
        lines.append(
            {
                "address": ins.address,
                "mnemonic": ins.mnemonic,
                "op_str": ins.op_str,
                **({"call_target": target} if target is not None else {}),
                **({"marker": marker} if marker is not None else {}),
            }
        )
    return {"rva": rva, "size": size, "marker_calls": marker_calls, "instructions": lines}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    view = BinaryView(args.lib)
    try:
        windows = {name: analyze_window(view, rva, size) for name, (rva, size) in WINDOWS.items()}
    finally:
        view.close()

    report = {"schema": 1, "windows": windows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    md = [
        "# Final 11.6.3 bootstrap continuation windows",
        "",
        "These are deliberately bounded instruction windows from the exact hash-verified specimen.",
        "No APK, ELF, metadata, bulk dump, or secret material is retained.",
    ]
    for name, window in windows.items():
        md += ["", f"## {name}", ""]
        for call in window["marker_calls"]:
            md.append(f"- marker: `0x{call['site']:X}` → `{call['marker']}`")
        md.append("")
        for ins in window["instructions"]:
            suffix = f"  // {ins['marker']}" if ins.get("marker") else ""
            md.append(f"- `0x{ins['address']:X}: {ins['mnemonic']} {ins['op_str']}`{suffix}")
    args.output.with_suffix(".md").write_text("\n".join(md) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
