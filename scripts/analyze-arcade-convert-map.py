#!/usr/bin/env python3
"""Recover static evidence for ArcadePhaseBaseTask Lab->Garden API conversion.

`ConvertType` is already proven to receive normal Lab keys 352..360 and to store its
return value into `NetworkTask.type`. This pass inspects only the owning type's
managed declaration block and its own native methods (especially `.cctor`) to find
constant pair initialization / helper calls that can prove the alternate Garden
keys 362..370 without relying on name/path similarity.
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
OWNER = "Stage.ArcadePhaseBaseTask"
MAX_BLOCK_LINES = 1024
MAX_METHODS = 32
MAX_INSNS = 2048
MAX_FUNCTION_SIZE = 0x10000

_NS_RE = re.compile(r"^\s*//\s*Namespace:\s*(.*)\s*$")
_TYPE_RE = re.compile(r"^\s*(?:public|private|internal|protected)?\s*(?:(?:sealed|abstract|static|partial|readonly)\s+)*class\s+([^\s:{]+)")


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: Any = None

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
                if rel >= filesz: return b""
                n = min(size, filesz - rel)
                self.stream.seek(offset + rel)
                return self.stream.read(n)
        return b""


def as_int(value: Any) -> int:
    if isinstance(value, int): return value
    if isinstance(value, str): return int(value, 0)
    raise TypeError(value)


def load_methods(path: Path) -> tuple[list[Method], list[int], dict[int, str]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    methods=[]; starts=set(); names={}
    for item in raw.get("ScriptMethod", []):
        address=as_int(item.get("Address",0))
        if address<=0: continue
        m=Method(address,str(item.get("Name","")),item.get("Signature"))
        methods.append(m); starts.add(address); names.setdefault(address,m.name)
    for item in raw.get("Addresses",[]):
        address=as_int(item)
        if address>0: starts.add(address)
    methods.sort(key=lambda m:(m.address,m.name))
    return methods,sorted(starts),names


def function_end(starts:list[int],address:int)->int:
    i=bisect.bisect_right(starts,address)
    end=starts[i] if i<len(starts) else address+MAX_FUNCTION_SIZE
    return min(end,address+MAX_FUNCTION_SIZE)


def type_block(path:Path)->dict[str,Any]:
    lines=path.read_text(encoding="utf-8",errors="replace").splitlines(); ns=""
    for i,line in enumerate(lines):
        m=_NS_RE.match(line)
        if m: ns=m.group(1).strip(); continue
        t=_TYPE_RE.match(line)
        if not t: continue
        full=f"{ns}.{t.group(1)}" if ns else t.group(1)
        if full!=OWNER: continue
        out=[line.strip()[:500]]; depth=0; opened=False
        for j in range(i+1,min(len(lines),i+1+MAX_BLOCK_LINES)):
            text=lines[j]; s=text.strip(); depth+=text.count("{"); opened=opened or "{" in text
            if s: out.append(s[:500])
            depth-=text.count("}")
            if opened and depth<=0 and s=="}": break
        return {"type":full,"line":i+1,"declarations":out}
    raise RuntimeError(f"{OWNER} not found")


def disasm(view:BinaryView,starts:list[int],method:Method,names:dict[int,str])->dict[str,Any]:
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
    end=function_end(starts,method.address); insns=[]; constants=[]; calls=[]
    for ins in md.disasm(view.read(method.address,end-method.address),method.address):
        row={"rva":int(ins.address),"mnemonic":ins.mnemonic,"op_str":ins.op_str}
        insns.append(row)
        # record API-range immediates appearing textually in this tiny bounded body
        for op in ins.operands:
            if op.type==ARM64_OP_IMM:
                v=int(op.imm)
                if 300<=v<=400:
                    constants.append({"rva":int(ins.address),"value":v,"mnemonic":ins.mnemonic})
        if ins.id==ARM64_INS_BL and ins.operands and ins.operands[0].type==ARM64_OP_IMM:
            target=int(ins.operands[0].imm)
            calls.append({"rva":int(ins.address),"target_rva":target,"target_name":names.get(target)})
        if ins.id==ARM64_INS_RET: break
        if len(insns)>=MAX_INSNS: raise RuntimeError(f"{method.name} unexpectedly large")
    return {"name":method.name,"member":method.member,"rva":method.address,"signature":method.signature,"instructions":insns,"api_range_immediates":constants,"calls":calls}


def main()->int:
    ap=argparse.ArgumentParser(); ap.add_argument("--lib",type=Path,required=True); ap.add_argument("--dump-cs",type=Path,required=True); ap.add_argument("--script-json",type=Path,required=True); ap.add_argument("--output",type=Path,required=True); args=ap.parse_args()
    methods,starts,names=load_methods(args.script_json)
    owner_methods=[m for m in methods if m.owner==OWNER]
    if not owner_methods: raise RuntimeError(f"no methods for {OWNER}")
    if len(owner_methods)>MAX_METHODS: raise RuntimeError(f"too many methods for {OWNER}: {len(owner_methods)}")
    view=BinaryView(args.lib)
    try:
        bodies=[disasm(view,starts,m,names) for m in owner_methods]
    finally:
        view.close()
    report={"schema":SCHEMA,"type_block":type_block(args.dump_cs),"method_count":len(bodies),"methods":bodies}
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return 0


if __name__=="__main__": raise SystemExit(main())
