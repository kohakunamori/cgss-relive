#!/usr/bin/env python3
"""Inventory native BL targets used by C2 request / C3 response methods.

The broad C0 role inventory already fixes the exact method RVAs.  This pass scans
only those bounded bodies and counts named direct-call targets from Il2CppDumper's
`script.json`.  It is an evidence-discovery stage used to identify the actual
PostParams/serialization helpers on the request side and parser/dictionary helpers
on the response side before implementing key-level data-flow.

Only method names/RVAs/call counts are emitted; native bodies remain ephemeral.
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
from capstone.arm64 import ARM64_INS_BL, ARM64_INS_RET, ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

SCHEMA = 1
MAX_FUNCTION_SIZE = 0x20000
MAX_SAMPLES_PER_TARGET = 24
MAX_TARGETS = 10000


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: Any = None


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.loads=[]
        for seg in self.elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            self.loads.append((
                int(seg["p_vaddr"]), int(seg["p_memsz"]),
                int(seg["p_offset"]), int(seg["p_filesz"]),
            ))

    def close(self):
        self.stream.close()

    def read(self, address: int, size: int) -> bytes:
        for vaddr,memsz,offset,filesz in self.loads:
            if vaddr <= address < vaddr+memsz:
                rel=address-vaddr
                if rel >= filesz:
                    return b""
                n=min(size,filesz-rel)
                self.stream.seek(offset+rel)
                return self.stream.read(n)
        return b""


def as_int(value: Any) -> int:
    if isinstance(value,int): return value
    if isinstance(value,str): return int(value,0)
    raise TypeError(value)


def load_script(path: Path):
    raw=json.loads(path.read_text(encoding="utf-8"))
    starts=set(); by_rva={}
    for item in raw.get("ScriptMethod",[]):
        rva=as_int(item.get("Address",0))
        if rva<=0: continue
        by_rva.setdefault(rva,[]).append(Method(rva,str(item.get("Name","")),item.get("Signature")))
        starts.add(rva)
    for value in raw.get("Addresses",[]):
        rva=as_int(value)
        if rva>0: starts.add(rva)
    for rows in by_rva.values(): rows.sort(key=lambda m:m.name)
    return by_rva, sorted(starts)


def function_end(starts:list[int], rva:int)->int:
    i=bisect.bisect_right(starts,rva)
    end=starts[i] if i<len(starts) else rva+MAX_FUNCTION_SIZE
    return min(end,rva+MAX_FUNCTION_SIZE)


def role_methods(inventory:dict[str,Any], role:str):
    rows=[]
    for task in inventory.get("tasks",[]):
        for method in task.get("role_methods",[]):
            if method.get("role")!=role: continue
            rows.append({
                "task":str(task["type"]),
                "name":str(method["name"]),
                "member":str(method["member"]),
                "rva":int(method["rva"]),
                "signature":method.get("signature"),
            })
    return rows


def interesting_family(name:str|None)->str:
    if not name: return "unmapped"
    low=name.lower()
    checks=(
        ("messagepack","messagepack"),
        ("dictionary","dictionary"),
        ("postparam","postparams"),
        ("param","param"),
        ("network","network"),
        ("json","json"),
        ("getint","getint"),
        ("getstring","getstring"),
        ("getbool","getbool"),
        ("tryget","tryget"),
        ("getvalue","getvalue"),
        ("convert","convert"),
    )
    for needle,label in checks:
        if needle in low: return label
    return "other"


def main()->int:
    p=argparse.ArgumentParser()
    p.add_argument("--lib",type=Path,required=True)
    p.add_argument("--script-json",type=Path,required=True)
    p.add_argument("--inventory",type=Path,required=True)
    p.add_argument("--role",choices=["request","response"],required=True)
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()

    inventory=json.loads(args.inventory.read_text(encoding="utf-8"))
    methods=role_methods(inventory,args.role)
    by_rva,starts=load_script(args.script_json)
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True
    view=BinaryView(args.lib)
    stats={}
    caller_rows=[]
    try:
        for method in methods:
            start=method["rva"]; end=function_end(starts,start)
            calls=[]
            for ins in md.disasm(view.read(start,end-start),start):
                if ins.id==ARM64_INS_BL and ins.operands and ins.operands[0].type==ARM64_OP_IMM:
                    target=int(ins.operands[0].imm)
                    names=[m.name for m in by_rva.get(target,[])]
                    if not names: names=[None]
                    for name in names:
                        key=(target,name)
                        stat=stats.setdefault(key,{"target_rva":target,"target_name":name,"count":0,"family":interesting_family(name),"samples":[]})
                        stat["count"]+=1
                        if len(stat["samples"])<MAX_SAMPLES_PER_TARGET:
                            sample={"task":method["task"],"caller":method["name"],"caller_rva":start,"call_rva":int(ins.address)}
                            if sample not in stat["samples"]: stat["samples"].append(sample)
                        calls.append({"call_rva":int(ins.address),"target_rva":target,"target_name":name})
                if ins.id==ARM64_INS_RET: break
            caller_rows.append({**method,"direct_call_count":len(calls),"calls":calls})
    finally:
        view.close()

    if len(stats)>MAX_TARGETS: raise RuntimeError(f"unexpected call target count: {len(stats)}")
    targets=sorted(stats.values(),key=lambda r:(-r["count"],r["target_name"] or "",r["target_rva"]))
    family_counts=defaultdict(int)
    for row in targets: family_counts[row["family"]]+=row["count"]
    report={
        "schema":SCHEMA,
        "role":args.role,
        "role_method_count":len(methods),
        "unique_direct_target_count":len(targets),
        "named_direct_target_count":sum(row["target_name"] is not None for row in targets),
        "total_direct_calls":sum(row["count"] for row in targets),
        "family_call_counts":dict(sorted(family_counts.items(),key=lambda kv:(-kv[1],kv[0]))),
        "targets":targets,
        "callers":caller_rows,
    }
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return 0


if __name__=="__main__":
    raise SystemExit(main())
