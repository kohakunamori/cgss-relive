#!/usr/bin/env python3
"""Trace native consumers of final 11.6.3 `Common.ApiType.ApiList`.

`Common.ApiType::.cctor` proves the B-group route table is stored in the sole static
field `Dictionary<Common.ApiType.Type,string> ApiList`.  In the exact arm64 specimen
the cctor stores through the Common.ApiType TypeInfo GOT slot at 0x82657d0.  This
pass finds executable `ADRP page(0x82657d0)` + nearby `LDR [...,#0x7d0]` references,
maps them to managed ScriptMethods, and emits only those bounded consumer bodies with
call-target annotations.  The goal is to identify the VR/login URL resolver/factory
without guessing from task names.
"""
from __future__ import annotations

import argparse
import bisect
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL, ARM64_INS_RET, ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

SCHEMA = 1
TYPEINFO_GOT = 0x82657D0
TYPEINFO_PAGE = TYPEINFO_GOT & ~0xFFF
TYPEINFO_PAGE_OFFSET = TYPEINFO_GOT & 0xFFF
MAX_FUNCTION_SIZE = 0x20000
MAX_CONSUMERS = 96
MAX_INSNS_PER_CONSUMER = 2048
MAX_WINDOW = 8


@dataclass(frozen=True)
class Method:
    address: int
    name: str
    signature: Any = None


class BinaryView:
    def __init__(self, path: Path):
        self.stream = path.open("rb")
        self.elf = ELFFile(self.stream)
        self.loads=[]; self.execs=[]
        for seg in self.elf.iter_segments():
            if seg["p_type"]!="PT_LOAD": continue
            row=(int(seg["p_vaddr"]),int(seg["p_memsz"]),int(seg["p_offset"]),int(seg["p_filesz"]))
            self.loads.append(row)
            if int(seg["p_flags"]) & 1 and row[3]: self.execs.append((row[0],row[2],row[3]))

    def close(self): self.stream.close()

    def read(self,address:int,size:int)->bytes:
        for vaddr,memsz,offset,filesz in self.loads:
            if vaddr<=address<vaddr+memsz:
                rel=address-vaddr
                if rel>=filesz:return b""
                n=min(size,filesz-rel); self.stream.seek(offset+rel); return self.stream.read(n)
        return b""

    def find_typeinfo_adrps(self)->list[int]:
        out=[]
        for vaddr,offset,filesz in self.execs:
            self.stream.seek(offset); data=self.stream.read(filesz); limit=len(data)-len(data)%4
            for pos in range(0,limit,4):
                word=struct.unpack_from('<I',data,pos)[0]
                if word & 0x9F000000 != 0x90000000: continue
                immlo=(word>>29)&0x3; immhi=(word>>5)&0x7FFFF
                imm=(immhi<<2)|immlo
                if imm & (1<<20): imm-=1<<21
                pc=vaddr+pos; target=(pc & ~0xFFF)+(imm<<12)
                if target==TYPEINFO_PAGE: out.append(pc)
        return out


def as_int(v:Any)->int:
    if isinstance(v,int):return v
    if isinstance(v,str):return int(v,0)
    raise TypeError(v)


def load_methods(path:Path)->tuple[list[Method],list[int],dict[int,str]]:
    raw=json.loads(path.read_text(encoding='utf-8')); ms=[]; starts=set(); names={}
    for item in raw.get('ScriptMethod',[]):
        a=as_int(item.get('Address',0))
        if a<=0:continue
        m=Method(a,str(item.get('Name','')),item.get('Signature')); ms.append(m); starts.add(a); names.setdefault(a,m.name)
    for v in raw.get('Addresses',[]):
        a=as_int(v)
        if a>0:starts.add(a)
    ms.sort(key=lambda m:(m.address,m.name)); return ms,sorted(starts),names


def function_end(starts:list[int],a:int)->int:
    i=bisect.bisect_right(starts,a); e=starts[i] if i<len(starts) else a+MAX_FUNCTION_SIZE; return min(e,a+MAX_FUNCTION_SIZE)


def containing_methods(methods:list[Method],starts:list[int],rva:int)->list[Method]:
    addrs=[m.address for m in methods]; i=bisect.bisect_right(addrs,rva)-1
    if i<0:return []
    start=methods[i].address
    if not(start<=rva<function_end(starts,start)):return []
    l=bisect.bisect_left(addrs,start); r=bisect.bisect_right(addrs,start); return methods[l:r]


def exact_refs(view:BinaryView)->list[dict[str,int]]:
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True; refs=[]
    for adrp in view.find_typeinfo_adrps():
        insns=list(md.disasm(view.read(adrp,4*MAX_WINDOW),adrp))
        if not insns:continue
        base=insns[0].op_str.split(',',1)[0].strip()
        for ins in insns[1:]:
            text=ins.op_str.replace(' ','').lower()
            if text.startswith(base.lower()+',') and f'[{base.lower()},#0x{TYPEINFO_PAGE_OFFSET:x}]' in text:
                refs.append({'adrp_rva':adrp,'load_rva':int(ins.address)})
                break
    return refs


def disasm_consumer(view:BinaryView,starts:list[int],method:Method,names:dict[int,str],ref_rvas:set[int])->dict[str,Any]:
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN); md.detail=True; end=function_end(starts,method.address)
    insns=[]; calls=[]; small_imms=[]
    for ins in md.disasm(view.read(method.address,end-method.address),method.address):
        insns.append({'rva':int(ins.address),'mnemonic':ins.mnemonic,'op_str':ins.op_str,'is_apilist_ref':int(ins.address) in ref_rvas})
        for op in ins.operands:
            if op.type==ARM64_OP_IMM:
                value=int(op.imm)
                if 0<=value<=64: small_imms.append({'rva':int(ins.address),'value':value,'mnemonic':ins.mnemonic})
        if ins.id==ARM64_INS_BL and ins.operands and ins.operands[0].type==ARM64_OP_IMM:
            target=int(ins.operands[0].imm); calls.append({'rva':int(ins.address),'target_rva':target,'target_name':names.get(target)})
        if ins.id==ARM64_INS_RET:break
        if len(insns)>=MAX_INSNS_PER_CONSUMER:raise RuntimeError(f'consumer too large: {method.name}')
    return {'name':method.name,'rva':method.address,'signature':method.signature,'instructions':insns,'calls':calls,'small_immediates':small_imms}


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument('--lib',type=Path,required=True); p.add_argument('--script-json',type=Path,required=True); p.add_argument('--output',type=Path,required=True); args=p.parse_args()
    methods,starts,names=load_methods(args.script_json); view=BinaryView(args.lib)
    try:
        refs=exact_refs(view); owners={}; unmapped=[]
        for ref in refs:
            ms=containing_methods(methods,starts,ref['load_rva'])
            if not ms:unmapped.append(ref)
            for m in ms: owners[(m.address,m.name)]=m
        if len(owners)>MAX_CONSUMERS:raise RuntimeError(f'too many Common.ApiList consumers: {len(owners)}')
        refset={x['adrp_rva'] for x in refs}|{x['load_rva'] for x in refs}
        consumers=[disasm_consumer(view,starts,m,names,refset) for m in owners.values()]
    finally:view.close()
    report={'schema':SCHEMA,'typeinfo_got':TYPEINFO_GOT,'exact_reference_count':len(refs),'references':refs,'consumer_method_count':len(consumers),'consumers':consumers,'unmapped_references':unmapped}
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8'); return 0


if __name__=='__main__':raise SystemExit(main())
