#!/usr/bin/env python3
"""Inspect the tiny set of final NetworkTasks with non-constant `type` writes.

After exhaustive descendant scanning, only three ordinary tasks remain whose ctor
writes `NetworkTask.type` without a recovered constant: Cute.LoginTask,
Stage.MemberEvolutionTask, and Stage.RoomSettingUpdateTask.  This bounded pass emits
only their type declarations, ctor bodies, and direct ctor caller windows so caller
arguments / constructor semantics can be proven without broad decompiler output.
"""
from __future__ import annotations

import argparse,bisect,json,re,struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from capstone.arm64 import ARM64_INS_BL,ARM64_INS_RET,ARM64_OP_IMM
from elftools.elf.elffile import ELFFile

SCHEMA=1
TARGETS=("Cute.LoginTask","Stage.MemberEvolutionTask","Stage.RoomSettingUpdateTask")
MAX_FUNCTION_SIZE=0x10000; MAX_INSNS=1024; MAX_CALLERS=64; WINDOW_BEFORE=20; WINDOW_AFTER=12
_NS_RE=re.compile(r"^\s*//\s*Namespace:\s*(.*)\s*$")
_TYPE_RE=re.compile(r"^\s*(?:public|private|internal|protected)?\s*(?:(?:sealed|abstract|static|partial|readonly)\s+)*class\s+([^\s:{]+)")

@dataclass(frozen=True)
class Method:
    address:int; name:str; signature:Any=None
    @property
    def owner(self): return self.name.split('$$',1)[0] if '$$' in self.name else ''
    @property
    def member(self): return self.name.split('$$',1)[1] if '$$' in self.name else self.name

class BinaryView:
    def __init__(self,path:Path):
        self.stream=path.open('rb'); self.elf=ELFFile(self.stream); self.loads=[]; self.execs=[]
        for s in self.elf.iter_segments():
            if s['p_type']!='PT_LOAD':continue
            row=(int(s['p_vaddr']),int(s['p_memsz']),int(s['p_offset']),int(s['p_filesz'])); self.loads.append(row)
            if int(s['p_flags'])&1 and row[3]:self.execs.append((row[0],row[2],row[3]))
    def close(self):self.stream.close()
    def read(self,a,n):
        for v,m,o,f in self.loads:
            if v<=a<v+m:
                r=a-v
                if r>=f:return b''
                n=min(n,f-r);self.stream.seek(o+r);return self.stream.read(n)
        return b''
    def find_bl_xrefs(self,targets:set[int]):
        out=[]
        for v,o,f in self.execs:
            self.stream.seek(o);data=self.stream.read(f);limit=len(data)-len(data)%4
            for pos in range(0,limit,4):
                w=struct.unpack_from('<I',data,pos)[0]
                if w&0xFC000000!=0x94000000:continue
                imm=w&0x03FFFFFF
                if imm&0x02000000:imm-=1<<26
                call=v+pos;target=call+(imm<<2)
                if target in targets:
                    out.append((call,target))
                    if len(out)>MAX_CALLERS:raise RuntimeError('too many dynamic ctor xrefs')
        return sorted(out)

def as_int(v):
    if isinstance(v,int):return v
    if isinstance(v,str):return int(v,0)
    raise TypeError(v)

def load_methods(path):
    raw=json.loads(path.read_text());ms=[];starts=set();names={}
    for x in raw.get('ScriptMethod',[]):
        a=as_int(x.get('Address',0))
        if a<=0:continue
        m=Method(a,str(x.get('Name','')),x.get('Signature'));ms.append(m);starts.add(a);names.setdefault(a,m.name)
    for x in raw.get('Addresses',[]):
        a=as_int(x)
        if a>0:starts.add(a)
    ms.sort(key=lambda m:(m.address,m.name));return ms,sorted(starts),names

def fend(starts,a):
    i=bisect.bisect_right(starts,a);e=starts[i] if i<len(starts) else a+MAX_FUNCTION_SIZE;return min(e,a+MAX_FUNCTION_SIZE)

def containing(ms,starts,rva):
    addrs=[m.address for m in ms];i=bisect.bisect_right(addrs,rva)-1
    if i<0:return []
    start=ms[i].address
    if not(start<=rva<fend(starts,start)):return []
    l=bisect.bisect_left(addrs,start);r=bisect.bisect_right(addrs,start);return ms[l:r]

def blocks(path):
    lines=path.read_text(encoding='utf-8',errors='replace').splitlines();ns='';out={}
    for i,line in enumerate(lines):
        n=_NS_RE.match(line)
        if n:ns=n.group(1).strip();continue
        t=_TYPE_RE.match(line)
        if not t:continue
        full=f"{ns}.{t.group(1)}" if ns else t.group(1)
        if full not in TARGETS:continue
        rows=[line.strip()[:500]];depth=0;opened=False
        for j in range(i+1,min(len(lines),i+800)):
            s=lines[j].strip();depth+=lines[j].count('{');opened=opened or '{' in lines[j]
            if s:rows.append(s[:500])
            depth-=lines[j].count('}')
            if opened and depth<=0 and s=='}':break
        out[full]={'line':i+1,'declarations':rows}
    return out

def disasm_method(view,starts,m,names):
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);md.detail=True;out=[];calls=[]
    for ins in md.disasm(view.read(m.address,fend(starts,m.address)-m.address),m.address):
        row={'rva':int(ins.address),'mnemonic':ins.mnemonic,'op_str':ins.op_str};out.append(row)
        if ins.id==ARM64_INS_BL and ins.operands and ins.operands[0].type==ARM64_OP_IMM:
            target=int(ins.operands[0].imm);calls.append({'rva':int(ins.address),'target_rva':target,'target_name':names.get(target)})
        if ins.id==ARM64_INS_RET:break
        if len(out)>=MAX_INSNS:raise RuntimeError(f'large target method {m.name}')
    return {'name':m.name,'rva':m.address,'signature':m.signature,'instructions':out,'calls':calls}

def caller_window(view,starts,m,call_rva,names):
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);md.detail=True
    ins=list(md.disasm(view.read(m.address,fend(starts,m.address)-m.address),m.address))
    idx=next((i for i,x in enumerate(ins) if int(x.address)==call_rva),None)
    if idx is None:return None
    a=max(0,idx-WINDOW_BEFORE);b=min(len(ins),idx+WINDOW_AFTER+1);rows=[]
    for x in ins[a:b]:
        row={'rva':int(x.address),'mnemonic':x.mnemonic,'op_str':x.op_str,'is_ctor_call':int(x.address)==call_rva}
        if x.id==ARM64_INS_BL and x.operands and x.operands[0].type==ARM64_OP_IMM:
            target=int(x.operands[0].imm);row['target_name']=names.get(target);row['target_rva']=target
        rows.append(row)
    return {'caller':m.name,'caller_rva':m.address,'signature':m.signature,'call_rva':call_rva,'window':rows}

def main():
    p=argparse.ArgumentParser();p.add_argument('--lib',type=Path,required=True);p.add_argument('--dump-cs',type=Path,required=True);p.add_argument('--script-json',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    ms,starts,names=load_methods(args.script_json);types=blocks(args.dump_cs)
    ctors={}
    for owner in TARGETS:
        found=[m for m in ms if m.owner==owner and m.member in {'.ctor','ctor'}]
        if len(found)!=1:raise RuntimeError(f'expected one ctor for {owner}, got {len(found)}')
        ctors[owner]=found[0]
    view=BinaryView(args.lib)
    try:
        bodies={owner:disasm_method(view,starts,m,names) for owner,m in ctors.items()}
        xrefs=view.find_bl_xrefs({m.address for m in ctors.values()});target_owner={m.address:o for o,m in ctors.items()};callers={o:[] for o in TARGETS};unmapped=[]
        for call,target in xrefs:
            owners=containing(ms,starts,call)
            if not owners:unmapped.append({'call_rva':call,'target_owner':target_owner[target]})
            for m in owners:
                w=caller_window(view,starts,m,call,names)
                if w:callers[target_owner[target]].append(w)
    finally:view.close()
    report={'schema':SCHEMA,'types':types,'constructors':bodies,'callers':callers,'unmapped_xrefs':unmapped}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+'\n');return 0
if __name__=='__main__':raise SystemExit(main())
