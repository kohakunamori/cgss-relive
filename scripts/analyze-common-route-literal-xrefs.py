#!/usr/bin/env python3
"""Trace executable references to every final B-group Common.ApiType route literal.

This is the third independent dead/live check for the 22-entry VR/login surface:
managed declarations, Common.ApiType.ApiList static-field xrefs, and now the route
string literals themselves.  For each B route, join its delivered literal index to
`stringliteral.json`, find ELF RELA slots whose addend is that literal object address,
then locate executable ADRP+LDR references to those slots and map them to managed
ScriptMethods.  Output is bounded derived metadata only.
"""
from __future__ import annotations

import argparse,bisect,json,re,struct
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from capstone import Cs,CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN
from elftools.elf.elffile import ELFFile

SCHEMA=1
MAX_WINDOW=8
MAX_REFS=512
MAX_FUNCTION_SIZE=0x20000

@dataclass(frozen=True)
class Method:
    address:int; name:str

class View:
    def __init__(self,path:Path):
        self.f=path.open('rb');self.elf=ELFFile(self.f);self.loads=[];self.execs=[]
        for s in self.elf.iter_segments():
            if s['p_type']!='PT_LOAD':continue
            row=(int(s['p_vaddr']),int(s['p_memsz']),int(s['p_offset']),int(s['p_filesz']));self.loads.append(row)
            if int(s['p_flags'])&1 and row[3]:self.execs.append((row[0],row[2],row[3]))
    def close(self):self.f.close()
    def read(self,a,n):
        for v,m,o,f in self.loads:
            if v<=a<v+m:
                r=a-v
                if r>=f:return b''
                n=min(n,f-r);self.f.seek(o+r);return self.f.read(n)
        return b''
    def reloc_by_addend(self,addresses:set[int]):
        out=[]
        for sec in self.elf.iter_sections():
            if not hasattr(sec,'iter_relocations'):continue
            for rel in sec.iter_relocations():
                if not rel.is_RELA():continue
                add=int(rel['r_addend'])
                if add in addresses:out.append({'section':sec.name,'slot':int(rel['r_offset']),'addend':add,'type':int(rel['r_info_type'])})
        return out
    def adrp_candidates(self,pages:set[int]):
        out=[]
        for v,o,f in self.execs:
            self.f.seek(o);data=self.f.read(f);limit=len(data)-len(data)%4
            for pos in range(0,limit,4):
                w=struct.unpack_from('<I',data,pos)[0]
                if w&0x9F000000!=0x90000000:continue
                immlo=(w>>29)&3;immhi=(w>>5)&0x7ffff;imm=(immhi<<2)|immlo
                if imm&(1<<20):imm-=1<<21
                pc=v+pos;page=(pc&~0xfff)+(imm<<12)
                if page in pages:out.append((pc,page))
        return out

def as_int(v:Any)->int:
    if isinstance(v,int):return v
    if isinstance(v,str):return int(v,0)
    raise TypeError(v)

def load_methods(path:Path):
    raw=json.loads(path.read_text());ms=[];starts=set()
    for x in raw.get('ScriptMethod',[]):
        a=as_int(x.get('Address',0))
        if a>0:ms.append(Method(a,str(x.get('Name',''))));starts.add(a)
    for x in raw.get('Addresses',[]):
        a=as_int(x)
        if a>0:starts.add(a)
    ms.sort(key=lambda m:(m.address,m.name));return ms,sorted(starts)

def fend(starts,a):
    i=bisect.bisect_right(starts,a);e=starts[i] if i<len(starts) else a+MAX_FUNCTION_SIZE;return min(e,a+MAX_FUNCTION_SIZE)

def containing(ms,starts,rva):
    addrs=[m.address for m in ms];i=bisect.bisect_right(addrs,rva)-1
    if i<0:return []
    start=ms[i].address
    if not(start<=rva<fend(starts,start)):return []
    l=bisect.bisect_left(addrs,start);r=bisect.bisect_right(addrs,start);return ms[l:r]

def load_b_map(path:Path):
    raw=json.loads(path.read_text());rows=[]
    for r in raw['B']:
        rows.append({'enum':str(r[0]),'key':int(r[1]),'route':str(r[2]),'literal_index':int(r[3])})
    return rows

def load_literals(path:Path,indices:set[int]):
    raw=json.loads(path.read_text());out={}
    for i in indices:
        x=raw[i];value=x.get('value',x.get('Value',x.get('string',x.get('String'))));addr=x.get('address',x.get('Address'))
        if not isinstance(value,str) or addr is None:raise RuntimeError(f'literal {i} missing')
        out[i]={'literal_index':i,'value':value,'address':as_int(addr)}
    return out

def exact_slot_refs(view:View,slots:set[int]):
    md=Cs(CS_ARCH_ARM64,CS_MODE_LITTLE_ENDIAN);md.detail=True;pages={s&~0xfff for s in slots};out=[]
    for adrp,page in view.adrp_candidates(pages):
        ins=list(md.disasm(view.read(adrp,4*MAX_WINDOW),adrp))
        if not ins:continue
        base=ins[0].op_str.split(',',1)[0].strip().lower()
        for x in ins[1:]:
            text=x.op_str.replace(' ','').lower()
            for slot in slots:
                if slot&~0xfff!=page:continue
                off=slot&0xfff
                if text.startswith(base+',') and f'[{base},#0x{off:x}]' in text:
                    out.append({'adrp_rva':adrp,'load_rva':int(x.address),'slot':slot});break
            else:continue
            break
        if len(out)>MAX_REFS:raise RuntimeError('too many B route literal refs')
    return out

def main():
    p=argparse.ArgumentParser();p.add_argument('--lib',type=Path,required=True);p.add_argument('--script-json',type=Path,required=True);p.add_argument('--stringliteral-json',type=Path,required=True);p.add_argument('--api-map',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    rows=load_b_map(args.api_map);lits=load_literals(args.stringliteral_json,{r['literal_index'] for r in rows});addr_to_rows=defaultdict(list)
    for r in rows:
        lit=lits[r['literal_index']]
        if lit['value']!=r['route']:raise RuntimeError(f"B route/literal mismatch: {r} vs {lit}")
        addr_to_rows[lit['address']].append(r)
    ms,starts=load_methods(args.script_json);view=View(args.lib)
    try:
        rels=view.reloc_by_addend(set(addr_to_rows));slot_to_add={r['slot']:r['addend'] for r in rels};refs=exact_slot_refs(view,set(slot_to_add));mapped=[];unmapped=[]
        for ref in refs:
            owners=containing(ms,starts,ref['load_rva']);add=slot_to_add[ref['slot']];routes=addr_to_rows[add]
            if not owners:unmapped.append({**ref,'routes':routes})
            for m in owners:mapped.append({**ref,'consumer':m.name,'consumer_rva':m.address,'routes':routes})
    finally:view.close()
    by_key={str(r['key']):[] for r in rows}
    for x in mapped:
        for r in x['routes']:by_key[str(r['key'])].append({'consumer':x['consumer'],'consumer_rva':x['consumer_rva'],'load_rva':x['load_rva'],'slot':x['slot']})
    report={'schema':SCHEMA,'route_count':len(rows),'unique_literal_address_count':len(addr_to_rows),'relocation_count':len(rels),'exact_reference_count':len(refs),'mapped_references':mapped,'unmapped_references':unmapped,'by_key':by_key}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+'\n');return 0
if __name__=='__main__':raise SystemExit(main())
