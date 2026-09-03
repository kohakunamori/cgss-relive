#!/usr/bin/env python3
"""Resolve exact constant-pool values used by the remaining dynamic NetworkTask ctors.

Final 11.6.3 arm64 uses `ldr d0, [page,#off]; str d0,[this,#0x50]` in
MemberEvolutionTask and RoomSettingUpdateTask, atomically initializing the ApiType
field at +0x50 and the next 32-bit field at +0x54.  Read those exact virtual
addresses from the ELF and expose the two little-endian dwords as sanitized derived
metadata.
"""
from __future__ import annotations

import argparse,json,struct
from pathlib import Path
from elftools.elf.elffile import ELFFile

SCHEMA=1
TARGETS={
    "Stage.MemberEvolutionTask": 0x163D548,
    "Stage.RoomSettingUpdateTask": 0x163D810,
}

class View:
    def __init__(self,path:Path):
        self.f=path.open('rb'); self.elf=ELFFile(self.f); self.loads=[]
        for s in self.elf.iter_segments():
            if s['p_type']=='PT_LOAD':
                self.loads.append((int(s['p_vaddr']),int(s['p_memsz']),int(s['p_offset']),int(s['p_filesz'])))
    def close(self): self.f.close()
    def read(self,a,n):
        for v,m,o,f in self.loads:
            if v<=a<v+m:
                r=a-v
                if r+n>f: raise RuntimeError(f'read crosses file-backed segment at {a:#x}')
                self.f.seek(o+r); return self.f.read(n)
        raise RuntimeError(f'VA not mapped: {a:#x}')

def main()->int:
    p=argparse.ArgumentParser();p.add_argument('--lib',type=Path,required=True);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    view=View(args.lib); rows={}
    try:
        for name,va in TARGETS.items():
            raw=view.read(va,8); low,high=struct.unpack('<II',raw)
            rows[name]={"constant_va":va,"raw_u64":struct.unpack('<Q',raw)[0],"type_key_dword":low,"next_field_dword":high}
    finally:view.close()
    report={"schema":SCHEMA,"targets":rows}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');return 0
if __name__=='__main__':raise SystemExit(main())
