#!/usr/bin/env python3
"""Resolve the fixed string prefix used by ArcadePhaseBaseTask.ConvertType.

Exact 11.6.3 code loads the first argument to `System.String.Concat` through GOT
slot 0x82455d8.  Resolve that slot through ELF relocations and join the relocation
addend/target against Il2CppDumper `stringliteral.json`.  This turns the final
Lab->Garden enum-name conversion from a naming inference into direct static evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

SCHEMA=1
PREFIX_GOT=0x82455D8


def as_int(v:Any)->int:
    if isinstance(v,int): return v
    if isinstance(v,str): return int(v,0)
    raise TypeError(v)


def literals(path:Path)->list[dict[str,Any]]:
    raw=json.loads(path.read_text(encoding='utf-8'))
    out=[]
    for i,item in enumerate(raw):
        if not isinstance(item,dict): continue
        value=item.get('value',item.get('Value',item.get('string',item.get('String'))))
        addr=item.get('address',item.get('Address'))
        if isinstance(value,str) and addr is not None:
            out.append({'literal_index':i,'value':value,'address':as_int(addr)})
    return out


def relocations(lib:Path)->list[dict[str,Any]]:
    out=[]
    with lib.open('rb') as f:
        elf=ELFFile(f)
        for section in elf.iter_sections():
            if not hasattr(section,'iter_relocations'): continue
            for rel in section.iter_relocations():
                if int(rel['r_offset'])!=PREFIX_GOT: continue
                row={'section':section.name,'offset':int(rel['r_offset']),'type':int(rel['r_info_type'])}
                if rel.is_RELA(): row['addend']=int(rel['r_addend'])
                out.append(row)
    return out


def main()->int:
    p=argparse.ArgumentParser(); p.add_argument('--lib',type=Path,required=True); p.add_argument('--stringliteral-json',type=Path,required=True); p.add_argument('--output',type=Path,required=True); args=p.parse_args()
    lits=literals(args.stringliteral_json); rels=relocations(args.lib)
    if not rels: raise RuntimeError(f'no relocation found for GOT {PREFIX_GOT:#x}')
    addresses={r.get('addend') for r in rels if r.get('addend') is not None}
    exact=[x for x in lits if x['address'] in addresses]
    # Some Unity IL2CPP builds relocate a pointer cell rather than the final string
    # object. Keep exact-value candidates visible for a bounded secondary check.
    named=[x for x in lits if x['value'] in {'Garden','GardenArcade','garden','GardenArcadeRoundStartPhase'}]
    report={'schema':SCHEMA,'prefix_got':PREFIX_GOT,'relocations':rels,'exact_literal_matches':exact,'bounded_named_candidates':named}
    args.output.parent.mkdir(parents=True,exist_ok=True); args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    return 0


if __name__=='__main__': raise SystemExit(main())
