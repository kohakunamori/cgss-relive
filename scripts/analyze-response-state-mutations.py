#!/usr/bin/env python3
"""C7a: derive high-confidence response-parser -> client-state mutation call edges.

Consumes the sanitized response direct-call graph and C0 endpoint bindings. A call
is promoted only when both the declaring owner is a recognized client state
surface (Work*/LocalData/TempData/Savedata/etc.) and the method has an explicit
mutator verb. Generic collection calls and read-like Get*/get_* calls are
excluded. This is call-edge evidence, not yet direct field-write proof.
"""
from __future__ import annotations
import argparse, json, re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SCHEMA=1
MUTATOR_PREFIXES=(
    'set_','Set','Add','Update','Save','Clear','Reset','Remove','Insert','Replace',
    'Append','Apply','Delete','Create','Init','Initialize','Open','Close','Unlock',
    'Release','Push','Pop','Sub','Use','Consume','Receive','Acquire','Register',
    'Unregister','Change','Edit','Refresh','LoadFrom','SetUp','SlotDataClear',
)
READ_PREFIXES=('get_','Get','Is','Has','Can','Contains','Find','Search','Check','Calc','TryGet','Exists','Count')

def load(path:Path)->dict[str,Any]: return json.loads(path.read_text(encoding='utf-8'))

def split_target(name:str)->tuple[str,str]|None:
    if '$$' not in name:return None
    return tuple(name.split('$$',1))

def state_surface(owner:str)->tuple[str,str]|None:
    if owner.startswith(('System.','UnityEngine.','LitJson.','MessagePack.','Cysharp.')):return None
    low=owner.lower()
    if owner=='Cute.Certification':return 'session-auth',owner
    if 'savedata' in low:return 'persistent-save',owner
    if '.localdata.' in low or owner.startswith('Stage.LocalData.') or owner.startswith('Stage.LocalLiveCommonData'):return 'local-state',owner
    if '.tempdata.' in low or owner.startswith('Stage.TempData.'):return 'temp-state',owner
    simple=owner.rsplit('.',1)[-1]
    if simple.startswith('Work') or re.search(r'(?:^|\.)Work[A-Z][A-Za-z0-9_<>.]*$',owner):return 'work-state',owner
    if owner.startswith(('Stage.WorkDataManager','Stage.WorkDataUtil')):return 'work-state-manager',owner
    if owner.endswith('DataManager') and owner.startswith('Stage.'):return 'state-manager',owner
    return None

def mutator_kind(method:str)->str|None:
    if method.startswith(READ_PREFIXES):return None
    for prefix in MUTATOR_PREFIXES:
        if method.startswith(prefix):
            if prefix=='set_':return 'property-set'
            if prefix in ('Add','Append','Insert','Push','Acquire','Receive','Register'):return 'add-or-register'
            if prefix in ('Remove','Delete','Pop','Sub','Consume','Use','Unregister'):return 'remove-or-consume'
            if prefix in ('Save','LoadFrom'):return 'persist-or-load'
            if prefix in ('Clear','Reset','Init','Initialize','Create'):return 'reset-or-initialize'
            if prefix in ('Open','Close','Unlock','Release'):return 'progression-state'
            return 'set-or-update'
    return None

def endpoint_map(epdoc:dict[str,Any])->dict[str,list[dict[str,Any]]]:
    out:dict[str,list[dict[str,Any]]]=defaultdict(list)
    for ep in epdoc.get('endpoints',[]):
        route=str(ep.get('route') or '')
        if not route:continue
        if not route.startswith('/'):route='/'+route
        for b in ep.get('task_bindings',[]):
            task=str(b.get('task') or '')
            if task:
                out[task].append({'route':route,'enum':ep.get('enum'),'status':ep.get('status'),'group':ep.get('group'),'key':ep.get('key'),'binding_evidence':b.get('evidence')})
    for task in out:out[task].sort(key=lambda x:(x['route'],str(x.get('enum'))))
    return dict(out)

def main()->int:
    p=argparse.ArgumentParser();p.add_argument('--response-call-targets',type=Path,required=True);p.add_argument('--endpoint-contracts',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--markdown-output',type=Path);a=p.parse_args()
    calls=load(a.response_call_targets);eps=endpoint_map(load(a.endpoint_contracts))
    if calls.get('role')!='response':raise RuntimeError('input call graph is not response role')
    edges=[]
    for caller in calls.get('callers',[]):
        task=str(caller.get('task') or '')
        for call in caller.get('calls',[]):
            name=call.get('target_name')
            if not name:continue
            parsed=split_target(str(name))
            if not parsed:continue
            owner,method=parsed
            surface=state_surface(owner);kind=mutator_kind(method)
            if surface is None or kind is None:continue
            category,state_type=surface
            edges.append({'task':task,'parser':caller.get('name'),'parser_rva':int(caller.get('rva',0)),'call_rva':int(call.get('call_rva',0)),'target_rva':int(call.get('target_rva',0)),'target':name,'state_type':state_type,'state_category':category,'operation':method,'mutation_kind':kind,'confidence':'high','endpoint_candidates':eps.get(task,[]),'evidence':'direct BL from response-role parser to recognized state-owner explicit mutator'})
    grouped:dict[tuple[str,str,int,str,int],list[dict[str,Any]]]=defaultdict(list)
    for e in edges:grouped[(e['task'],str(e['parser']),e['parser_rva'],e['target'],e['target_rva'])].append(e)
    relations=[]
    for (task,parser,parser_rva,target,target_rva),rows in sorted(grouped.items()):
        first=rows[0]
        relations.append({'task':task,'parser':parser,'parser_rva':parser_rva,'target':target,'target_rva':target_rva,'state_type':first['state_type'],'state_category':first['state_category'],'operation':first['operation'],'mutation_kind':first['mutation_kind'],'confidence':'high','endpoint_candidates':first['endpoint_candidates'],'call_count':len(rows),'call_rvas':sorted({r['call_rva'] for r in rows}),'evidence':'one or more direct BL edges from response parser to explicit state mutator'})
    bound=sum(bool(r['endpoint_candidates']) for r in relations)
    report={'schema':SCHEMA,'scope':'C7a high-confidence response-parser to client-state mutator call edges; not direct field-write proof','source_schema':calls.get('schema'),'response_parser_count':calls.get('role_method_count'),'mutation_call_site_count':len(edges),'mutation_relation_count':len(relations),'task_with_mutation_count':len({r['task'] for r in relations}),'state_type_count':len({r['state_type'] for r in relations}),'bound_relation_count':bound,'unbound_relation_count':len(relations)-bound,'state_category_counts':dict(sorted(Counter(r['state_category'] for r in relations).items())),'mutation_kind_counts':dict(sorted(Counter(r['mutation_kind'] for r in relations).items())),'relations':relations,'call_sites':edges}
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    if a.markdown_output:
        lines=['# C7a response state mutation graph','','High-confidence direct-call evidence only; this is not yet direct object-field write proof.','',f"- response parsers: **{report['response_parser_count']}**",f"- mutation call sites: **{report['mutation_call_site_count']}**",f"- unique parser→mutator relations: **{report['mutation_relation_count']}**",f"- tasks with mutations: **{report['task_with_mutation_count']}**",f"- state types: **{report['state_type_count']}**",f"- endpoint-bound relations: **{report['bound_relation_count']}**",f"- unbound relations: **{report['unbound_relation_count']}**",'', '## State categories','']
        lines += [f'- `{k}`: **{v}**' for k,v in report['state_category_counts'].items()]
        lines += ['', '## Mutation kinds','']+[f'- `{k}`: **{v}**' for k,v in report['mutation_kind_counts'].items()]
        lines += ['', '## Most frequent state targets','']
        for target,count in Counter(r['target'] for r in edges).most_common(100):lines.append(f'- `{target}`: **{count}** call sites')
        lines.append('');a.markdown_output.parent.mkdir(parents=True,exist_ok=True);a.markdown_output.write_text('\n'.join(lines),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('response_parser_count','mutation_call_site_count','mutation_relation_count','task_with_mutation_count','state_type_count','bound_relation_count','unbound_relation_count','state_category_counts','mutation_kind_counts')},indent=2,sort_keys=True))
    return 0
if __name__=='__main__':raise SystemExit(main())
