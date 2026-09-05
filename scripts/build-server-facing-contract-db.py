#!/usr/bin/env python3
"""C6: merge endpoint bindings + C4 request + C5 response contracts.

Produces one endpoint-centric JSON contract model and an equivalent SQLite DB.
All inputs are already sanitized semantic artifacts; no specimen/native files are
needed here.  Multiple task bindings and ambiguous endpoint reuse are preserved.
"""
from __future__ import annotations
import argparse, json, sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SCHEMA=1

def load(path:Path)->dict[str,Any]: return json.loads(path.read_text(encoding='utf-8'))

def endpoint_rows(epdoc):
    rows=[]; taskmap=defaultdict(list)
    for ep in epdoc.get('endpoints',[]):
        route=str(ep.get('route') or '')
        if not route:continue
        if not route.startswith('/'):route='/'+route
        row={'route':route,'enum':ep.get('enum'),'status':ep.get('status'),'group':ep.get('group'),'key':ep.get('key'),
             'task_bindings':[{'task':str(b.get('task') or ''),'evidence':b.get('evidence')} for b in ep.get('task_bindings',[]) if b.get('task')],
             'request_fields':[],'response_fields':[]}
        rows.append(row)
        for b in row['task_bindings']:taskmap[b['task']].append(row)
    return rows,taskmap

def strip_endpoint_candidates(row):
    return {k:v for k,v in row.items() if k!='endpoint_candidates'}

def merge(epdoc,c4,c5):
    endpoints,taskmap=endpoint_rows(epdoc)
    unbound_req=[]; unbound_resp=[]
    for row in c4.get('contracts',[]):
        payload=strip_endpoint_candidates(row); targets=taskmap.get(str(row.get('task')),[])
        if not targets:unbound_req.append(payload)
        for ep in targets:ep['request_fields'].append(payload)
    for row in c5.get('contracts',[]):
        payload=strip_endpoint_candidates(row); targets=taskmap.get(str(row.get('task')),[])
        if not targets:unbound_resp.append(payload)
        for ep in targets:ep['response_fields'].append(payload)
    for ep in endpoints:
        ep['request_fields'].sort(key=lambda x:(str(x.get('task')),str(x.get('field')),int(x.get('store_rva',0))))
        ep['response_fields'].sort(key=lambda x:(str(x.get('task')),str(x.get('field')),int(x.get('method_rva',0))))
    return endpoints,unbound_req,unbound_resp

def create_db(path:Path,report:dict[str,Any]):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():path.unlink()
    db=sqlite3.connect(path)
    try:
        db.executescript('''
        PRAGMA foreign_keys=ON;
        CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE endpoints(id INTEGER PRIMARY KEY, route TEXT NOT NULL, enum TEXT, status TEXT, group_name TEXT, api_key INTEGER);
        CREATE TABLE task_bindings(endpoint_id INTEGER NOT NULL, route TEXT NOT NULL, enum TEXT, task TEXT NOT NULL, evidence TEXT,
          UNIQUE(endpoint_id, task, evidence), FOREIGN KEY(endpoint_id) REFERENCES endpoints(id));
        CREATE TABLE request_fields(id INTEGER PRIMARY KEY, endpoint_id INTEGER, route TEXT, enum TEXT, task TEXT NOT NULL, method TEXT,
          method_rva INTEGER, payload_type TEXT, payload_resolution TEXT, field TEXT NOT NULL, managed_type TEXT,
          field_offset INTEGER, store_rva INTEGER, confidence TEXT, value_provenance_json TEXT, evidence_json TEXT);
        CREATE TABLE response_fields(id INTEGER PRIMARY KEY, endpoint_id INTEGER, route TEXT, enum TEXT, task TEXT NOT NULL, method TEXT,
          method_rva INTEGER, field TEXT NOT NULL, requiredness TEXT, value_types_json TEXT, access_styles_json TEXT,
          access_count INTEGER, evidence_json TEXT);
        CREATE INDEX idx_request_route ON request_fields(route);
        CREATE INDEX idx_request_task ON request_fields(task);
        CREATE INDEX idx_response_route ON response_fields(route);
        CREATE INDEX idx_response_task ON response_fields(task);
        CREATE INDEX idx_response_requiredness ON response_fields(requiredness);
        ''')
        meta={k:report[k] for k in ('schema','endpoint_count','endpoint_with_request_count','endpoint_with_response_count','request_field_binding_count','response_field_binding_count','unbound_request_contract_count','unbound_response_contract_count')}
        db.executemany('INSERT INTO metadata(key,value) VALUES (?,?)',[(k,json.dumps(v,ensure_ascii=False,sort_keys=True)) for k,v in meta.items()])
        for ep in report['endpoints']:
            route,enum=ep['route'],ep.get('enum')
            cur=db.execute('INSERT INTO endpoints(route,enum,status,group_name,api_key) VALUES (?,?,?,?,?)',(route,enum,ep.get('status'),ep.get('group'),ep.get('key')))
            endpoint_id=int(cur.lastrowid)
            for b in ep['task_bindings']:
                db.execute('INSERT OR IGNORE INTO task_bindings(endpoint_id,route,enum,task,evidence) VALUES (?,?,?,?,?)',(endpoint_id,route,enum,b['task'],b.get('evidence')))
            for r in ep['request_fields']:
                db.execute('''INSERT INTO request_fields(endpoint_id,route,enum,task,method,method_rva,payload_type,payload_resolution,field,managed_type,field_offset,store_rva,confidence,value_provenance_json,evidence_json)
                              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(endpoint_id,route,enum,r.get('task'),r.get('method'),r.get('method_rva'),r.get('payload_type'),r.get('payload_resolution'),r.get('field'),r.get('managed_type'),r.get('field_offset'),r.get('store_rva'),r.get('confidence'),json.dumps(r.get('value_provenance',[]),ensure_ascii=False,sort_keys=True),json.dumps(r,ensure_ascii=False,sort_keys=True)))
            for r in ep['response_fields']:
                db.execute('''INSERT INTO response_fields(endpoint_id,route,enum,task,method,method_rva,field,requiredness,value_types_json,access_styles_json,access_count,evidence_json)
                              VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',(endpoint_id,route,enum,r.get('task'),r.get('method'),r.get('method_rva'),r.get('field'),r.get('requiredness'),json.dumps(r.get('value_types',[]),ensure_ascii=False,sort_keys=True),json.dumps(r.get('access_styles',[]),ensure_ascii=False,sort_keys=True),r.get('access_count'),json.dumps(r.get('evidence',[]),ensure_ascii=False,sort_keys=True)))
        # unbound contracts remain queryable with NULL endpoint/route.
        for r in report['unbound_request_contracts']:
            db.execute('''INSERT INTO request_fields(endpoint_id,route,enum,task,method,method_rva,payload_type,payload_resolution,field,managed_type,field_offset,store_rva,confidence,value_provenance_json,evidence_json)
                          VALUES (NULL,NULL,NULL,?,?,?,?,?,?,?,?,?,?,?,?)''',(r.get('task'),r.get('method'),r.get('method_rva'),r.get('payload_type'),r.get('payload_resolution'),r.get('field'),r.get('managed_type'),r.get('field_offset'),r.get('store_rva'),r.get('confidence'),json.dumps(r.get('value_provenance',[]),ensure_ascii=False,sort_keys=True),json.dumps(r,ensure_ascii=False,sort_keys=True)))
        for r in report['unbound_response_contracts']:
            db.execute('''INSERT INTO response_fields(endpoint_id,route,enum,task,method,method_rva,field,requiredness,value_types_json,access_styles_json,access_count,evidence_json)
                          VALUES (NULL,NULL,NULL,?,?,?,?,?,?,?,?,?)''',(r.get('task'),r.get('method'),r.get('method_rva'),r.get('field'),r.get('requiredness'),json.dumps(r.get('value_types',[]),ensure_ascii=False,sort_keys=True),json.dumps(r.get('access_styles',[]),ensure_ascii=False,sort_keys=True),r.get('access_count'),json.dumps(r.get('evidence',[]),ensure_ascii=False,sort_keys=True)))
        db.commit()
        assert db.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        assert db.execute('SELECT COUNT(*) FROM endpoints').fetchone()[0]==report['endpoint_count']
    finally:db.close()

def main():
    p=argparse.ArgumentParser(); p.add_argument('--endpoint-contracts',type=Path,required=True); p.add_argument('--c4',type=Path,required=True); p.add_argument('--c5',type=Path,required=True); p.add_argument('--json-output',type=Path,required=True); p.add_argument('--sqlite-output',type=Path,required=True); p.add_argument('--markdown-output',type=Path); a=p.parse_args()
    epdoc,c4,c5=load(a.endpoint_contracts),load(a.c4),load(a.c5)
    if c4.get('schema')!=1 or c5.get('schema')!=1: raise RuntimeError('unsupported C4/C5 schema')
    endpoints,ur,us=merge(epdoc,c4,c5)
    report={'schema':SCHEMA,'scope':'C6 endpoint-centric server-facing semantic contracts from sanitized C0/C4/C5 evidence',
      'source_endpoint_schema':epdoc.get('schema'),'source_c4_schema':c4.get('schema'),'source_c5_schema':c5.get('schema'),
      'endpoint_count':len(endpoints),'endpoint_with_request_count':sum(bool(x['request_fields']) for x in endpoints),'endpoint_with_response_count':sum(bool(x['response_fields']) for x in endpoints),
      'request_field_binding_count':sum(len(x['request_fields']) for x in endpoints),'response_field_binding_count':sum(len(x['response_fields']) for x in endpoints),
      'unbound_request_contract_count':len(ur),'unbound_response_contract_count':len(us),
      'response_requiredness_counts':dict(sorted(Counter(r.get('requiredness','unknown') for ep in endpoints for r in ep['response_fields']).items())),
      'endpoints':endpoints,'unbound_request_contracts':ur,'unbound_response_contracts':us}
    a.json_output.parent.mkdir(parents=True,exist_ok=True); a.json_output.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+'\n',encoding='utf-8'); create_db(a.sqlite_output,report)
    if a.markdown_output:
      lines=['# C6 server-facing contract DB','',f"- endpoints: **{report['endpoint_count']}**",f"- endpoints with request fields: **{report['endpoint_with_request_count']}**",f"- endpoints with response fields: **{report['endpoint_with_response_count']}**",f"- request field bindings: **{report['request_field_binding_count']}**",f"- response field bindings: **{report['response_field_binding_count']}**",f"- unbound request contracts: **{report['unbound_request_contract_count']}**",f"- unbound response contracts: **{report['unbound_response_contract_count']}**",'', '## Response requiredness bindings','']
      lines += [f'- `{k}`: **{v}**' for k,v in report['response_requiredness_counts'].items()]
      lines += ['', 'SQLite mirrors the endpoint/task/request/response relationship and keeps evidence JSON on each field row.','']
      a.markdown_output.parent.mkdir(parents=True,exist_ok=True); a.markdown_output.write_text('\n'.join(lines),encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('endpoint_count','endpoint_with_request_count','endpoint_with_response_count','request_field_binding_count','response_field_binding_count','unbound_request_contract_count','unbound_response_contract_count','response_requiredness_counts')},indent=2,sort_keys=True))
    return 0
if __name__=='__main__':raise SystemExit(main())
