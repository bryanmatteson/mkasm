#!/usr/bin/env python3
"""Run complete independent Ghidra source decode/assembly coverage.

PUSHL is tested at its original SLEIGH 0xFA encoding separately from the
hardware 0xEA encoding (Microchip DS39762F p420 and independent gputils).
"""
import argparse,gzip,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--artifacts',type=Path,required=True);p.add_argument('--reuse',action='store_true',help='reuse completed oracle output after inspecting its request identity');a=p.parse_args();root=a.artifacts/'oracle';repo=Path(__file__).resolve().parents[3];oracle=repo/'scripts/ghidra-codec-oracle.py'
requests=[json.loads(x)for x in (root/'requests.jsonl').read_text().splitlines()]
source_requests=[]
for q in requests:
 q=q.copy()
 if q['id']=='pic18_L1831_1':q['bytes']='00fa'
 source_requests.append(q)
(root/'source-requests.jsonl').write_text(''.join(json.dumps(q)+'\n'for q in source_requests))
def run(src,dest):
 if a.reuse and dest.exists():return
 with src.open()as inp,dest.open('w')as out:subprocess.run(['python3',str(oracle),'--output',str(root)],stdin=inp,stdout=out,check=True)
run(root/'source-requests.jsonl',root/'decode.jsonl')
decoded=[json.loads(x)for x in (root/'decode.jsonl').read_text().splitlines()];assert len(requests)==len(decoded)
with (root/'assembly-requests.jsonl').open('w')as f:
 for q,d in zip(source_requests,decoded):
  assert q['id']==d['id'];assert 'error'not in d,(q,d)
  assert d['length']==len(bytes.fromhex(q['bytes'])),(q,d)
  q=q.copy();q['assembly']=d['text'];f.write(json.dumps(q)+'\n')
run(root/'assembly-requests.jsonl',root/'assembly.jsonl')
assembled=[json.loads(x)for x in (root/'assembly.jsonl').read_text().splitlines()];assert len(assembled)==len(requests);rows=[]
for q,source,d,r in zip(requests,source_requests,decoded,assembled):
 assert q['id']==r['id'];row=q.copy();row.update({'text':d['text'],'length':d['length'],'mnemonic':d['mnemonic'],'flow':d['flow']});row['encoded']=r.get('encoded','');row['error']=(r.get('error','').splitlines()or[''])[0]
 if source['bytes']!=q['bytes']:row['source_bytes']=source['bytes']
 rows.append(row)
with gzip.open(repo/'pkg/pic/testdata/ghidra-vectors.json.gz','wt')as f:json.dump(rows,f,separators=(',',':'))
print('Ghidra',len(rows),'source byte matches',sum(r['encoded']==r.get('source_bytes',r['bytes'])for r in rows),'assembler alternatives',sum(bool(r['encoded'])and r['encoded']!=r.get('source_bytes',r['bytes'])for r in rows),'assembler errors',sum(bool(r['error'])for r in rows))
