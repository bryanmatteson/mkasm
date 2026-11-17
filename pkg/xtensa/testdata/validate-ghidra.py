#!/usr/bin/env python3
"""Compare source representatives with Ghidra, adapting only its text dialect."""
import pathlib,json,subprocess,sys,re,collections,argparse
p=argparse.ArgumentParser();p.add_argument('artifact',type=pathlib.Path);p.add_argument('--ghidra',type=pathlib.Path,default=pathlib.Path.home()/'Ghidra');a=p.parse_args();cases=[c for c in json.loads((a.artifact/'cases.json').read_text()) if not c['Text'].startswith('{')];requests=[]
for c in cases:
 text=c['Text'];text=re.sub(r'^(lsip|ssip|lsxp|ssxp)\b',lambda m:{'lsip':'lsiu','ssip':'ssiu','lsxp':'lsxu','ssxp':'ssxu'}[m[1]],text)
 text=re.sub(r'^(rsr)\.(176|208) ',lambda m:m[1]+'.'+{'176':'CONFIGID0','208':'CONFIGID1'}[m[2]]+' ',text)
 m=re.fullmatch(r'(rsr|wsr|xsr)\.([^ ]+) (.*)',text)
 if m:text=f'{m[1]} {m[3]}, {m[2].upper()}'
 m=re.fullmatch(r'(rsr|wsr|xsr) ([^,]+), (.*)',text)
 if m:text=f'{m[1]} {m[2]}, {m[3].upper()}'
 m=re.fullmatch(r'(ball|bany|bnall|bnone) ([^,]+), ([^,]+), (.*)',text)
 if m:text=f'{m[1]} {m[4]}, {m[2]}, {m[3]}'
 # Ghidra prints a trailing comma for three reduction branch forms.
 if text.startswith(('bany ','bnall ','bnone ')):text+=','
 m=re.fullmatch(r'(rur|wur)\.([^ ]+) (.*)',text)
 if m:text=f'{m[1]} {m[3]}, {m[2]}'
 m=re.fullmatch(r'(rur|wur) ([^,]+), (.*)',text)
 if m:
  # Named register operands are a text dialect adaptation. For generic forms
  # take the semantic operand supplied to Encode, never derive a native input
  # from the expected output bytes.
  names={'threadptr':231,'fcr':232,'fsr':233,'f64r_lo':234,'f64r_hi':235,'f64s':236}
  ur=names.get(m[3].lower())
  if ur is None:ur=c['Values'].get('ur')
  if ur is not None:text=f'{m[1]} {m[2]}, '+(str(ur) if m[1]=='rur' else names.get(m[3].lower(),m[3]).__str__())
 requests.append({'language':'Xtensa:'+('BE' if c['Architecture']=='xtensaeb' else 'LE')+':32:default','assembly':text,'address':hex(c['Address'])})
req=''.join(json.dumps(r)+'\n' for r in requests);(a.artifact/'ghidra-requests.jsonl').write_text(req)
r=subprocess.run([sys.executable,str(pathlib.Path(__file__).resolve().parents[3]/'scripts/ghidra-codec-oracle.py'),'--ghidra',str(a.ghidra),'--output',str(a.artifact/'ghidra')],input=req,capture_output=True,text=True);(a.artifact/'ghidra-results.jsonl').write_text(r.stdout);(a.artifact/'ghidra.stderr').write_text(r.stderr);r.check_returncode();responses=[json.loads(l) for l in r.stdout.splitlines() if l.startswith('{')];assert len(responses)==len(cases);out=[]
for c,req,r in zip(cases,requests,responses):
 d=dict(c);d['oracle_text']=req['assembly'];d.update(r);d['status']='exact' if r.get('encoded')==c['Bytes'] else 'different' if 'encoded' in r else 'rejected';out.append(d)
(a.artifact/'ghidra-comparison.json').write_text(json.dumps(out,indent=2));print(collections.Counter((x['Architecture'],x['status']) for x in out))
for x in out:
 if x['status']=='different':print(x['ID'],x['Architecture'],x['Text'],x['Bytes'],x['encoded'])
