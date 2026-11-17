#!/usr/bin/env python3
"""Independently disassemble/reassemble every small-core representative with gputils."""
import argparse,collections,json,subprocess,re
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--artifacts',type=Path,required=True);args=p.parse_args();root=args.artifacts
bin=root/'gputils';oracle=root/'oracle';out=root/'gputils-vectors';out.mkdir(exist_ok=True)
processors={'pic12':'12c508','pic16c5x':'16c54','pic14':'16f84a','pic14-enhanced':'16f1827','pic17':'17c756','pic18':'18f4520'}

def ihex(data):
 lines=[]
 for at in range(0,len(data),16):
  b=data[at:at+16];v=bytes([len(b),at>>8,at&255,0])+b;lines.append(':'+v.hex().upper()+f'{(-sum(v))&255:02X}')
 return '\n'.join(lines+[':00000001FF'])+'\n'
def readhex(p):
 out={}
 for s in p.read_text().splitlines():
  b=bytes.fromhex(s[1:]);n,at,kind=b[0],int.from_bytes(b[1:3],'big'),b[3]
  if kind==0:
   for i,v in enumerate(b[4:4+n]):out[at+i]=v
 return out
cachepath=root/'gputils-vectors.json'
cache={r['id']:r for r in json.loads(cachepath.read_text())}if cachepath.exists()else{}
rows=[]
for req in map(json.loads,(oracle/'requests.jsonl').read_text().splitlines()):
 profile=req.get('profile',req['id'].split('_L')[0])
 if profile not in processors:continue
 proc=processors[profile]
 previous=cache.get(req['id'])
 if previous and previous['bytes']==req['bytes'] and previous['processor']==proc:rows.append(previous);continue
 data=bytes.fromhex(req['bytes']);hexfile=out/'current.hex';hexfile.write_text(ihex(data));cmd=[str(bin/'gputils/gpdasm'),'-s','-p',proc,str(hexfile)]
 if profile=='pic18':cmd.insert(1,'-y')
 dis=subprocess.run(cmd,capture_output=True,text=True);source=out/'current.asm';normalized=dis.stdout
 normalized=re.sub(r'(movsf\s+)(0x[0-9a-f]+)(,)',r'\1[\2]\3',normalized,flags=re.I)
 normalized=re.sub(r'(movss\s+)(0x[0-9a-f]+),\s*(0x[0-9a-f]+)',r'\1[\2],[\3]',normalized,flags=re.I)
 normalized=re.sub(r'addfsr\s+0x3,\s*(0x[0-9a-f]+)',r'addulnk \1',normalized,flags=re.I)
 normalized=re.sub(r'subfsr\s+0x3,\s*(0x[0-9a-f]+)',r'subulnk \1',normalized,flags=re.I)
 source.write_text(normalized+'\n end\n');assembled=out/'assembled.hex' 
 asmcmd=[str(bin/'gpasm/gpasm'),'-I',str(bin/'header'),'-p',proc,'-o',str(assembled),str(source)]
 if profile=='pic18':asmcmd.insert(1,'-y')
 asm=subprocess.run(asmcmd,capture_output=True,text=True)
 row={'id':req['id'],'bytes':req['bytes'],'source':dis.stdout.strip(),'processor':proc,'normalized':normalized.strip()}
 if asm.returncode:row['error']=asm.stdout+asm.stderr
 else:
  actual=readhex(assembled);row['encoded']=''.join(f'{actual.get(i,0):02x}'for i in range(len(data)));row['instruction']=not any(s.strip().lower().startswith('dw ')for s in dis.stdout.splitlines())
 rows.append(row)
(root/'gputils-vectors.json').write_text(json.dumps(rows,indent=2)+'\n')
print('vectors',len(rows),'errors',sum('error'in r for r in rows),'exact',sum(r.get('encoded')==r['bytes']for r in rows),'dw',sum(not r.get('instruction',True)for r in rows))
