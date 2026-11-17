#!/usr/bin/env python3
"""Assemble every LE representative with GNU gas or LLVM MC and compare ELF bytes."""
import argparse,json,pathlib,re,struct,subprocess,collections,os
p=argparse.ArgumentParser();p.add_argument('artifact',type=pathlib.Path);p.add_argument('--assembler',required=True);p.add_argument('--llvm',action='store_true');p.add_argument('--architecture',choices=['xtensa','xtensaeb'],default='xtensa');p.add_argument('--gnu-config');a=p.parse_args();prefix=('llvm' if a.llvm else 'gnu')+('-be' if a.architecture=='xtensaeb' else '');cs=[c for c in json.loads((a.artifact/'cases.json').read_text()) if c['Architecture']==a.architecture];rejected={}
def write():
 lines=['.text'];line_map={}
 for i,c in enumerate(cs):
  if i in rejected:continue
  text=re.sub(r'0x[0-9a-f]+',lambda m:'.+('+str(int(m[0],16)-c['Address'])+')',c['Text'])
  if a.architecture=='xtensaeb':text=re.sub(r'^rsr\.(176|208) ',lambda m:'rsr.'+{'176':'configid0','208':'configid1'}[m[1]]+' ',text)
  lines+=['.p2align 3',f'.global case{i}',f'case{i}:',text];line_map[len(lines)]=i
 (a.artifact/(prefix+'-corpus.s')).write_text('\n'.join(lines)+'\n');return line_map
for attempt in range(3):
 lm=write();command=[a.assembler,'--no-transform','--no-target-align','--flix','-o',str(a.artifact/(prefix+'-corpus.o')),str(a.artifact/(prefix+'-corpus.s'))];
 if a.llvm:
  source=json.loads((pathlib.Path(__file__).parent/'llvm.json').read_text());features=[v['Name'] for v in source.values() if isinstance(v,dict) and 'SubtargetFeature' in v.get('!superclasses',[]) and v.get('Value')=='true'];command=[a.assembler,'-triple=xtensa','-mcpu=esp32','-mattr='+','.join('+'+f for f in features),'-filetype=obj','-o',str(a.artifact/(prefix+'-corpus.o')),str(a.artifact/(prefix+'-corpus.s'))]
 environment=os.environ.copy()
 if a.gnu_config:environment['XTENSA_GNU_CONFIG']=a.gnu_config
 r=subprocess.run(command,capture_output=True,text=True,env=environment);(a.artifact/f'{prefix}-corpus-{attempt}.stderr').write_text(r.stderr)
 if r.returncode==0:break
 new=0
 for line in r.stderr.splitlines():
  m=re.search(r'-corpus.s:(\d+):(?:\d+:)? (?:Error|error): (.*)',line)
  if m and int(m[1]) in lm:
   i=lm[int(m[1])];rejected[i]=m[2];new+=1
 if not new:raise RuntimeError('no case errors parsed; see retained assembler stderr')
else:raise RuntimeError('assembler still fails after excluding diagnosed representatives')
b=(a.artifact/(prefix+'-corpus.o')).read_bytes();assert b[:5]==b'\x7fELF\x01';assert b[5]==(2 if a.architecture=='xtensaeb' else 1),'reference emitted the wrong byte order';endian='<' if b[5]==1 else '>';shoff=struct.unpack_from(endian+'I',b,32)[0];entsize,num,names=struct.unpack_from(endian+'HHH',b,46);sh=[struct.unpack_from(endian+'10I',b,shoff+i*entsize) for i in range(num)];st=b[sh[names][4]:sh[names][4]+sh[names][5]]
def name(n):return st[n:st.index(b'\0',n)].decode()
textindex=next(i for i,s in enumerate(sh) if name(s[0])=='.text');text=b[sh[textindex][4]:sh[textindex][4]+sh[textindex][5]];syms={}
for s in sh:
 if s[1]!=2:continue
 strings=b[sh[s[6]][4]:sh[s[6]][4]+sh[s[6]][5]]
 for off in range(s[4],s[4]+s[5],s[9]):
  nm,value,size,info,other,section=struct.unpack_from(endian+'IIIBBH',b,off)
  if section==textindex:
   nm=strings[nm:strings.index(b'\0',nm)].decode()
   if nm.startswith('case'):syms[int(nm[4:])]=value
results=[]
for i,c in enumerate(cs):
 d=dict(c)
 if i in rejected:d.update(status='rejected',diagnostic=rejected[i])
 else:
  raw=text[syms[i]:syms[i]+len(bytes.fromhex(c['Bytes']))].hex();d.update(actual=raw,status='exact' if raw==c['Bytes'] else 'different')
 results.append(d)
(a.artifact/(prefix+'-results.json')).write_text(json.dumps(results,indent=2));print(collections.Counter(r['status'] for r in results))
for r in results:
 if r['status']=='different':print(r['ID'],r['Text'],r['Bytes'],r['actual'])
