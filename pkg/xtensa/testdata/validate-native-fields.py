#!/usr/bin/env python3
"""Check optional BE formats with independent native vendor field functions.

The input instruction is the independently assembled LE reference, never mkasm's
expected bytes. No fallback is permitted unless a native LE assembler covered
that exact source/operand sample. Supported supplemental formats are explicit.
"""
import argparse,collections,ctypes,json,pathlib
p=argparse.ArgumentParser(description=__doc__);p.add_argument('artifact',type=pathlib.Path);p.add_argument('--library',required=True);a=p.parse_args()
native=ctypes.CDLL(a.library)
for name in ('reference_le_fields','reference_be_fields'):
 getattr(native,name).argtypes=[ctypes.c_uint,ctypes.POINTER(ctypes.c_uint),ctypes.c_int]
rows=json.loads((a.artifact/'cases.json').read_text())
independent={}
for file in ('gnu-results.json','llvm-results.json'):
 for row in json.loads((a.artifact/file).read_text()):
  if row['status']=='exact':independent[(row['ID'],row['Seed'])]=row
fp={'ADDEXPM_S','ADDEXP_S','CONST_S','DIV0_S','DIVN_S','MADDN_S','MKDADJ_S','MKSADJ_S','NEXP01_S','RECIP0_S','RSQRT0_S','SQRT0_S'}
results=[]
for row in rows:
 if row['Architecture']!='xtensaeb':continue
 mnemonic=row['Text'].split()[0]
 if row['ID'] in fp:format=0
 elif mnemonic in ('lsip','ssip'):format=1
 elif mnemonic=='wur' or mnemonic.startswith('wur.'):format=2
 elif mnemonic=='rur' or mnemonic.startswith('rur.'):format=3
 else:continue
 reference=independent[(row['ID'],row['Seed'])]
 raw=bytes.fromhex(reference['actual']);assert len(raw)==3
 fields=(ctypes.c_uint*10)()
 native.reference_le_fields(int.from_bytes(raw,'little'),fields,format)
 native.reference_be_fields(0,fields,format)
 encoded=fields[9].to_bytes(3,'big').hex()
 results.append(dict(row,actual=encoded,status='exact' if encoded==row['Bytes'] else 'different',reference='native LE assembler + vendor BE format fields'))
(a.artifact/'native-fields-results.json').write_text(json.dumps(results,indent=2))
print(collections.Counter(r['status'] for r in results))
for row in results:
 if row['status']!='exact':print(row['ID'],row['Text'],row['Bytes'],row['actual'])
