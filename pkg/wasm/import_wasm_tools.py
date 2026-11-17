#!/usr/bin/env python3
"""Extract the opcode corpus from the actual wasm-tools source grammar.

Usage: import_wasm_tools.py WASMPARSER_LIB WASM_ENCODER_INSTRUCTIONS WAST_EXPR OUTPUT
Sources must be from the same wasm-tools release. No hand-curated opcode subset.
"""
import json, re, sys, pathlib, hashlib

if len(sys.argv) != 5:
    sys.exit(__doc__)
pins = ['1a79a9e372eab1c27417b47458725edabcaacfe9e92a5b718e663e6ca5ab5fdb',
        'd44d9d7af3c3a72f15d40023e15c1ef3ee416a8018f126ff5c0ecf4cb4dd5ac2',
        'a4313fa536bde765320fe17a30822aacb342658069cf024abe690ebf4697cb01']
for path, digest in zip(sys.argv[1:4], pins):
    if hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() != digest:
        sys.exit('Input differs from qualified wasm-tools 0.262.0: '+path)
parser, encoder, wast = [pathlib.Path(p).read_text() for p in sys.argv[1:4]]
ops={}
for m in re.finditer(r'(\w+)\s*(?:\{([^{}]*)\})?\s*=>\s*visit_(\w+)\s*\(arity',parser,re.S):
    before=parser[:m.start()]
    groups=re.findall(r'@(\w+)\s*\{',before)
    fields=[]
    for f in (m[2] or '').split(','):
        if f.strip():
            name,typ=f.strip().split(':',1); fields.append({'name':name,'kind':typ.strip().replace('$crate::','')})
    ops[m[3]]={'id':m[1],'feature':groups[-1],'fields':fields}
texts={m[1].rstrip('_'):m[2] for m in re.finditer(r'^\s*(\w+)(?:\([^\n]*\))?\s*:\s*"([^"]+)"',wast,re.M)}
result=[];missing=[]
chunks=re.split(r'(?=    /// Encode \[`Instruction::)',encoder)
for chunk in chunks:
    fn=re.search(r'pub fn (\w+)',chunk)
    if not fn:continue
    name=fn[1].rstrip('_')
    if name not in ops:
        missing.append(name);continue
    r=ops.pop(name)
    if name=='typed_select_multi':continue
    nums=re.findall(r'self\.sink\.push\((0x[0-9a-fA-F]+)\)',chunk)
    if not nums: raise Exception('no opcode '+name)
    first=int(nums[0],16)
    if first in (0xfb,0xfc,0xfd,0xfe):
        prefix=first
        if len(nums)>1: code=int(nums[1],16)
        else:
            n=re.search(r'(0x[0-9a-fA-F]+|[0-9]+)u32\.encode\(self.sink\)',chunk)
            if not n:raise Exception('missing prefixed code '+name)
            code=int(n[1],0)
    else:prefix=0;code=first
    r['prefix']=prefix;r['opcode']=code
    base=re.sub(r'_(non_null|nullable)$','',name)
    r['mnemonic']=texts.get(name,texts.get(base))
    if name=='typed_select':r['mnemonic']='select'
    if r['mnemonic'] is None:raise Exception('missing upstream WAT spelling '+name)
    # wasmparser presents several operands as aggregate objects; keep these
    # aggregates rather than losing their vector lengths, flags, or tags.
    kinds={'u32':'u32','i32':'s32','i64':'s64','u8':'lane','Ieee32':'f32','Ieee64':'f64','V128':'v128','[u8; 16]':'shuffle','BlockType':'block','BrTable<\'a>':'br_table','ValType':'valtype','Vec<ValType>':'valtypes','MemArg':'memarg','HeapType':'heaptype','RefType':'reftype','TryTable':'try_table','ResumeTable':'resume_table','Ordering':'ordering'}
    for f in r['fields']:
        if f['kind'] not in kinds:raise Exception((name,f))
        f['kind']=kinds[f['kind']]
    if name.startswith('br_on_cast'):r['fields']=[{'name':'cast','kind':'cast'}]
    if name=='try_table':r['fields']=[{'name':'try_table','kind':'try_table'}]
    if name in ('typed_select','typed_select_multi'):r['fields']=[{'name':'types','kind':'valtypes'}]
    if name=='atomic_fence':r['fields']=[{'name':'reserved','kind':'zero'}]
    if name.endswith('nullable'): r['nullable']=True
    elif name.endswith('non_null'):r['nullable']=False
    result.append(r)
if missing != ['new']:raise Exception('unmapped encoder functions '+str(missing))
# typed_select_multi shares opcode and wire grammar with typed_select.
ops.pop('typed_select_multi',None)
if ops:raise Exception('unmapped upstream operators: '+str(ops))
seen=set()
for r in result:
    key=(r['prefix'],r['opcode'])
    if key in seen:raise Exception('duplicate '+str(r))
    seen.add(key)
result.sort(key=lambda r:(r['prefix'],r['opcode']))
out={'schema':'mkasm.wasm-opcodes.v1','source':'wasm-tools 0.262.0','source_commit':'e22db44da4eaf17a0e46ec55b911c7539589a3cc','source_sha256':{pathlib.Path(p).name:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in sys.argv[1:4]},'opcodes':result}
pathlib.Path(sys.argv[4]).write_text(json.dumps(out,indent=2)+'\n')
print('extracted',len(result),'opcodes; encoder-only helpers',missing)
