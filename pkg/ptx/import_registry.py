#!/usr/bin/env python3
"""Import complete factual PTX syntax registry from NVIDIA HTML and LLVM dump.
Only input records are emitted; no representative opcode selection is made.
"""
import hashlib,html.parser,json,pathlib,re,sys
class Node:
 def __init__(self,tag='',attrs=()):self.tag=tag;self.attrs=dict(attrs);self.children=[]
 def text(self):return ''.join(c.text() if isinstance(c,Node) else c for c in self.children)
 def descendants(self,tag):
  for c in self.children:
   if isinstance(c,Node):
    if c.tag==tag:yield c
    yield from c.descendants(tag)
class HTML(html.parser.HTMLParser):
 def __init__(self):super().__init__();self.root=Node();self.stack=[self.root]
 def handle_starttag(self,t,a):
  n=Node(t,a);self.stack[-1].children.append(n)
  if t not in ['area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr']:self.stack.append(n)
 def handle_endtag(self,t):
  for i in range(len(self.stack)-1,0,-1):
   if self.stack[i].tag==t:self.stack=self.stack[:i];break
 def handle_data(self,s):self.stack[-1].children.append(s)
def digest(b):return hashlib.sha256(b).hexdigest()
EXPECTED_NVIDIA="3a4fe2a0dff0320a46e140b52d913839c8cd3dc0227b9809a46e116ab5b0a0a3"
EXPECTED_LLVM="ecb3467b6b196856d382a29a75e49b10a1b1181f3cc47abf2692583cf0a11758"
def main():
 htmlfile,llvmfile,out=map(pathlib.Path,sys.argv[1:]);raw=htmlfile.read_bytes();
 if digest(raw)!=EXPECTED_NVIDIA:raise SystemExit("NVIDIA source does not match pinned PTX ISA 9.5 SHA-256")
 p=HTML();p.feed(raw.decode());docs=[]
 for section in p.root.descendants('section'):
  children=[c for c in section.children if isinstance(c,Node)];heading=next((c for c in children if re.fullmatch('h[1-6]',c.tag)),None)
  if heading is None:continue
  number=next((c.text().strip() for c in heading.descendants('span') if c.attrs.get('class')=='section-number'),'')
  if not(number.startswith('9.7.')or number.startswith('10.')or number.startswith('11.')):continue
  codes=[c.text().strip()for c in heading.descendants('code')];syntax=[];requirements=[];examples=[];mode=''
  for c in children:
   if c.tag=='p'and 'rubric'in c.attrs.get('class',''):mode=c.text().strip()
   elif mode.startswith('Syntax'):syntax +=[n.text()for n in c.descendants('pre')]
   elif mode=='Examples':examples +=[n.text()for n in c.descendants('pre')]
   elif mode in ['PTX ISA Notes','Target ISA Notes']:requirements.append(c.text().strip())
  if not syntax:continue
  names=list(dict.fromkeys(codes));kind='instruction'if number.startswith('9.')else'special-register'if number.startswith('10.')else'directive'
  if not names:
   # A few syntax-bearing section headings name grouped families in plain text.
   for block in syntax:
    for line in block.splitlines():
     m=re.match(r'\s*([.%]?[A-Za-z_$][\w.$:]*)',line)
     if m and not line.lstrip().startswith('//'):names.append(m[1]);break
  req='\n'.join(requirements);versions=[int(a)*10+int(b)for a,b in re.findall(r'(?:PTX ISA|PTX)(?: version)?\s+(\d+)\.(\d+)',req)];targets=[int(n)for n in re.findall(r'sm_(\d+)',req)]
  docs.append(dict(id=section.attrs['id'],kind=kind,section=number,names=list(dict.fromkeys(names)),syntax=syntax,examples=examples,requirements=requirements,min_version=min(versions,default=0),min_target=(0 if 'Supported on all target architectures.' in req else min(targets,default=0))))
 rawllvm=llvmfile.read_bytes();
 if digest(rawllvm)!=EXPECTED_LLVM:raise SystemExit("LLVM source does not match pinned llvmorg-22.1.8 dump SHA-256")
 llvm=json.loads(rawllvm);ids=llvm['!instanceof']['Instruction'];records=[]
 for key in ids:
  r=llvm[key];records.append(dict(id=key,syntax=r.get('AsmString',''),pseudo=bool(r.get('isPseudo')),namespace=r.get('Namespace',''),features=[v.get('def',v.get('printable',''))for v in r.get('Predicates',[])],operands=[dict(name=a[1],class_name=a[0].get('def',a[0].get('printable','')))for field in ['OutOperandList','InOperandList']for a in (r.get(field)or{}).get('args',[])],constraints=r.get('Constraints',''),locations=r.get('!locs',[])))
 grammar=[dict(id=s.attrs.get('id',''),text=''.join(n.text() for n in s.descendants('pre'))) for s in p.root.descendants('section') if s.attrs.get('id','') in ['syntax','state-spaces-types-and-variables','instruction-operands','abstracting-abi']]
 target_versions={}
 for d in docs:
  if d["names"]==[".target"]:
   for req in d["requirements"]:
    v=re.search(r"introduced in PTX ISA version (\d+)\.(\d+)",req)
    if v and req.startswith("Target string"):
     for t in re.findall(r"sm_[0-9]+[af]?",req.split("introduced")[0]):target_versions[t]=int(v[1])*10+int(v[2])
 features=[]
 for kind in ['Predicate','SubtargetFeature']:
  for key in llvm['!instanceof'].get(kind,[]):
   r=llvm[key];features.append(dict(id=key,kind=kind,name=r.get('Name',''),field=r.get('FieldName',''),value=r.get('Value',''),description=r.get('Desc',''),condition=r.get('CondString',''),implies=[x.get('def','')for x in r.get('Implies',[])]))
 registry=dict(features=features,target_versions=target_versions,grammar=grammar,schema='mkasm.ptx.registry.v1',architecture='ptx',isa_version='9.5',sources=[dict(name='NVIDIA PTX ISA 9.5',url='https://docs.nvidia.com/cuda/parallel-thread-execution/index.html',sha256=digest(raw)),dict(name='LLVM llvmorg-22.1.8 NVPTX TableGen',url='https://github.com/llvm/llvm-project/tree/llvmorg-22.1.8/llvm/lib/Target/NVPTX',sha256=digest(rawllvm))],documents=docs,llvm=records)
 out.write_text(json.dumps(registry,separators=(',',':'))+'\n');print(len(docs),'NVIDIA syntax sections;',len(records),'LLVM instruction records;',sum(bool(r['syntax'])for r in records),'nonempty LLVM syntax records')
if __name__=='__main__':main()
