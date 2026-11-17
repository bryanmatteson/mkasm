#[derive(Debug,Clone)]
pub struct NativeSection<'a>{pub kind:u32,pub directory:Directory,pub data:&'a[u8]}
#[derive(Debug,Clone)]
pub struct ReadyToRunInfo<'a>{pub major:u16,pub minor:u16,pub flags:u32,pub architecture:&'static str,pub os_override:u16,pub sections:Vec<NativeSection<'a>>}
#[derive(Debug,Clone)]
pub struct NativeFunction<'a>{pub index:u32,pub begin_rva:u32,pub end_rva:u32,pub unwind:u32,pub code:&'a[u8],pub methods:Vec<Token>,pub instances:Vec<NativeMethodInstance<'a>>,pub component_methods:Vec<NativeMethodReference>}
fn native_architecture(machine:u16)->(&'static str,u16){for os in [0,0x4644,0xadc4,0x7b79,0x1993,0x1992]{let arch=match machine^os{0x14c=>"x86_32",0x8664=>"x86_64",0x1c4=>"arm32",0xaa64=>"aarch64",0x6264=>"loongarch64",0x5064=>"riscv64",0x1f0=>"powerpc32",_=>continue};return(arch,os);}("unknown",0)}
fn native_unsigned(b:&[u8],at:usize)->Result<(u32,usize)>{let first=*b.get(at).ok_or_else(||err("native integer out of bounds"))? as u32;let(mut n,mut shift)=(1usize,1usize);while n<=4&&first&(1<<(n-1))!=0{n+=1;shift+=1;}if n==5{if first&16!=0{return Err(err("invalid native integer"));}return Ok((u32(b,at+1)?,at+5));}let a=span(b,at,n)?;let mut v=first>>shift;for(i,byte)in a.iter().enumerate().skip(1){v|=(*byte as u32)<<(8*i-shift);}Ok((v,at+n))}
fn native_array_at(b:&[u8],base:usize,width:u32,index:u32)->Result<Option<usize>>{let n=if width==0{1}else if width==1{2}else{4};let p=base.checked_add((index as usize/16).checked_mul(n).ok_or_else(||err("native array overflow"))?).ok_or_else(||err("native array overflow"))?;let a=span(b,p,n)?;let relative=if n==1{a[0] as u32}else if n==2{u16(b,p)? as u32}else{u32(b,p)?};let mut offset=base.checked_add(relative as usize).ok_or_else(||err("native array overflow"))?;for bit in [8,4,2,1]{let(v,next)=native_unsigned(b,offset)?;if index&bit!=0{if v&2!=0{offset=offset.checked_add((v>>2) as usize).ok_or_else(||err("native array overflow"))?;continue;}}else if v&1!=0{offset=next;continue;}if v&3==0&&v>>2==index&15{return Ok(Some(next));}return Ok(None);}Ok(Some(offset))}

/// Tokens retain their ReadyToRun module context. Foreign tokens are never
/// merged into NativeFunction.methods. Offsets are relative to section 109.
#[derive(Debug,Clone)]
pub struct NativeMethodInstance<'a>{
    pub hash:u8,pub offset:u32,pub flags:u32,pub module:Option<u32>,
    pub owner:Option<Type>,pub token:Token,pub slot:Option<u32>,
    pub type_arguments:Vec<Type>,pub constrained:Option<Type>,
    pub function_index:u32,pub fixup_offset:Option<u32>,pub signature:&'a[u8],
}
fn native_signed(b:&[u8],at:usize)->Result<(i32,usize)>{
    let(mut v,next)=native_unsigned(b,at)?;let bits=(next-at)*7;
    if bits<32&&v&(1<<(bits-1))!=0{v|=u32::MAX<<bits;}Ok((v as i32,next))
}

#[derive(Debug,Clone)]
pub struct NativeMethodReference{pub component:u32,pub token:Token}
#[derive(Debug)]
pub struct ReadyToRunComponent<'a>{pub index:u32,pub cli_header:Directory,pub assembly_header:Directory,pub flags:u32,pub sections:Vec<NativeSection<'a>>,pub metadata:Option<Metadata<'a>>}
fn composite_directory<'a>(exports:Directory,at:&impl Fn(u32,u32)->Result<&'a[u8]>)->Result<Directory>{
    if exports.rva==0||exports.size==0{return Ok(Directory::default());}
    let b=at(exports.rva,exports.size)?;span(b,0,40)?;let(functions,names)=(u32(b,20)?,u32(b,24)?);
    let fs=at(u32(b,28)?,functions.checked_mul(4).ok_or_else(||err("export table overflow"))?)?;
    let ns=at(u32(b,32)?,names.checked_mul(4).ok_or_else(||err("export table overflow"))?)?;
    let os=at(u32(b,36)?,names.checked_mul(2).ok_or_else(||err("export table overflow"))?)?;
    for i in 0..names as usize{let mut rva=u32(ns,i*4)?;let mut matches=true;
        for (j,want) in b"RTR_HEADER\0".iter().enumerate(){let c=at(rva.checked_add(j as u32).ok_or_else(||err("export string overflow"))?,1)?[0];if c!=*want{matches=false;break;}}
        if !matches{continue;}let ordinal=u16(os,i*2)? as usize;if ordinal>=functions as usize{return Err(err("invalid PE export ordinal"));}rva=u32(fs,ordinal*4)?;
        if rva as u64>=exports.rva as u64&&(rva as u64)<exports.rva as u64+exports.size as u64{return Err(err("forwarded RTR_HEADER export"));}
        let header=at(rva,16)?;if u32(header,0)?!=0x00525452{return Err(err("invalid composite signature"));}
        let size=u32(header,12)?.checked_mul(12).and_then(|n|n.checked_add(16)).ok_or_else(||err("composite header overflow"))?;at(rva,size)?;return Ok(Directory{rva,size});
    }Ok(Directory::default())
}
fn native_entry_point(b:&[u8],at:usize)->Result<(u32,Option<u32>)>{
    let(id,mut next)=native_unsigned(b,at)?;if id&1==0{return Ok((id>>1,None));}
    if id&2!=0{let(delta,_)=native_unsigned(b,next)?;next=next.checked_sub(delta as usize).ok_or_else(||err("invalid fixup back reference"))?;}
    if next>=b.len(){return Err(err("fixup out of bounds"));}Ok((id>>2,Some(next as u32)))
}
impl<'a> Metadata<'a>{
    fn native_method_instance(&self,b:&'a[u8],at:usize)->Result<NativeMethodInstance<'a>>{
        let mut r=Cursor{b,p:at,native:true};let flags=r.compressed()?;
        if flags&!255!=0{return Err(err("unknown R2R method flags"));}
        let module=if flags&0x80!=0{Some(r.compressed()?)}else{None};
        let owner=if flags&0x40!=0{Some(self.signature_type(&mut r,0)?)}else{None};
        let rid=r.compressed()?;let(slot,token)=if flags&8!=0{(Some(rid),Token(0))}else{
            if rid==0||rid>0xffffff{return Err(err("invalid R2R method RID"));}
            (None,Token((if flags&16!=0{10}else{6})<<24|rid))
        };
        let mut type_arguments=vec![];
        if flags&4!=0{let count=r.compressed()?;if count as usize>b.len().saturating_sub(r.p){return Err(err("R2R argument count out of bounds"));}for _ in 0..count{type_arguments.push(self.signature_type(&mut r,0)?);}}
        let constrained=if flags&0x20!=0{Some(self.signature_type(&mut r,0)?)}else{None};
        let signature=&b[at..r.p];let(function_index,fixup_offset)=native_entry_point(b,r.p)?;
        Ok(NativeMethodInstance{hash:0,offset:at as u32,flags,module,owner,token,slot,type_arguments,constrained,function_index,fixup_offset,signature})
    }
    fn native_method_instances(&self,b:&'a[u8])->Result<Vec<NativeMethodInstance<'a>>>{
        let header=*b.first().ok_or_else(||err("empty R2R hashtable"))?;let shift=header>>2;let code=header&3;
        if shift>31||code>2{return Err(err("invalid R2R hash header"));}
        let buckets=1u64<<shift;let width=1u64<<code;let index_size=(buckets+1)*width;
        if index_size>=b.len() as u64{return Err(err("R2R hash index out of bounds"));}
        let read=|i:u64|{let mut v=0u64;for j in 0..width{v|=(b[(1+i*width+j)as usize]as u64)<<(j*8);}v+1};
        let mut out=vec![];
        for bucket in 0..buckets{let(mut at,end)=(read(bucket),read(bucket+1));if at<index_size+1||end<at||end>b.len()as u64{return Err(err("invalid R2R hash bucket"));}
            while at<end{let hash=b[at as usize];at+=1;let(delta,next)=native_signed(b,at as usize)?;if next as u64>end{return Err(err("R2R hash entry exceeds bucket"));}let target=at as i64+delta as i64;
                if target<(index_size+1)as i64||target>=b.len()as i64{return Err(err("R2R signature out of bounds"));}
                let mut instance=self.native_method_instance(b,target as usize)?;instance.hash=hash;out.push(instance);at=next as u64;
            }
        }Ok(out)
    }
}
impl<'a> Image<'a>{
    pub fn ready_to_run_components(&self)->Result<Vec<ReadyToRunComponent<'a>>>{
        let Some(header)=self.ready_to_run_header()? else{return Ok(vec![]);};let mut data=&[][..];for s in &header.sections{if s.kind==115{data=s.data;}}
        if data.len()%16!=0{return Err(err("invalid component assembly table"));}let mut out=vec![];
        for i in (0..data.len()).step_by(16){let cli_header=Directory{rva:u32(data,i)?,size:u32(data,i+4)?};let assembly_header=Directory{rva:u32(data,i+8)?,size:u32(data,i+12)?};let b=self.bytes_at_rva(assembly_header.rva,assembly_header.size)?;span(b,0,8)?;let flags=u32(b,0)?;let count=u32(b,4)? as usize;span(b,8,count.checked_mul(12).ok_or_else(||err("component section overflow"))?)?;
            let mut sections=vec![];let mut last=0;for n in 0..count{let p=8+n*12;let kind=u32(b,p)?;if n>0&&kind<=last{return Err(err("unordered component sections"));}last=kind;let directory=Directory{rva:u32(b,p+4)?,size:u32(b,p+8)?};sections.push(NativeSection{kind,directory,data:self.bytes_at_rva(directory.rva,directory.size)?});}
            let metadata=if cli_header.size!=0{let cli=self.bytes_at_rva(cli_header.rva,cli_header.size)?;span(cli,0,72)?;if u32(cli,0)?<72||u32(cli,0)?>cli_header.size{return Err(err("invalid component CLI header"));}let(rva,size)=(u32(cli,8)?,u32(cli,12)?);if size==0{None}else{Some(Metadata::parse(self.bytes_at_rva(rva,size)?)?)}}else{None};
            out.push(ReadyToRunComponent{index:(i/16)as u32,cli_header,assembly_header,flags,sections,metadata});
        }Ok(out)
    }
    pub fn native_method_instances(&self)->Result<Vec<NativeMethodInstance<'a>>>{
        let Some(header)=self.ready_to_run_header()? else{return Ok(vec![]);};
        for section in &header.sections{if section.kind==109{return self.metadata.native_method_instances(section.data);}}Ok(vec![])
    }
    pub fn ready_to_run_header(&self)->Result<Option<ReadyToRunInfo<'a>>>{if !self.ready_to_run{return Ok(None);}let d=if self.composite{&self.native_header}else{&self.cli.managed_native_header};let b=self.bytes_at_rva(d.rva,d.size)?;span(b,0,16)?;let(architecture,os_override)=native_architecture(self.machine);let mut out=ReadyToRunInfo{major:u16(b,4)?,minor:u16(b,6)?,flags:u32(b,8)?,architecture,os_override,sections:vec![]};let n=u32(b,12)? as usize;span(b,16,n.checked_mul(12).ok_or_else(||err("R2R section overflow"))?)?;let mut last=0;for i in 0..n{let p=16+i*12;let kind=u32(b,p)?;if i>0&&kind<=last{return Err(err("unordered R2R sections"));}last=kind;let directory=Directory{rva:u32(b,p+4)?,size:u32(b,p+8)?};let data=self.bytes_at_rva(directory.rva,directory.size)?;out.sections.push(NativeSection{kind,directory,data});}Ok(Some(out))}
    pub fn native_functions(&self)->Result<Vec<NativeFunction<'a>>>{
        let Some(header)=self.ready_to_run_header()? else{return Ok(vec![]);};let mut table=&[][..];let mut entries=&[][..];for s in &header.sections{if s.kind==102{table=s.data;}if s.kind==103{entries=s.data;}}
        if table.is_empty(){return Ok(vec![]);}let width=if header.architecture=="x86_64"{12}else{8};if table.len()%width!=0{return Err(err("invalid runtime function width"));}let mut out=Vec::new();
        for i in 0..table.len()/width{let p=i*width;let mut begin=u32(table,p)?;let mut unwind=u32(table,p+4)?;let end=if width==12{let end=unwind;unwind=u32(table,p+8)?;end}else{let length=match header.architecture{
            "aarch64"=>if unwind&3!=0{((unwind>>2)&0x7ff)*4}else{(u32(self.bytes_at_rva(unwind,4)?,0)?&0x3ffff)*4},
            "arm32"=>{begin&=!1;if unwind&3!=0{((unwind>>2)&0x7ff)*2}else{(u32(self.bytes_at_rva(unwind,4)?,0)?&0x3ffff)*2}},
            "loongarch64"|"riscv64"=>(u32(self.bytes_at_rva(unwind,4)?,0)?&0x3ffff)*4,
            "x86_32"=>{let p=self.rva_offset(unwind,1)?;let mut length=0u32;for n in 0..5{let b=span(self.data,p+n,1)?[0];if length>u32::MAX>>7{return Err(err("GC length overflow"));}length=(length<<7)|(b&127) as u32;if b&128==0{break;}if n==4{return Err(err("invalid GC length"));}}length},
            _=>return Err(err("native function length requires target unwind format"))
        };begin.checked_add(length).ok_or_else(||err("native function extent overflow"))?};if end<=begin{return Err(err("invalid native function extent"));}let code=self.bytes_at_rva(begin,end-begin)?;out.push(NativeFunction{index:i as u32,begin_rva:begin,end_rva:end,unwind,code,methods:vec![],instances:vec![],component_methods:vec![]});}
        if !entries.is_empty(){let(value,base)=native_unsigned(entries,0)?;let(count,width)=(value>>2,value&3);if count>self.metadata.tables[6].count{return Err(err("method array exceeds MethodDef table"));}for i in 0..count{let Some(at)=native_array_at(entries,base,width,i)? else{continue;};let(id,_)=native_unsigned(entries,at)?;let id=if id&1!=0{id>>2}else{id>>1};let f=out.get_mut(id as usize).ok_or_else(||err("R2R function index out of bounds"))?;f.methods.push(Token((6<<24)|(i+1)));}}
        for instance in self.native_method_instances()? {let f=out.get_mut(instance.function_index as usize).ok_or_else(||err("R2R generic function index out of bounds"))?;f.instances.push(instance);}
        if self.composite {for c in self.ready_to_run_components()?{for s in &c.sections{if s.kind!=103{continue;}let(value,base)=native_unsigned(s.data,0)?;let(count,width)=(value>>2,value&3);if count as u64>s.data.len()as u64*16||c.metadata.as_ref().is_some_and(|m|count>m.tables[6].count){return Err(err("component method array exceeds metadata"));}for i in 0..count{let Some(at)=native_array_at(s.data,base,width,i)? else{continue;};let(id,_)=native_entry_point(s.data,at)?;let f=out.get_mut(id as usize).ok_or_else(||err("component function index out of bounds"))?;f.component_methods.push(NativeMethodReference{component:c.index,token:Token((6<<24)|(i+1))});}}}}
        Ok(out)
    }
}
