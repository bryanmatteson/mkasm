#[derive(Debug,Clone)]
pub struct SerializedType{pub kind:String,pub enum_name:String,pub enum_module:Option<ModuleIdentity>,pub enum_arguments:Vec<Type>,pub element:Option<Box<SerializedType>>}
impl PartialEq for SerializedType{fn eq(&self,other:&Self)->bool{self.kind==other.kind&&self.enum_name==other.enum_name&&self.enum_module==other.enum_module&&self.element==other.element&&self.enum_arguments.len()==other.enum_arguments.len()&&self.enum_arguments.iter().zip(&other.enum_arguments).all(|(a,b)|serialized_signature_type_equal(a,b))}}
impl Eq for SerializedType{}
fn serialized_signature_type_equal(a:&Type,b:&Type)->bool{a.kind==b.kind&&a.token==b.token&&a.index==b.index&&a.rank==b.rank&&a.sizes==b.sizes&&a.lower_bounds==b.lower_bounds&&a.args.len()==b.args.len()&&a.args.iter().zip(&b.args).all(|(a,b)|serialized_signature_type_equal(a,b))&&match(&a.method,&b.method){(None,None)=>true,(Some(a),Some(b))=>serialized_signature_equal(a,b),_=>false}}
fn serialized_signature_equal(a:&Signature,b:&Signature)->bool{a.kind==b.kind&&a.calling_convention==b.calling_convention&&a.generic_arity==b.generic_arity&&a.sentinel==b.sentinel&&a.parameters.len()==b.parameters.len()&&a.parameters.iter().zip(&b.parameters).all(|(a,b)|serialized_signature_type_equal(a,b))&&match(&a.return_type,&b.return_type){(None,None)=>true,(Some(a),Some(b))=>serialized_signature_type_equal(a,b),_=>false}}
impl SerializedType{fn scalar(kind:&str)->Self{Self{kind:kind.into(),enum_name:String::new(),enum_module:None,enum_arguments:vec![],element:None}}}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct AttributeValue{pub typ:SerializedType,pub bits:u64,pub text:Option<String>,pub null:bool,pub elements:Vec<AttributeValue>}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct NamedArgument{pub field:bool,pub name:String,pub value:AttributeValue}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct DecodedAttribute{pub fixed:Vec<AttributeValue>,pub named:Vec<NamedArgument>}
fn serialized_string(r:&mut Cursor<'_>)->Result<Option<String>>{if r.b.get(r.p)==Some(&255){r.p+=1;return Ok(None);}let n=r.compressed()? as usize;let b=r.take(n)?;Ok(Some(std::str::from_utf8(b).map_err(|_|err("invalid UTF-8 serialized string"))?.into()))}
fn scalar_width(kind:&str)->Option<usize>{Some(match kind{"bool"|"int8"|"uint8"=>1,"char"|"int16"|"uint16"=>2,"int32"|"uint32"|"float32"=>4,"int64"|"uint64"|"float64"=>8,_=>return None})}
fn serialized_type(r:&mut Cursor<'_>,depth:usize)->Result<SerializedType>{
    if depth>64{return Err(err("attribute nesting limit"));}let code=r.uint(1)?;
    let kind=match code{2=>"bool",3=>"char",4=>"int8",5=>"uint8",6=>"int16",7=>"uint16",8=>"int32",9=>"uint32",10=>"int64",11=>"uint64",12=>"float32",13=>"float64",14=>"string",0x50=>"type",0x51=>"object",0x1d=>"array",0x55=>"enum",_=>return Err(err("invalid serialized attribute type"))};let mut t=SerializedType::scalar(kind);
    if kind=="array"{t.element=Some(Box::new(serialized_type(r,depth+1)?));}if kind=="enum"{t.enum_name=serialized_string(r)?.filter(|s|!s.is_empty()).ok_or_else(||err("empty enum name"))?;}Ok(t)
}
fn attribute_value(r:&mut Cursor<'_>,typ:SerializedType,enums:&mut impl FnMut(&str)->Result<String>,depth:usize)->Result<AttributeValue>{
 attribute_value_scoped(r,typ,&mut |t:&SerializedType|enums(&t.enum_name),depth)
}
fn attribute_value_scoped(r:&mut Cursor<'_>,typ:SerializedType,enums:&mut impl FnMut(&SerializedType)->Result<String>,depth:usize)->Result<AttributeValue>{
    if depth>64{return Err(err("attribute nesting limit"));}let kind=if typ.kind=="enum"{let s=enums(&typ)?;if !matches!(s.as_str(),"int8"|"uint8"|"int16"|"uint16"|"int32"|"uint32"|"int64"|"uint64"){return Err(err("invalid enum storage type"));}s}else{typ.kind.clone()};let mut out=AttributeValue{typ,bits:0,text:None,null:false,elements:vec![]};
    if let Some(width)=scalar_width(&kind){for(i,b)in r.take(width)?.iter().enumerate(){out.bits|=(*b as u64)<<(8*i);}if kind=="bool"&&out.bits>1{return Err(err("invalid attribute boolean"));}return Ok(out);}
    match kind.as_str(){
        "string"|"type"=>{out.text=serialized_string(r)?;out.null=out.text.is_none();}
        "object"=>{if r.b.get(r.p)==Some(&255){r.p+=1;out.null=true;}else{let t=serialized_type(r,depth+1)?;if t.kind=="object"{return Err(err("object cannot box object"));}out.elements.push(attribute_value_scoped(r,t,enums,depth+1)?);}}
        "array"=>{let n=r.uint(4)?;if n==u32::MAX{out.null=true;}else{if n>i32::MAX as u32||n as usize>r.b.len()-r.p{return Err(err("array length out of bounds"));}let child=out.typ.element.as_ref().ok_or_else(||err("missing array element type"))?;for _ in 0..n{out.elements.push(attribute_value_scoped(r,(**child).clone(),enums,depth+1)?);}}}
        _=>return Err(err("unsupported attribute value type"))
    }Ok(out)
}
fn named_arguments(r:&mut Cursor<'_>,count:u32,enums:&mut impl FnMut(&str)->Result<String>)->Result<Vec<NamedArgument>>{
 named_arguments_scoped(r,count,&mut |t:&SerializedType|enums(&t.enum_name))
}
fn named_arguments_scoped(r:&mut Cursor<'_>,count:u32,enums:&mut impl FnMut(&SerializedType)->Result<String>)->Result<Vec<NamedArgument>>{
    if count as usize>r.b.len()-r.p{return Err(err("named argument count out of bounds"));}let mut out=Vec::new();for _ in 0..count{let code=r.uint(1)?;if code!=0x53&&code!=0x54{return Err(err("invalid named argument kind"));}let t=serialized_type(r,0)?;let name=serialized_string(r)?.filter(|s|!s.is_empty()).ok_or_else(||err("empty named argument"))?;let value=attribute_value_scoped(r,t,enums,0)?;out.push(NamedArgument{field:code==0x53,name,value});}Ok(out)
}
impl Metadata<'_>{
    fn attribute_type(&self,t:&Type)->Result<SerializedType>{let mut t=t;while matches!(t.kind.as_str(),"modreq"|"modopt")&&t.args.len()==1{t=&t.args[0];}if scalar_width(&t.kind).is_some()||matches!(t.kind.as_str(),"string"|"object"){return Ok(SerializedType::scalar(&t.kind));}if t.kind=="szarray"&&t.args.len()==1{let mut out=SerializedType::scalar("array");out.element=Some(Box::new(self.attribute_type(&t.args[0])?));return Ok(out);}if t.kind=="genericinst"&&t.args.len()>1&&t.args[0].kind=="valuetype"{let mut out=SerializedType::scalar("enum");out.enum_name=self.reference_serialized_argument_name(t,0)?;out.enum_arguments=t.args[1..].to_vec();return Ok(out);}if matches!(t.kind.as_str(),"class"|"valuetype"){let name=self.resolve(t.token)?;if name=="System.Type"{return Ok(SerializedType::scalar("type"));}if t.kind=="valuetype"{let mut out=SerializedType::scalar("enum");out.enum_name=self.reference_enum_type_name(t.token)?;return Ok(out);}}Err(err("invalid custom attribute signature type"))}
    pub fn decode_attribute(&self,a:&Attribute<'_>,enums:&mut impl FnMut(&str)->Result<String>)->Result<DecodedAttribute>{let mut r=Cursor{native:false,b:a.value,p:0};if r.uint(2)?!=1{return Err(err("invalid attribute prolog"));}let mut out=DecodedAttribute{fixed:vec![],named:vec![]};for p in &a.constructor.resolved_signature.parameters{let t=self.attribute_type(p)?;out.fixed.push(attribute_value(&mut r,t,enums,0)?);}let count=r.uint(2)?;out.named=named_arguments(&mut r,count,enums)?;if r.p!=r.b.len(){return Err(err("trailing attribute bytes"));}Ok(out)}
    pub fn local_enum_underlying(&self,name:&str)->Result<String>{
      let(typ,id)=reference_parse_enum_identity(name)?;if id.is_some(){return Err(err(&format!("defining assembly for enum {} is required",name)));}
      ReferenceSet::new(self,&[])?.enum_underlying(&typ)
    }

}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct SecurityAttribute{pub typ:String,pub named:Vec<NamedArgument>}
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct SecurityDeclaration{pub legacy_xml:Vec<u8>,pub attributes:Vec<SecurityAttribute>}
pub fn decode_security(b:&[u8],enums:&mut impl FnMut(&str)->Result<String>)->Result<SecurityDeclaration>{let mut out=SecurityDeclaration{legacy_xml:vec![],attributes:vec![]};if b.is_empty(){return Err(err("empty security blob"));}if b[0]!=b'.'{out.legacy_xml=b.to_vec();return Ok(out);}let mut r=Cursor{native:false,b,p:1};let count=r.compressed()?;if count as usize>b.len()-r.p{return Err(err("security attribute count out of bounds"));}for _ in 0..count{let typ=serialized_string(&mut r)?.filter(|s|!s.is_empty()).ok_or_else(||err("security type missing"))?;let n=r.compressed()? as usize;let data=r.take(n)?;let mut sub=Cursor{native:false,b:data,p:0};let n=sub.compressed()?;let named=named_arguments(&mut sub,n,enums)?;if sub.p!=data.len(){return Err(err("trailing security attribute bytes"));}out.attributes.push(SecurityAttribute{typ,named});}if r.p!=b.len(){return Err(err("trailing security bytes"));}Ok(out)}
#[derive(Debug,Clone,Default,PartialEq,Eq)]
pub struct MarshalDescriptor{pub native_type:u32,pub element_type:Option<u32>,pub size_parameter:Option<u32>,pub size:Option<u32>,pub flags:Option<u32>,pub variant_type:Option<u32>,pub user_type:Option<String>,pub custom_strings:Vec<Option<String>>}
pub fn decode_marshal(b:&[u8])->Result<MarshalDescriptor>{let mut r=Cursor{native:false,b,p:0};let mut out=MarshalDescriptor{native_type:r.uint(1)?,..Default::default()};fn read(r:&mut Cursor<'_>,required:bool)->Result<Option<u32>>{if r.p==r.b.len()&&!required{return Ok(None);}Ok(Some(r.compressed()?))}
    match out.native_type{
        0x17=>out.size=read(&mut r,true)?,
        0x1e=>{out.size=read(&mut r,true)?;out.element_type=read(&mut r,false)?;}
        0x1d=>{out.variant_type=read(&mut r,false)?;if r.p<b.len(){out.user_type=serialized_string(&mut r)?;}}
        0x2a=>{out.element_type=read(&mut r,true)?;out.size_parameter=read(&mut r,false)?;out.size=read(&mut r,false)?;out.flags=read(&mut r,false)?;}
        0x2c=>for _ in 0..4{out.custom_strings.push(serialized_string(&mut r)?);},
        0x19|0x1a|0x1c=>out.size_parameter=read(&mut r,false)?,
        0x02..=0x0f|0x11..=0x16|0x18|0x1b|0x1f..=0x26|0x28|0x2b|0x2d..=0x30=>{},
        _=>return Err(err("unknown native marshal type"))
    }if r.p!=b.len(){return Err(err("trailing marshal bytes"));}Ok(out)
}

#[derive(Debug,Clone)]
pub struct AttributeRecord<'a>{pub attribute:Attribute<'a>,pub decoded:Option<DecodedAttribute>,pub decode_error:Option<String>}
#[derive(Debug,Clone)]
pub struct MarshalRecord<'a>{pub token:Token,pub parent:Token,pub value:&'a[u8],pub decoded:Option<MarshalDescriptor>,pub decode_error:Option<String>}
#[derive(Debug,Clone)]
pub struct SecurityRecord<'a>{pub token:Token,pub parent:Token,pub action:u32,pub value:&'a[u8],pub decoded:Option<SecurityDeclaration>,pub decode_error:Option<String>}
impl<'a> Metadata<'a>{
    pub fn serialized_attributes(&self,parent:Option<Token>,enums:&mut impl FnMut(&str)->Result<String>)->Result<Vec<AttributeRecord<'a>>>{
        self.attributes(parent)?.into_iter().map(|attribute|{let (decoded,decode_error)=match self.decode_attribute(&attribute,enums){Ok(v)=>(Some(v),None),Err(e)=>(None,Some(e.to_string()))};Ok(AttributeRecord{attribute,decoded,decode_error})}).collect()
    }
    pub fn marshal_records(&self)->Result<Vec<MarshalRecord<'a>>>{let mut out=vec![];for rid in 1..=self.tables[13].count{let row=self.row(13,rid)?;let parent=decode_coded("HasFieldMarshal",row[0])?;let value=self.blob(row[1])?;let(decoded,decode_error)=match decode_marshal(value){Ok(v)=>(Some(v),None),Err(e)=>(None,Some(e.to_string()))};out.push(MarshalRecord{token:Token(13<<24|rid),parent,value,decoded,decode_error});}Ok(out)}
    pub fn security_records(&self,enums:&mut impl FnMut(&str)->Result<String>)->Result<Vec<SecurityRecord<'a>>>{let mut out=vec![];for rid in 1..=self.tables[14].count{let row=self.row(14,rid)?;let parent=decode_coded("HasDeclSecurity",row[1])?;let value=self.blob(row[2])?;let(decoded,decode_error)=match decode_security(value,enums){Ok(v)=>(Some(v),None),Err(e)=>(None,Some(e.to_string()))};out.push(SecurityRecord{token:Token(14<<24|rid),parent,action:row[0],value,decoded,decode_error});}Ok(out)}
}
