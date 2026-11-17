
fn mos_text(text:&str)->String{
 let chars=text.chars().collect::<Vec<_>>();let mut out=String::new();let mut i=0;
 while i<chars.len(){let c=chars[i];if (c=='$'&&i+1<chars.len()&&chars[i+1].is_ascii_hexdigit())||(c=='%'&&i+1<chars.len()&&matches!(chars[i+1],'0'|'1')){let mut end=i+1;while end<chars.len()&&(if c=='$'{chars[end].is_ascii_hexdigit()}else{matches!(chars[end],'0'|'1')}){end+=1;}if end<chars.len()&&(chars[end].is_ascii_alphanumeric()||chars[end]=='_'){out.push(c);i+=1;continue;}out.push_str(if c=='$'{"0x"}else{"0b"});i+=1;while i<chars.len()&&(if c=='$'{chars[i].is_ascii_hexdigit()}else{matches!(chars[i],'0'|'1')}){out.push(chars[i]);i+=1;}continue;}out.push(c);i+=1;}
 let mnemonic=out.split_whitespace().next().unwrap_or("").to_owned();match mnemonic.to_ascii_lowercase().as_str(){"ane"=>{let at=out.find(&mnemonic).unwrap();out=format!("xaa{}",&out[at+mnemonic.len()..]);},"sha"=>{let at=out.find(&mnemonic).unwrap();out=format!("ahx{}",&out[at+mnemonic.len()..]);},_=>{}}
 let fields=out.split_whitespace().collect::<Vec<_>>();if fields.len()==1{match fields[0].to_ascii_lowercase().as_str(){"brk"=>out.push_str(" #0"),"asl"|"lsr"|"rol"|"ror"|"inc"|"dec"=>out.push_str(" a"),_=>{}}}out
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct ResolvedAddress{pub address:u16,pub page_crossed:bool,pub indirect:bool}
/// Effective-address arithmetic, including zero-page and NMOS JMP wrapping.
pub fn resolve_operand(d:&Decoded,name:&str,pc:u16,processor:&str,x:u8,y:u8,mut read:Option<&mut dyn FnMut(u16)->u8>)->Result<Option<ResolvedAddress>,Error>{
 if !matches!(processor.to_ascii_lowercase().as_str(),""|"mos6502"|"6502"|"6502x"|"65sc02"|"65c02"|"w65c02"|"w65c02+nops"){return Err(Error::Operand);}
 let(o,value)=d.operands().find(|(o,_)|o.name==name).ok_or(Error::Operand)?;let v=value as u16;let mut r=ResolvedAddress{address:v,page_crossed:false,indirect:false};
 if o.relative{r.address=(pc as i128+o.pc_bias+value)as u16;r.page_crossed=pc.wrapping_add(d.length as u16)&0xff00!=r.address&0xff00;return Ok(Some(r));}
 if o.kind!="address"{return Ok(None);}
 let mut word=|p:u16,h:u16|->Result<u16,Error>{let f=read.as_mut().ok_or(Error::Operand)?;Ok(f(p)as u16|((f(h)as u16)<<8))};
 match o.class{
 "DirectX"=>r.address=(v as u8).wrapping_add(x)as u16,
 "DirectY"=>r.address=(v as u8).wrapping_add(y)as u16,
 "AbsoluteX"=>{r.address=v.wrapping_add(x as u16);r.page_crossed=v&0xff00!=r.address&0xff00;},
 "AbsoluteY"=>{r.address=v.wrapping_add(y as u16);r.page_crossed=v&0xff00!=r.address&0xff00;},
 "DirectIndirect"|"DirectXIndirect"|"DirectIndirectY"=>{let mut p=v as u8;if o.class=="DirectXIndirect"{p=p.wrapping_add(x);}let base=word(p as u16,p.wrapping_add(1)as u16)?;r.address=base;r.indirect=true;if o.class=="DirectIndirectY"{r.address=base.wrapping_add(y as u16);r.page_crossed=base&0xff00!=r.address&0xff00;}},
 "JmpAbsoluteIndirect"|"AbsoluteXIndirect"=>{let mut p=v;if o.class=="AbsoluteXIndirect"{p=p.wrapping_add(x as u16);}let mut h=p.wrapping_add(1);if o.class=="JmpAbsoluteIndirect"&&matches!(processor.to_ascii_lowercase().as_str(),""|"6502"|"6502x"|"mos6502"){h=p&0xff00|((p as u8).wrapping_add(1)as u16);}r.address=word(p,h)?;r.indirect=true;},_=>{}
 }Ok(Some(r))
}

/// Source-defined legality for one processor profile.
pub fn opcode_status(processor:&str,opcode:u8)->Result<&'static str,Error>{let active=profile(processor).ok_or(Error::Operand)?;match decode_with_features(&[opcode,0,0],Some(active)){Ok(d)=>{for f in d.encoding().features{if matches!(*f,"undocumented"|"reserved-nop"){return Ok(f);}}Ok("documented")},Err(Error::Unknown)=>Ok("invalid"),Err(e)=>Err(e)}}

