
/// State at an instruction boundary; E forces M=X=1.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct ExecutionContext{pub pc:u32,pub emulation:bool,pub accumulator8:bool,pub index8:bool}
impl Default for ExecutionContext{fn default()->Self{Self{pc:0,emulation:true,accumulator8:true,index8:true}}}
impl ExecutionContext{
    pub fn profile(self)->&'static str{match(self.emulation||self.accumulator8,self.emulation||self.index8){(true,true)=>"m8x8",(true,false)=>"m8x16",(false,true)=>"m16x8",(false,false)=>"m16x16"}}
    pub fn next(mut self,d:&Decoded)->Result<Self,Error>{
        if self.pc>0xffffff{return Err(Error::Operand);}
        match d.encoding().mnemonic{
            "plp"|"rti"|"xce"=>return Err(Error::Operand),
            "rep"|"sep"=>{let value=d.operands().find(|(o,_)|o.name=="value").ok_or(Error::Operand)?.1;let set=d.encoding().mnemonic=="sep";if value&32!=0{self.accumulator8=set;}if value&16!=0{self.index8=set;}},_=>{}
        }
        if self.emulation{self.accumulator8=true;self.index8=true;}
        self.pc=(self.pc&0xff0000)|((self.pc+d.length as u32)&0xffff);Ok(self)
    }
}
pub fn decode_with_context(bytes:&[u8],ctx:ExecutionContext)->Result<Decoded,Error>{if ctx.pc>0xffffff{return Err(Error::Operand);}decode_with_features(bytes,profile(ctx.profile()))}
pub fn assemble_with_context(text:&str,ctx:ExecutionContext)->Result<Vec<Vec<u8>>,Error>{if ctx.pc>0xffffff{return Err(Error::Operand);}assemble_with_features(text,ctx.pc as u64,profile(ctx.profile()))}
#[cfg(test)]mod context_tests{use super::*;
 #[test]fn widths_banks_and_status(){
  for(m,x)in[(true,true),(true,false),(false,true),(false,false)]{let ctx=ExecutionContext{pc:0x12fffe,emulation:false,accumulator8:m,index8:x};assert_eq!(decode_with_context(&[0xa9,0x34,0x12],ctx).unwrap().length,if m{2}else{3});assert_eq!(decode_with_context(&[0xa2,0x34,0x12],ctx).unwrap().length,if x{2}else{3});let d=decode_with_context(&[0x80,1],ctx).unwrap();assert_eq!(d.branch_target(ctx.pc as u64),Some(0x120001));assert!(d.relocated(ctx.pc as u64,0x130000).is_err());assert!(assemble_with_context("bra 0x120001",ctx).unwrap().contains(&vec![0x80,1]));let next=ctx.next(&decode_with_context(&[0xc2,0x30],ctx).unwrap()).unwrap();assert_eq!(next.pc,0x120000);assert_eq!(next.profile(),"m16x16");}
 }
}
