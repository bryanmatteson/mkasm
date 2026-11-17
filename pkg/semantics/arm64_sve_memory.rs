//! SVE ordinary gather/scatter forms from the June 2026 A64 register diagrams.
//! Each access retains its original element width and increasing lane order.
use super::*;
use BinaryOp as B;
#[derive(Clone,Copy)]
struct Shape {mask:u32,value:u32,element:u8,memory:u8,offset:u8,scale:u8,store:bool,signed:bool,immediate:bool,xs:u8}
const SHAPES: &[Shape] = &[
    Shape{mask:0xffa0e000,value:0xc4004000,element:64,memory:8,offset:32,scale:0,store:false,signed:false,immediate:false,xs:22}, // ld1b_z_p_bz
    Shape{mask:0xffa0e000,value:0x84004000,element:32,memory:8,offset:32,scale:0,store:false,signed:false,immediate:false,xs:22}, // ld1b_z_p_bz
    Shape{mask:0xffe0e000,value:0xc440c000,element:64,memory:8,offset:64,scale:0,store:false,signed:false,immediate:false,xs:22}, // ld1b_z_p_bz
    Shape{mask:0xffe0e000,value:0x8420c000,element:32,memory:8,offset:0,scale:0,store:false,signed:false,immediate:true,xs:22}, // ld1b_z_p_ai
    Shape{mask:0xffe0e000,value:0xc420c000,element:64,memory:8,offset:0,scale:0,store:false,signed:false,immediate:true,xs:22}, // ld1b_z_p_ai
    Shape{mask:0xffa0e000,value:0x84a04000,element:32,memory:16,offset:32,scale:1,store:false,signed:false,immediate:false,xs:22}, // ld1h_z_p_bz
    Shape{mask:0xffa0e000,value:0xc4a04000,element:64,memory:16,offset:32,scale:1,store:false,signed:false,immediate:false,xs:22}, // ld1h_z_p_bz
    Shape{mask:0xffa0e000,value:0xc4804000,element:64,memory:16,offset:32,scale:0,store:false,signed:false,immediate:false,xs:22}, // ld1h_z_p_bz
    Shape{mask:0xffa0e000,value:0x84804000,element:32,memory:16,offset:32,scale:0,store:false,signed:false,immediate:false,xs:22}, // ld1h_z_p_bz
    Shape{mask:0xffe0e000,value:0xc4e0c000,element:64,memory:16,offset:64,scale:1,store:false,signed:false,immediate:false,xs:22}, // ld1h_z_p_bz
    Shape{mask:0xffe0e000,value:0xc4c0c000,element:64,memory:16,offset:64,scale:0,store:false,signed:false,immediate:false,xs:22}, // ld1h_z_p_bz
    Shape{mask:0xffe0e000,value:0x84a0c000,element:32,memory:16,offset:0,scale:0,store:false,signed:false,immediate:true,xs:22}, // ld1h_z_p_ai
    Shape{mask:0xffe0e000,value:0xc4a0c000,element:64,memory:16,offset:0,scale:0,store:false,signed:false,immediate:true,xs:22}, // ld1h_z_p_ai
    Shape{mask:0xffa0e000,value:0x85204000,element:32,memory:32,offset:32,scale:2,store:false,signed:false,immediate:false,xs:22}, // ld1w_z_p_bz
    Shape{mask:0xffa0e000,value:0xc5204000,element:64,memory:32,offset:32,scale:2,store:false,signed:false,immediate:false,xs:22}, // ld1w_z_p_bz
    Shape{mask:0xffa0e000,value:0xc5004000,element:64,memory:32,offset:32,scale:0,store:false,signed:false,immediate:false,xs:22}, // ld1w_z_p_bz
    Shape{mask:0xffa0e000,value:0x85004000,element:32,memory:32,offset:32,scale:0,store:false,signed:false,immediate:false,xs:22}, // ld1w_z_p_bz
    Shape{mask:0xffe0e000,value:0xc560c000,element:64,memory:32,offset:64,scale:2,store:false,signed:false,immediate:false,xs:22}, // ld1w_z_p_bz
    Shape{mask:0xffe0e000,value:0xc540c000,element:64,memory:32,offset:64,scale:0,store:false,signed:false,immediate:false,xs:22}, // ld1w_z_p_bz
    Shape{mask:0xffe0e000,value:0x8520c000,element:32,memory:32,offset:0,scale:0,store:false,signed:false,immediate:true,xs:22}, // ld1w_z_p_ai
    Shape{mask:0xffe0e000,value:0xc520c000,element:64,memory:32,offset:0,scale:0,store:false,signed:false,immediate:true,xs:22}, // ld1w_z_p_ai
    Shape{mask:0xffa0e000,value:0xc5a04000,element:64,memory:64,offset:32,scale:3,store:false,signed:false,immediate:false,xs:22}, // ld1d_z_p_bz
    Shape{mask:0xffa0e000,value:0xc5804000,element:64,memory:64,offset:32,scale:0,store:false,signed:false,immediate:false,xs:22}, // ld1d_z_p_bz
    Shape{mask:0xffe0e000,value:0xc5e0c000,element:64,memory:64,offset:64,scale:3,store:false,signed:false,immediate:false,xs:22}, // ld1d_z_p_bz
    Shape{mask:0xffe0e000,value:0xc5c0c000,element:64,memory:64,offset:64,scale:0,store:false,signed:false,immediate:false,xs:22}, // ld1d_z_p_bz
    Shape{mask:0xffe0e000,value:0xc5a0c000,element:64,memory:64,offset:0,scale:0,store:false,signed:false,immediate:true,xs:22}, // ld1d_z_p_ai
    Shape{mask:0xffa0e000,value:0xc4000000,element:64,memory:8,offset:32,scale:0,store:false,signed:true,immediate:false,xs:22}, // ld1sb_z_p_bz
    Shape{mask:0xffa0e000,value:0x84000000,element:32,memory:8,offset:32,scale:0,store:false,signed:true,immediate:false,xs:22}, // ld1sb_z_p_bz
    Shape{mask:0xffe0e000,value:0xc4408000,element:64,memory:8,offset:64,scale:0,store:false,signed:true,immediate:false,xs:22}, // ld1sb_z_p_bz
    Shape{mask:0xffe0e000,value:0x84208000,element:32,memory:8,offset:0,scale:0,store:false,signed:true,immediate:true,xs:22}, // ld1sb_z_p_ai
    Shape{mask:0xffe0e000,value:0xc4208000,element:64,memory:8,offset:0,scale:0,store:false,signed:true,immediate:true,xs:22}, // ld1sb_z_p_ai
    Shape{mask:0xffa0e000,value:0x84a00000,element:32,memory:16,offset:32,scale:1,store:false,signed:true,immediate:false,xs:22}, // ld1sh_z_p_bz
    Shape{mask:0xffa0e000,value:0xc4a00000,element:64,memory:16,offset:32,scale:1,store:false,signed:true,immediate:false,xs:22}, // ld1sh_z_p_bz
    Shape{mask:0xffa0e000,value:0xc4800000,element:64,memory:16,offset:32,scale:0,store:false,signed:true,immediate:false,xs:22}, // ld1sh_z_p_bz
    Shape{mask:0xffa0e000,value:0x84800000,element:32,memory:16,offset:32,scale:0,store:false,signed:true,immediate:false,xs:22}, // ld1sh_z_p_bz
    Shape{mask:0xffe0e000,value:0xc4e08000,element:64,memory:16,offset:64,scale:1,store:false,signed:true,immediate:false,xs:22}, // ld1sh_z_p_bz
    Shape{mask:0xffe0e000,value:0xc4c08000,element:64,memory:16,offset:64,scale:0,store:false,signed:true,immediate:false,xs:22}, // ld1sh_z_p_bz
    Shape{mask:0xffe0e000,value:0x84a08000,element:32,memory:16,offset:0,scale:0,store:false,signed:true,immediate:true,xs:22}, // ld1sh_z_p_ai
    Shape{mask:0xffe0e000,value:0xc4a08000,element:64,memory:16,offset:0,scale:0,store:false,signed:true,immediate:true,xs:22}, // ld1sh_z_p_ai
    Shape{mask:0xffa0e000,value:0xc5200000,element:64,memory:32,offset:32,scale:2,store:false,signed:true,immediate:false,xs:22}, // ld1sw_z_p_bz
    Shape{mask:0xffa0e000,value:0xc5000000,element:64,memory:32,offset:32,scale:0,store:false,signed:true,immediate:false,xs:22}, // ld1sw_z_p_bz
    Shape{mask:0xffe0e000,value:0xc5608000,element:64,memory:32,offset:64,scale:2,store:false,signed:true,immediate:false,xs:22}, // ld1sw_z_p_bz
    Shape{mask:0xffe0e000,value:0xc5408000,element:64,memory:32,offset:64,scale:0,store:false,signed:true,immediate:false,xs:22}, // ld1sw_z_p_bz
    Shape{mask:0xffe0e000,value:0xc5208000,element:64,memory:32,offset:0,scale:0,store:false,signed:true,immediate:true,xs:22}, // ld1sw_z_p_ai
    Shape{mask:0xffe0a000,value:0xe4008000,element:64,memory:8,offset:32,scale:0,store:true,signed:false,immediate:false,xs:14}, // st1b_z_p_bz
    Shape{mask:0xffe0a000,value:0xe4408000,element:32,memory:8,offset:32,scale:0,store:true,signed:false,immediate:false,xs:14}, // st1b_z_p_bz
    Shape{mask:0xffe0e000,value:0xe400a000,element:64,memory:8,offset:64,scale:0,store:true,signed:false,immediate:false,xs:14}, // st1b_z_p_bz
    Shape{mask:0xffe0e000,value:0xe460a000,element:32,memory:8,offset:0,scale:0,store:true,signed:false,immediate:true,xs:14}, // st1b_z_p_ai
    Shape{mask:0xffe0e000,value:0xe440a000,element:64,memory:8,offset:0,scale:0,store:true,signed:false,immediate:true,xs:14}, // st1b_z_p_ai
    Shape{mask:0xffe0a000,value:0xe4e08000,element:32,memory:16,offset:32,scale:1,store:true,signed:false,immediate:false,xs:14}, // st1h_z_p_bz
    Shape{mask:0xffe0a000,value:0xe4a08000,element:64,memory:16,offset:32,scale:1,store:true,signed:false,immediate:false,xs:14}, // st1h_z_p_bz
    Shape{mask:0xffe0a000,value:0xe4808000,element:64,memory:16,offset:32,scale:0,store:true,signed:false,immediate:false,xs:14}, // st1h_z_p_bz
    Shape{mask:0xffe0a000,value:0xe4c08000,element:32,memory:16,offset:32,scale:0,store:true,signed:false,immediate:false,xs:14}, // st1h_z_p_bz
    Shape{mask:0xffe0e000,value:0xe4a0a000,element:64,memory:16,offset:64,scale:1,store:true,signed:false,immediate:false,xs:14}, // st1h_z_p_bz
    Shape{mask:0xffe0e000,value:0xe480a000,element:64,memory:16,offset:64,scale:0,store:true,signed:false,immediate:false,xs:14}, // st1h_z_p_bz
    Shape{mask:0xffe0e000,value:0xe4e0a000,element:32,memory:16,offset:0,scale:0,store:true,signed:false,immediate:true,xs:14}, // st1h_z_p_ai
    Shape{mask:0xffe0e000,value:0xe4c0a000,element:64,memory:16,offset:0,scale:0,store:true,signed:false,immediate:true,xs:14}, // st1h_z_p_ai
    Shape{mask:0xffe0a000,value:0xe5608000,element:32,memory:32,offset:32,scale:2,store:true,signed:false,immediate:false,xs:14}, // st1w_z_p_bz
    Shape{mask:0xffe0a000,value:0xe5208000,element:64,memory:32,offset:32,scale:2,store:true,signed:false,immediate:false,xs:14}, // st1w_z_p_bz
    Shape{mask:0xffe0a000,value:0xe5008000,element:64,memory:32,offset:32,scale:0,store:true,signed:false,immediate:false,xs:14}, // st1w_z_p_bz
    Shape{mask:0xffe0a000,value:0xe5408000,element:32,memory:32,offset:32,scale:0,store:true,signed:false,immediate:false,xs:14}, // st1w_z_p_bz
    Shape{mask:0xffe0e000,value:0xe520a000,element:64,memory:32,offset:64,scale:2,store:true,signed:false,immediate:false,xs:14}, // st1w_z_p_bz
    Shape{mask:0xffe0e000,value:0xe500a000,element:64,memory:32,offset:64,scale:0,store:true,signed:false,immediate:false,xs:14}, // st1w_z_p_bz
    Shape{mask:0xffe0e000,value:0xe560a000,element:32,memory:32,offset:0,scale:0,store:true,signed:false,immediate:true,xs:14}, // st1w_z_p_ai
    Shape{mask:0xffe0e000,value:0xe540a000,element:64,memory:32,offset:0,scale:0,store:true,signed:false,immediate:true,xs:14}, // st1w_z_p_ai
    Shape{mask:0xffe0a000,value:0xe5a08000,element:64,memory:64,offset:32,scale:3,store:true,signed:false,immediate:false,xs:14}, // st1d_z_p_bz
    Shape{mask:0xffe0a000,value:0xe5808000,element:64,memory:64,offset:32,scale:0,store:true,signed:false,immediate:false,xs:14}, // st1d_z_p_bz
    Shape{mask:0xffe0e000,value:0xe5a0a000,element:64,memory:64,offset:64,scale:3,store:true,signed:false,immediate:false,xs:14}, // st1d_z_p_bz
    Shape{mask:0xffe0e000,value:0xe580a000,element:64,memory:64,offset:64,scale:0,store:true,signed:false,immediate:false,xs:14}, // st1d_z_p_bz
    Shape{mask:0xffe0e000,value:0xe5c0a000,element:64,memory:64,offset:0,scale:0,store:true,signed:false,immediate:true,xs:14}, // st1d_z_p_ai
];
// 70 independently encoded physical classes

fn c(width:u8,value:u64)->Expr {Expr::constant(width,value)}
fn b(op:B,left:Expr,right:Expr)->Expr {Expr::binary(op,left,right)}
fn lane(n:u32,e:u16,width:u8)->Expr {
 let bit=e*u16::from(width);
 Expr::extract(Expr::register(register("a64.vector64",n as u16*32+bit/64,64,64)),(bit%64)as u8,width)
}
fn predicate(n:u32,e:u16,width:u8)->Expr {
 let bit=e*u16::from(width)/8;
 Expr::extract(Expr::register(register("a64.predicate64",n as u16*4+bit/64,64,64)),(bit%64)as u8,1)
}
/// Ordinary LD1[BHWD]/LD1S[BHW] gather and ST1[BHWD] scatter, both scalar-base
/// plus vector-offset and vector-base plus scaled immediate addressing.
/// Fault-first/nonfaulting and nontemporal variants have distinct encodings.
pub fn a64(word:u32,address:u64,endian:Endian,vl:u16)->Option<Recipe> {
 if !(128..=2048).contains(&vl)||!vl.is_power_of_two(){return None;}
 let s=*SHAPES.iter().find(|s|word&s.mask==s.value)?;
 let d=word&31;let n=(word>>5)&31;let pg=(word>>10)&7;let m=(word>>16)&31;
 let mut r=Recipe::new(address.wrapping_add(4),64);
 // Check the effective streaming capability before any address, predicate or
 // memory evaluation. FA64 must include every applicable SMCR_ELx control.
 let sm=Expr::extract(Expr::register(register("a64.svcr",0,64,64)),0,1);
 r.guard=Expr::require_context(Expr::select(sm,Expr::register(register("a64.sme_fa64",0,1,1)),c(1,1)),"SVE gather/scatter requires non-streaming mode or effective FA64");
 if !s.immediate && n==31 {
  let any=(0..vl/u16::from(s.element)).fold(c(1,0),|any,e|b(B::Or,any,predicate(pg,e,s.element)));
  let aligned=b(B::Eq,b(B::And,Expr::register(register("a64.sp",0,64,64)),c(64,15)),c(64,0));
  // SA0/SA policy is not an input to this recipe. Aligned SP is independent
  // of that policy; misaligned active use requires an explicit target context.
  // Choose the permitted CHECKSPNONEACTIVE=false behavior for an empty mask.
  r.guard=b(B::And,r.guard,Expr::require_context(Expr::select(any,aligned,c(1,1)),"misaligned active SVE SP access requires architectural SP-alignment policy"));
 }
 let mut values=Vec::new();
 for e in 0..vl/u16::from(s.element) {
  let active=predicate(pg,e,s.element);
  let address=if s.immediate {
   b(B::Add,Expr::cast(lane(n,e,s.element),64,false),c(64,u64::from(m)*u64::from(s.memory/8)))
  }else{
   let base=Expr::register(register(if n==31{"a64.sp"}else{"a64.gpr"},if n==31{0}else{n as u16},64,64));
   let raw=Expr::cast(lane(m,e,s.element),s.offset,false);
   let signed=s.offset==32&&((word>>s.xs)&1)!=0;
   let offset=b(B::Shl,Expr::cast(raw,64,signed),c(64,u64::from(s.scale)));
   b(B::Add,base,offset)
  };
  let memory=Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(address),width:s.memory,endian};
  if s.store {
   r.store_conditional(active,memory,Expr::cast(lane(d,e,s.element),s.memory,false));
  }else{
   let value=r.load_ordered_conditional(active.clone(),memory).expect("audited scalar SVE width");
   values.push(Expr::select(active,Expr::cast(value,s.element,s.signed),c(s.element,0)));
  }
 }
 if !s.store {
  for(chunk,elements)in values.chunks(64/usize::from(s.element)).enumerate(){
   let mut value=c(64,0);
   for(i,element)in elements.iter().enumerate(){value=b(B::Or,value,b(B::Shl,Expr::cast(element.clone(),64,false),c(64,i as u64*u64::from(s.element))));}
   let value=r.bind(value);
   r.write(register("a64.vector64",d as u16*32+chunk as u16,64,64),WritePolicy::ZeroUpper,value);
  }
 }
 Some(r)
}
