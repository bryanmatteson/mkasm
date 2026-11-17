#[allow(dead_code)]mod runtime;
use runtime::*;
use runtime::arm64_sve_memory::a64;
use std::{cell::RefCell,collections::BTreeMap};
#[derive(Default)]struct State {regs:BTreeMap<(&'static str,u16),Value>,reads:RefCell<Vec<(u64,u8,Endian)>>,fail:Option<u64>}
fn bits(w:u8)->u64 {if w==64{u64::MAX}else{(1u64<<w)-1}}
fn byte(a:u64)->u8 {(a.wrapping_mul(37)^(a>>7)^0xa5)as u8}
fn memory(a:u64,w:u8,endian:Endian)->u64 {
 let mut v=0;for i in 0..w/8{let shift=if endian==Endian::Little{i}else{w/8-1-i};v|=u64::from(byte(a.wrapping_add(u64::from(i))))<<(shift*8);}v
}
impl Machine for State{
 fn read_register(&self,r:Register)->Value{self.regs.get(&(r.bank,r.index)).copied().unwrap_or_else(||Value::unknown(64))}
 fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{self.reads.borrow_mut().push((a,w,e));if self.fail==Some(a){Err(EvalError::Memory)}else{Ok(Value::known(w,memory(a,w,e)))}}
}
impl State{
 fn set(&mut self,bank:&'static str,n:u16,w:u8,v:u64){self.regs.insert((bank,n),Value::known(w,v));}
 fn context(&mut self,streaming:bool,fa64:bool){self.set("a64.svcr",0,64,u64::from(streaming));self.set("a64.sme_fa64",0,1,u64::from(fa64));}
 fn vector(&mut self,n:u16,values:&[u64],w:u8){for(chunk,es)in values.chunks(64/usize::from(w)).enumerate(){let mut v=0;for(i,e)in es.iter().enumerate(){v|=(e&bits(w))<<(i*usize::from(w));}self.set("a64.vector64",n*32+chunk as u16,64,v);}}
 fn pred(&mut self,vl:u16,w:u8,active:impl Fn(usize)->bool){for chunk in 0..4{let mut v=0;for e in 0..usize::from(vl)/usize::from(w){let bit=e*usize::from(w)/8;if bit/64==chunk&&active(e){v|=1<<(bit%64);}}self.set("a64.predicate64",chunk as u16,64,v);}}
}
// Explicit register diagrams from the June 2026 pages; fields are independently
// interpreted below as host lane arithmetic, byte reads and destination writes.
const CASES:&[(u32,u8,u8,u8,u8,bool,bool,bool,u8)]=&[
 (0xc4004000,64,8,32,0,false,false,false,22),
 (0x84004000,32,8,32,0,false,false,false,22),
 (0xc440c000,64,8,64,0,false,false,false,22),
 (0x8420c000,32,8,0,0,false,false,true,22),
 (0xc420c000,64,8,0,0,false,false,true,22),
 (0x84a04000,32,16,32,1,false,false,false,22),
 (0xc4a04000,64,16,32,1,false,false,false,22),
 (0xc4804000,64,16,32,0,false,false,false,22),
 (0x84804000,32,16,32,0,false,false,false,22),
 (0xc4e0c000,64,16,64,1,false,false,false,22),
 (0xc4c0c000,64,16,64,0,false,false,false,22),
 (0x84a0c000,32,16,0,0,false,false,true,22),
 (0xc4a0c000,64,16,0,0,false,false,true,22),
 (0x85204000,32,32,32,2,false,false,false,22),
 (0xc5204000,64,32,32,2,false,false,false,22),
 (0xc5004000,64,32,32,0,false,false,false,22),
 (0x85004000,32,32,32,0,false,false,false,22),
 (0xc560c000,64,32,64,2,false,false,false,22),
 (0xc540c000,64,32,64,0,false,false,false,22),
 (0x8520c000,32,32,0,0,false,false,true,22),
 (0xc520c000,64,32,0,0,false,false,true,22),
 (0xc5a04000,64,64,32,3,false,false,false,22),
 (0xc5804000,64,64,32,0,false,false,false,22),
 (0xc5e0c000,64,64,64,3,false,false,false,22),
 (0xc5c0c000,64,64,64,0,false,false,false,22),
 (0xc5a0c000,64,64,0,0,false,false,true,22),
 (0xc4000000,64,8,32,0,false,true,false,22),
 (0x84000000,32,8,32,0,false,true,false,22),
 (0xc4408000,64,8,64,0,false,true,false,22),
 (0x84208000,32,8,0,0,false,true,true,22),
 (0xc4208000,64,8,0,0,false,true,true,22),
 (0x84a00000,32,16,32,1,false,true,false,22),
 (0xc4a00000,64,16,32,1,false,true,false,22),
 (0xc4800000,64,16,32,0,false,true,false,22),
 (0x84800000,32,16,32,0,false,true,false,22),
 (0xc4e08000,64,16,64,1,false,true,false,22),
 (0xc4c08000,64,16,64,0,false,true,false,22),
 (0x84a08000,32,16,0,0,false,true,true,22),
 (0xc4a08000,64,16,0,0,false,true,true,22),
 (0xc5200000,64,32,32,2,false,true,false,22),
 (0xc5000000,64,32,32,0,false,true,false,22),
 (0xc5608000,64,32,64,2,false,true,false,22),
 (0xc5408000,64,32,64,0,false,true,false,22),
 (0xc5208000,64,32,0,0,false,true,true,22),
 (0xe4008000,64,8,32,0,true,false,false,14),
 (0xe4408000,32,8,32,0,true,false,false,14),
 (0xe400a000,64,8,64,0,true,false,false,14),
 (0xe460a000,32,8,0,0,true,false,true,14),
 (0xe440a000,64,8,0,0,true,false,true,14),
 (0xe4e08000,32,16,32,1,true,false,false,14),
 (0xe4a08000,64,16,32,1,true,false,false,14),
 (0xe4808000,64,16,32,0,true,false,false,14),
 (0xe4c08000,32,16,32,0,true,false,false,14),
 (0xe4a0a000,64,16,64,1,true,false,false,14),
 (0xe480a000,64,16,64,0,true,false,false,14),
 (0xe4e0a000,32,16,0,0,true,false,true,14),
 (0xe4c0a000,64,16,0,0,true,false,true,14),
 (0xe5608000,32,32,32,2,true,false,false,14),
 (0xe5208000,64,32,32,2,true,false,false,14),
 (0xe5008000,64,32,32,0,true,false,false,14),
 (0xe5408000,32,32,32,0,true,false,false,14),
 (0xe520a000,64,32,64,2,true,false,false,14),
 (0xe500a000,64,32,64,0,true,false,false,14),
 (0xe560a000,32,32,0,0,true,false,true,14),
 (0xe540a000,64,32,0,0,true,false,true,14),
 (0xe5a08000,64,64,32,3,true,false,false,14),
 (0xe5808000,64,64,32,0,true,false,false,14),
 (0xe5a0a000,64,64,64,3,true,false,false,14),
 (0xe580a000,64,64,64,0,true,false,false,14),
 (0xe5c0a000,64,64,0,0,true,false,true,14),
];
#[test]fn every_physical_class_has_exact_lane_values_access_widths_endian_and_aliases(){
 assert_eq!(CASES.len(),70);
 for &(base,w,mw,ow,scale,store,signed,imm,xs)in CASES{for vl in [128,256,512,1024,2048]{for endian in [Endian::Little,Endian::Big]{for sx in [false,true]{for alias in [false,true]{
  let count=usize::from(vl)/usize::from(w);let d=if alias{2}else{0};let n=if imm{2}else{1};let m=if imm{7}else{2};
  let word=base|(n<<5)|(m<<16)|d|if !imm&&ow==32{u32::from(sx)<<xs}else{0};
  let offsets:Vec<_>=(0..count).map(|e|if imm{0x1000+e as u64*17}else{match e%4{0=>0xfffffff0,1=>0,2=>31,_=>0x100000010}}&bits(w)).collect();
  let data:Vec<_>=(0..count).map(|e|0xfedcba9876543210u64.rotate_left(e as u32*7)&bits(w)).collect();
  let mut s=State::default();s.context(false,false);s.set("a64.gpr",1,64,u64::MAX-0x800);s.pred(vl,w,|e|e%3!=1);
  s.vector(2,&offsets,w);if d!=2{s.vector(d as u16,&data,w);}
  let source=if d==2{&offsets}else{&data};
  let mut expected_reads=vec![];let mut expected_stores=vec![];let mut expected=vec![];
  for e in 0..count{
   if e%3==1{expected.push(0);continue;}
   let address=if imm{offsets[e].wrapping_add(u64::from(m)*u64::from(mw/8))}else{
    let raw=offsets[e]&bits(ow);let off=if ow==32&&sx{raw as u32 as i32 as i64 as u64}else{raw};(u64::MAX-0x800).wrapping_add(off.wrapping_shl(u32::from(scale)))
   };
   if store{expected_stores.push((address,source[e]&bits(mw)));}else{expected_reads.push((address,mw,endian));let raw=memory(address,mw,endian);let value=if signed{((raw<<(64-mw))as i64>>(64-mw))as u64}else{raw};expected.push(value&bits(w));}
  }
  let recipe=a64(word,0x1000,endian,vl).unwrap();assert_eq!(recipe.support,Support::Full);recipe.validate().unwrap();let t=evaluate(&recipe,&s).unwrap();assert_eq!(t.trap,None);assert_eq!(t.next_pc,Value::known(64,0x1004));
  assert_eq!(*s.reads.borrow(),expected_reads,"{word:08x} vl{vl}");
  if store{
   assert!(t.registers.is_empty());assert_eq!(t.memory.len(),expected_stores.len());
   for (actual,(address,value))in t.memory.iter().zip(expected_stores){assert_eq!(actual.address,address);assert_eq!(actual.value,Value::known(mw,value));assert_eq!(actual.endian,endian);}
   assert_eq!(t.events,(0..t.memory.len()).map(OrderedEvent::Store).collect::<Vec<_>>());
  }else{
   assert!(t.memory.is_empty());assert_eq!(t.registers.len(),usize::from(vl/64));
   for(e,value)in expected.iter().enumerate(){let bit=e*usize::from(w);let chunk=t.registers.iter().find(|v|v.register.index==d as u16*32+(bit/64)as u16).unwrap();assert!(chunk.value.is_known());assert_eq!((chunk.value.bits>>(bit%64))&bits(w),*value,"{word:08x} vl{vl} e{e}");}
  }
 }}}}}
}
#[test]fn inactive_lanes_do_not_read_unknown_bases_offsets_or_store_values(){
 for &(word,w,_,_,_,store,_,_,_)in CASES{let mut s=State::default();s.context(false,false);s.pred(2048,w,|_|false);let r=a64(word,0,Endian::Little,2048).unwrap();let t=evaluate(&r,&s).unwrap();assert!(s.reads.borrow().is_empty());assert!(t.memory.is_empty());if !store{assert!(t.registers.iter().all(|v|v.value==Value::known(64,0)));}}
}
#[test]fn lane_fault_order_stops_at_first_active_failure_and_alias_uses_incoming_values(){
 let mut s=State::default();s.context(false,false);s.pred(128,32,|e|e!=1);s.set("a64.gpr",1,64,0x1000);s.vector(2,&[0,99,16,32],32);s.fail=Some(0x1010);
 let r=a64(0x85004000|(2<<16)|(1<<5)|2,0,Endian::Little,128).unwrap();assert_eq!(evaluate(&r,&s),Err(EvalError::Memory));assert_eq!(*s.reads.borrow(),vec![(0x1000,32,Endian::Little),(0x1010,32,Endian::Little)]);
}
#[test]fn streaming_context_is_checked_before_predicates_addresses_or_memory(){
 let mut s=State::default();s.context(true,false);let r=a64(0x85004000,0,Endian::Little,128).unwrap();assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert!(s.reads.borrow().is_empty());
 s.context(true,true);s.pred(128,32,|_|false);assert!(evaluate(&r,&s).is_ok());
}
#[test]fn first_fault_and_invalid_vector_lengths_do_not_inherit_ordinary_recipes(){
 for &(word,_,_,_,_,store,_,_,_)in CASES{if !store{assert!(a64(word|(1<<13),0,Endian::Little,128).is_none());}}
 for vl in [0,64,192,384,4096]{assert!(a64(0x85004000,0,Endian::Little,vl).is_none());}
}
#[test]fn sp_alignment_is_qualified_before_active_memory_but_empty_masks_suppress_sp(){
 for word in [0x850243e0,0xe54283e0]{
  let mut s=State::default();s.context(false,false);s.pred(128,32,|e|e==0);s.vector(2,&[0;4],32);s.vector(0,&[7;4],32);s.set("a64.sp",0,64,0x1004);
  let r=a64(word,0,Endian::Little,128).unwrap();assert_eq!(r.support,Support::Full);assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert!(s.reads.borrow().is_empty());
  s.set("a64.sp",0,64,0x1000);let t=evaluate(&r,&s).unwrap();if word>>28==8{assert_eq!(*s.reads.borrow(),vec![(0x1000,32,Endian::Little)]);}else{assert_eq!(t.memory[0].address,0x1000);}
  let mut empty=State::default();empty.context(false,false);empty.pred(128,32,|_|false);assert!(evaluate(&r,&empty).is_ok());assert!(empty.reads.borrow().is_empty());
 }
}
