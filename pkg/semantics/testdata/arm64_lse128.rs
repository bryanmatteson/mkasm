#![allow(dead_code)]
#[path = "semantics.rs"]
mod semantics;
use semantics::*;
use std::cell::Cell;
fn recipe(word: u32, vl: u16, endian: Endian) -> Option<Recipe> {
    let _ = vl;
    semantics::arm64_atomics::a64(word, 0x1000, endian)
}
struct State { x: [u64; 32], sp: u64, old: u128, calls: Cell<usize>, fault: bool }
impl Machine for State {
 fn read_register(&self,r:Register)->Value { if r.bank=="a64.sp_alignment_enforced"{return Value::known(1,1);} Value::known(64,match r.bank {"a64.gpr"=>self.x[r.index as usize],"a64.sp"=>self.sp,other=>panic!("unexpected register {other}")}) }
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("ordinary load fallback")}
 fn evaluate_atomic(&self,_:&AtomicRequest,_:&[AtomicTransition])->Result<AtomicObservation,EvalError>{panic!("split scalar atomic")}
 fn evaluate_atomic_pair(&self,r:&AtomicRequest,p:&[AtomicTransition])->Result<AtomicPairObservation,EvalError>{self.calls.set(self.calls.get()+1);assert!(p.is_empty());assert_eq!(r.address,16);assert_eq!(r.width,128);assert_eq!(r.scope,MemoryScope::System);assert!(matches!(r.kind,AtomicRequestKind::ReadModifyWritePair{..}));if self.fault{return Err(EvalError::UnsupportedContext)}Ok(AtomicPairObservation{observation:AtomicObservation{old:Some(Value::known(64,self.old as u64)),store_succeeded:None,reservation_token:None,witness:91},old_high:Some(Value::known(64,(self.old>>64)as u64))})}
}
fn state()->State {State{x:std::array::from_fn(|n|(n as u64+1).wrapping_mul(0x9e3779b97f4a7c15)),sp:16,old:0xfedcba98765432100123456789abcdef,calls:Cell::new(0),fault:false}}
#[test] fn every_operation_order_endian_and_independent_register_pair(){
 let mut count=0;
 for endian in [Endian::Little,Endian::Big]{for(base,op)in[(0x19201000,AtomicPairRmwOp::And),(0x19203000,AtomicPairRmwOp::Or),(0x19208000,AtomicPairRmwOp::Exchange)]{for flags in 0..4u32{for rt in 0..31u32{for rt2 in 0..31u32{if rt==rt2{continue}for rn in [rt,rt2,31]{
  let word=base|((flags&1)<<23)|((flags>>1)<<22)|(rt2<<16)|(rn<<5)|rt;let mut s=state();if rn!=31{s.x[rn as usize]=16;}let incoming=(s.x[rt as usize],s.x[rt2 as usize]);let r=recipe(word,128,endian).unwrap();assert_eq!(r.support,Support::Full,"{word:08x}");r.validate().unwrap();assert_eq!(r.atomics.len(),1);let t=evaluate(&r,&s).unwrap();assert_eq!(s.calls.get(),1);assert_eq!(t.events,[OrderedEvent::Atomic(0)]);assert!(t.memory.is_empty());assert_eq!(t.next_pc,Value::known(64,0x1004));let a=&t.atomics[0];let req=a.request.as_ref().unwrap();assert_eq!(req.ordering,match flags{0=>MemoryOrdering::Monotonic,1=>MemoryOrdering::Acquire,2=>MemoryOrdering::Release,_=>MemoryOrdering::AcquireRelease});assert_eq!(req.endian,endian);assert_eq!(a.monitor,ExclusiveMonitorEffect::Preserved);
  let input=match endian{Endian::Little=>u128::from(incoming.0)|(u128::from(incoming.1)<<64),Endian::Big=>(u128::from(incoming.0)<<64)|u128::from(incoming.1)};let expected=match op{AtomicPairRmwOp::Exchange=>input,AtomicPairRmwOp::And=>s.old&!input,AtomicPairRmwOp::Or=>s.old|input};assert_eq!(u128::from(a.stored.unwrap().bits)|(u128::from(a.stored_high.unwrap().bits)<<64),expected,"{word:08x}");assert_eq!(t.registers.len(),2);let old=match endian{Endian::Little=>(s.old as u64,(s.old>>64)as u64),Endian::Big=>((s.old>>64)as u64,s.old as u64)};for(n,bits)in[(rt,old.0),(rt2,old.1)]{assert!(t.registers.iter().any(|w|w.register.bank=="a64.gpr"&&w.register.index==n as u16&&w.value==Value::known(64,bits)));}count+=1;
 }}}}}}assert_eq!(count,66960);
}
#[test] fn overlap_is_permitted_nop_reserved_zero_and_sp_faults_are_explicit(){
 for base in [0x19201000,0x19203000,0x19208000]{for flags in 0..4u32{let op=base|((flags&1)<<23)|((flags>>1)<<22);for n in 0..31u32{let mut s=state();s.sp=17;let r=recipe(op|(n<<16)|(31<<5)|n,128,Endian::Little).unwrap();assert_eq!(r.support,Support::Full);let t=evaluate(&r,&s).unwrap();assert!(t.events.is_empty());assert!(t.registers.is_empty());assert_eq!(s.calls.get(),0);}
 for(rt,rt2)in[(31,1),(1,31),(31,31)]{if let Some(r)=recipe(op|(rt2<<16)|(31<<5)|rt,128,Endian::Little){assert!(matches!(r.support,Support::Unsupported(_)));assert!(r.atomics.is_empty());}}
 let mut s=state();s.sp=17;let r=recipe(op|(1<<16)|(31<<5),128,Endian::Little).unwrap();assert_eq!(evaluate(&r,&s).unwrap().trap,Some(TrapKind::Protection));assert_eq!(s.calls.get(),0);s.sp=16;s.fault=true;assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert_eq!(s.calls.get(),1);
 }}
}
