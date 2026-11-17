package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustAtomicPairEvaluator(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runtime.rs"), []byte(RustRuntime+atomicPairBehaviorTests), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "runtime.rs", "-Dwarnings", "-o", filepath.Join(dir, "pair-tests"))
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile indivisible atomic pairs: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "pair-tests"), "atomic_pair_behavior::")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute indivisible atomic pairs: %v\n%s", err, out)
	}
}

const atomicPairBehaviorTests = `
#[cfg(test)] mod atomic_pair_behavior {
 use super::*;
 use std::cell::Cell;
 #[derive(Clone)] struct Backend {bytes:[u8;32],monitor:Option<ExclusiveReservation>,calls:Cell<usize>,fail:bool,registers:[u64;4]}
 impl Backend {
  fn new(endian:Endian)->Self {let mut s=Self{bytes:[0;32],monitor:None,calls:Cell::new(0),fail:false,registers:[0;4]};Self::store(&mut s.bytes,0,0x0123456789abcdef,0xfedcba9876543210,endian);s}
  fn store(bytes:&mut[u8;32],address:u64,low:u64,high:u64,endian:Endian){let bits=u128::from(low)|(u128::from(high)<<64);let serialized=match endian{Endian::Little=>bits.to_le_bytes(),Endian::Big=>bits.to_be_bytes()};bytes[address as usize..address as usize+16].copy_from_slice(&serialized);}
  fn load(bytes:&[u8;32],address:u64,endian:Endian)->(u64,u64){let b=bytes[address as usize..address as usize+16].try_into().unwrap();let bits=match endian{Endian::Little=>u128::from_le_bytes(b),Endian::Big=>u128::from_be_bytes(b)};(bits as u64,(bits>>64)as u64)}
  fn stamp(bytes:&[u8;32],index:usize)->u64{bytes.iter().fold(index as u64^0x876543210abcdef,|x,b|x.rotate_left(3)^u64::from(*b))}
  fn apply(bytes:&mut[u8;32],a:&AtomicTransition){if let(Some(r),Some(low))=(&a.request,a.stored){assert_eq!(r.width,128);let high=a.stored_high.expect("pair write lost high chunk");assert_eq!(low.width,64);assert_eq!(high.width,64);Self::store(bytes,r.address,low.bits,high.bits,r.endian);}}
  // Model the consumer's witness-aware commit: check all observations against
  // current memory and publish the whole pending state only after all validate.
  fn commit(&mut self,t:&Transition)->Result<(),EvalError>{let mut next=self.clone();for event in &t.events{if let OrderedEvent::Atomic(i)=event{let a=&t.atomics[*i];if let Some(observation)=&a.observation{if observation.witness!=Self::stamp(&next.bytes,*i){return Err(EvalError::InvalidAtomicOutcome);}}Self::apply(&mut next.bytes,a);match a.monitor{ExclusiveMonitorEffect::Preserved=>{},ExclusiveMonitorEffect::Set(r)=>next.monitor=Some(r),ExclusiveMonitorEffect::Cleared=>next.monitor=None}}}for w in &t.registers{next.registers[w.register.index as usize]=w.value.bits;}*self=next;Ok(())}
 }
 impl Machine for Backend {
  fn read_register(&self,r:Register)->Value{Value::known(64,self.registers[r.index as usize])}
  fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("128-bit operation fell back to plain memory")}
  fn evaluate_atomic(&self,_:&AtomicRequest,_:&[AtomicTransition])->Result<AtomicObservation,EvalError>{panic!("128-bit operation fell back to scalar atomic")}
  fn read_exclusive_monitor(&self)->Result<Option<ExclusiveReservation>,EvalError>{Ok(self.monitor)}
  fn evaluate_atomic_pair(&self,r:&AtomicRequest,previous:&[AtomicTransition])->Result<AtomicPairObservation,EvalError>{
   self.calls.set(self.calls.get()+1);assert_eq!(r.width,128);let mut bytes=self.bytes;for p in previous{Self::apply(&mut bytes,p);}
   let reads=matches!(r.kind,AtomicRequestKind::LoadPair|AtomicRequestKind::ReadModifyWritePair{..}|AtomicRequestKind::CompareExchangePair{..}|AtomicRequestKind::LoadLinkedPair);let(low,high)=Self::load(&bytes,r.address,r.endian);
   Ok(AtomicPairObservation{observation:AtomicObservation{old:reads.then(||Value::known(64,low)),store_succeeded:matches!(r.kind,AtomicRequestKind::StoreConditionalPair{..}).then(||!self.fail&&r.reservation.is_some_and(|x|x.width==128&&x.address==r.address&&x.scope==r.scope&&x.token==77)),reservation_token:matches!(r.kind,AtomicRequestKind::LoadLinkedPair).then_some(77),witness:Self::stamp(&bytes,previous.len())},old_high:reads.then(||Value::known(64,high))})
  }
 }
 fn op(kind:AtomicOperationKind,endian:Endian)->AtomicOperation{AtomicOperation{memory:Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,0)),width:128,endian},ordering:MemoryOrdering::Monotonic,scope:MemoryScope::System,kind}}
 fn c(bits:u64)->Expr{Expr::constant(64,bits)}
 fn write(r:&mut Recipe,index:u16,value:Expr){r.write(register("test",index,64,64),WritePolicy::Preserve,Expr::cast(value,64,false));}
 #[test]fn pair_load_store_chunks_and_whole_value_endian(){for endian in [Endian::Little,Endian::Big]{
  let mut state=Backend::new(endian);let before=state.bytes;let mut r=Recipe::new(4,64);let loaded=r.atomic(op(AtomicOperationKind::LoadPair,endian));assert_eq!(loaded.value.as_ref().unwrap().ty.width,64);assert_eq!(loaded.value_high.as_ref().unwrap().ty.width,64);assert!(loaded.success.is_none());
  let low=loaded.value.unwrap();let high=loaded.value_high.unwrap();let mut store=op(AtomicOperationKind::StorePair{low:high.clone(),high:low.clone()},endian);store.memory.address=Box::new(c(16));r.atomic(store);write(&mut r,0,low);write(&mut r,1,high);
  let t=evaluate(&r,&state).unwrap();assert_eq!(state.calls.get(),2);assert_eq!(state.bytes,before);assert!(t.memory.is_empty());assert_eq!(t.atomics.len(),2);assert_eq!(t.atomics[1].stored.unwrap().bits,0xfedcba9876543210);assert_eq!(t.atomics[1].stored_high.unwrap().bits,0x0123456789abcdef);state.commit(&t).unwrap();assert_eq!(state.registers[..2],[0x0123456789abcdef,0xfedcba9876543210]);assert_eq!(Backend::load(&state.bytes,16,endian),(0xfedcba9876543210,0x0123456789abcdef));
  let expected=match endian{Endian::Little=>0x0123456789abcdeffedcba9876543210u128.to_le_bytes(),Endian::Big=>0x0123456789abcdeffedcba9876543210u128.to_be_bytes()};assert_eq!(state.bytes[16..],expected);
 }}
 #[test]fn pair_rmw_operations_chain_observations_and_commit_indivisibly(){
  for endian in [Endian::Little,Endian::Big]{for ordering in [MemoryOrdering::Monotonic,MemoryOrdering::Acquire,MemoryOrdering::Release,MemoryOrdering::AcquireRelease,MemoryOrdering::SequentiallyConsistent]{for operation in [AtomicPairRmwOp::Exchange,AtomicPairRmwOp::And,AtomicPairRmwOp::Or]{
   let mut state=Backend::new(endian);let original=state.bytes;let mut r=Recipe::new(4,64);let apply=|a:u64,b:u64|match operation{AtomicPairRmwOp::Exchange=>b,AtomicPairRmwOp::And=>a&b,AtomicPairRmwOp::Or=>a|b};let values=[(0x13579bdf2468ace0,0xf0e1d2c3b4a59687),(0x1122334455667788,0x8899aabbccddeeff)];
   for(i,(low,high))in values.into_iter().enumerate(){let mut a=op(AtomicOperationKind::ReadModifyWritePair{operation,low:c(low),high:c(high)},endian);a.ordering=ordering;let out=r.atomic(a);assert!(out.success.is_none());write(&mut r,(i*2)as u16,out.value.unwrap());write(&mut r,(i*2+1)as u16,out.value_high.unwrap());}
   let t=evaluate(&r,&state).unwrap();assert_eq!(state.bytes,original);assert_eq!(state.calls.get(),2);assert!(t.memory.is_empty());assert_eq!(t.events,[OrderedEvent::Atomic(0),OrderedEvent::Atomic(1)]);assert!(t.atomics.iter().all(|a|a.monitor==ExclusiveMonitorEffect::Preserved));let first=(apply(0x0123456789abcdef,values[0].0),apply(0xfedcba9876543210,values[0].1));
   let mut interfered=state.clone();interfered.bytes[15]^=1;let before=interfered.bytes;assert_eq!(interfered.commit(&t),Err(EvalError::InvalidAtomicOutcome));assert_eq!(interfered.bytes,before);assert_eq!(interfered.registers,[0;4]);
   state.commit(&t).unwrap();assert_eq!(state.registers,[0x0123456789abcdef,0xfedcba9876543210,first.0,first.1]);assert_eq!(Backend::load(&state.bytes,0,endian),(apply(first.0,values[1].0),apply(first.1,values[1].1)));
  }}}
 }
 #[test]fn pair_rmw_capability_inputs_and_observations_are_checked(){
  for operation in [AtomicPairRmwOp::Exchange,AtomicPairRmwOp::And,AtomicPairRmwOp::Or]{
   let kind=||AtomicOperationKind::ReadModifyWritePair{operation,low:c(1),high:c(2)};let mut r=Recipe::new(4,64);r.atomic(op(kind(),Endian::Little));assert_eq!(evaluate(&r,&NarrowOnly),Err(EvalError::Unsupported));
   for high in [None,Some(Value::known(32,1)),Some(Value::unknown(64))]{assert_eq!(evaluate(&r,&Malformed(AtomicPairObservation{observation:AtomicObservation{old:Some(Value::known(64,1)),store_succeeded:None,reservation_token:None,witness:0},old_high:high})),Err(EvalError::InvalidAtomicOutcome));}
   for (low,high) in [(Expr::constant(32,1),c(2)),(c(1),Expr::constant(32,2))]{let mut r=Recipe::new(4,64);r.atomic(op(AtomicOperationKind::ReadModifyWritePair{operation,low,high},Endian::Little));assert_eq!(r.validate(),Err(EvalError::InvalidExpression));}
   let mut r=Recipe::new(4,64);r.atomic(op(AtomicOperationKind::ReadModifyWritePair{operation,low:c(1),high:Expr::undefined(64,"unknown pair input")},Endian::Little));assert_eq!(evaluate(&r,&Backend::new(Endian::Little)),Err(EvalError::UnknownAtomicValue));
  }
 }
 #[test]fn pair_strong_cas_compares_both_chunks_and_reuses_results(){for endian in [Endian::Little,Endian::Big]{
  let mut state=Backend::new(endian);let mut r=Recipe::new(4,64);
  let first=r.atomic(op(AtomicOperationKind::CompareExchangePair{expected_low:c(0x0123456789abcdef),expected_high:c(0xfedcba9876543210),replacement_low:c(11),replacement_high:c(22),failure_ordering:MemoryOrdering::Monotonic},endian));
  let second=r.atomic(op(AtomicOperationKind::CompareExchangePair{expected_low:c(11),expected_high:c(23),replacement_low:c(33),replacement_high:c(44),failure_ordering:MemoryOrdering::Monotonic},endian));
  r.atomic(op(AtomicOperationKind::CompareExchangePair{expected_low:c(12),expected_high:c(22),replacement_low:c(55),replacement_high:c(66),failure_ordering:MemoryOrdering::Monotonic},endian));
  write(&mut r,0,first.success.unwrap());write(&mut r,1,second.success.unwrap());write(&mut r,2,second.value.unwrap());write(&mut r,3,second.value_high.unwrap());let t=evaluate(&r,&state).unwrap();assert_eq!(t.atomics[0].success,Some(true));assert_eq!(t.atomics[1].success,Some(false));assert_eq!(t.atomics[2].success,Some(false));assert!(t.atomics[2].stored.is_none());assert!(t.atomics[2].stored_high.is_none());assert!(t.atomics[1].stored.is_none());assert!(t.atomics[1].stored_high.is_none());state.commit(&t).unwrap();assert_eq!(state.registers,[1,0,11,22]);assert_eq!(Backend::load(&state.bytes,0,endian),(11,22));
 }}
 #[test]fn pair_ll_sc_is_one_reservation_and_clears_on_all_outcomes(){
  for(clear,interference,success)in[(false,false,true),(true,false,false),(false,true,false)]{let endian=Endian::Little;let mut state=Backend::new(endian);state.fail=interference;let mut r=Recipe::new(4,64);let linked=r.atomic(op(AtomicOperationKind::LoadLinkedPair,endian));if clear{r.clear_exclusive();}let sc=r.atomic(op(AtomicOperationKind::StoreConditionalPair{low:linked.value_high.unwrap(),high:linked.value.unwrap()},endian));write(&mut r,0,sc.success.unwrap());let t=evaluate(&r,&state).unwrap();assert!(matches!(t.atomics[0].monitor,ExclusiveMonitorEffect::Set(ExclusiveReservation{width:128,..})));assert_eq!(t.atomics.last().unwrap().success,Some(success));assert_eq!(t.atomics.last().unwrap().monitor,ExclusiveMonitorEffect::Cleared);state.commit(&t).unwrap();assert!(state.monitor.is_none());assert_eq!(state.registers[0],success as u64);assert_eq!(Backend::load(&state.bytes,0,endian),if success{(0xfedcba9876543210,0x0123456789abcdef)}else{(0x0123456789abcdef,0xfedcba9876543210)});}
 }
 #[test]fn pair_witness_interference_or_tampering_rejects_the_whole_commit(){
  let mut state=Backend::new(Endian::Little);let mut r=Recipe::new(4,64);r.atomic(op(AtomicOperationKind::StorePair{low:c(5),high:c(6)},Endian::Little));r.atomic(op(AtomicOperationKind::StorePair{low:c(7),high:c(8)},Endian::Little));write(&mut r,0,c(42));let t=evaluate(&r,&state).unwrap();let original=state.bytes;
  let mut corrupted=t.clone();corrupted.atomics[1].observation.as_mut().unwrap().witness^=1;assert_eq!(state.commit(&corrupted),Err(EvalError::InvalidAtomicOutcome));assert_eq!(state.bytes,original);assert_eq!(state.registers,[0;4]);
  state.bytes[0]^=1;let interfered=state.bytes;assert_eq!(state.commit(&t),Err(EvalError::InvalidAtomicOutcome));assert_eq!(state.bytes,interfered);assert_eq!(state.registers,[0;4]);
 }
 struct Malformed(AtomicPairObservation);
 impl Machine for Malformed{fn read_register(&self,_:Register)->Value{Value::known(64,0)}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("ordinary fallback")}fn read_exclusive_monitor(&self)->Result<Option<ExclusiveReservation>,EvalError>{Ok(Some(ExclusiveReservation{address:0,width:64,scope:MemoryScope::System,token:77}))}fn evaluate_atomic_pair(&self,_:&AtomicRequest,_:&[AtomicTransition])->Result<AtomicPairObservation,EvalError>{Ok(self.0.clone())}}
 #[test]fn pair_malformed_results_and_wrong_width_reservations_are_rejected(){
  let good=AtomicObservation{old:Some(Value::known(64,1)),store_succeeded:None,reservation_token:None,witness:1};for(old,high)in[(None,Some(Value::known(64,2))),(Some(Value::known(32,1)),Some(Value::known(64,2))),(Some(Value::known(64,1)),None),(Some(Value::known(64,1)),Some(Value::known(32,2))),(Some(Value::known(64,1)),Some(Value::unknown(64)))]{let mut r=Recipe::new(4,64);r.atomic(op(AtomicOperationKind::LoadPair,Endian::Little));let mut observation=good.clone();observation.old=old;assert_eq!(evaluate(&r,&Malformed(AtomicPairObservation{observation,old_high:high})),Err(EvalError::InvalidAtomicOutcome));}
  let mut r=Recipe::new(4,64);r.atomic(op(AtomicOperationKind::StoreConditionalPair{low:c(1),high:c(2)},Endian::Little));assert_eq!(evaluate(&r,&Malformed(AtomicPairObservation{observation:AtomicObservation{old:None,store_succeeded:Some(true),reservation_token:None,witness:1},old_high:None})),Err(EvalError::InvalidAtomicOutcome));
  let mut r=Recipe::new(4,64);r.atomic(op(AtomicOperationKind::LoadLinkedPair,Endian::Little));assert_eq!(evaluate(&r,&Malformed(AtomicPairObservation{observation:good.clone(),old_high:Some(Value::known(64,2))})),Err(EvalError::InvalidAtomicOutcome));
  let mut r=Recipe::new(4,64);r.atomic(op(AtomicOperationKind::StorePair{low:c(1),high:c(2)},Endian::Little));let mut observation=good;observation.old=None;assert_eq!(evaluate(&r,&Malformed(AtomicPairObservation{observation,old_high:Some(Value::known(64,2))})),Err(EvalError::InvalidAtomicOutcome));
 }
 struct NarrowOnly;
 impl Machine for NarrowOnly{fn read_register(&self,_:Register)->Value{Value::known(64,0)}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("ordinary fallback")}fn evaluate_atomic(&self,_:&AtomicRequest,_:&[AtomicTransition])->Result<AtomicObservation,EvalError>{panic!("pair split into scalar atomic")}}
 #[test]fn pair_capability_and_graph_validation_are_explicit(){
  let mut r=Recipe::new(4,64);r.atomic(op(AtomicOperationKind::LoadPair,Endian::Little));assert_eq!(evaluate(&r,&NarrowOnly),Err(EvalError::Unsupported));
  let mut r=Recipe::new(4,64);let mut load=op(AtomicOperationKind::LoadPair,Endian::Little);load.memory.width=64;r.atomic(load);assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
  let mut r=Recipe::new(4,64);r.atomic(op(AtomicOperationKind::Load,Endian::Little));assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
  let mut r=Recipe::new(4,64);r.atomic(op(AtomicOperationKind::StorePair{low:Expr::constant(32,1),high:c(2)},Endian::Little));assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
  let mut r=Recipe::new(4,64);r.atomic(op(AtomicOperationKind::StorePair{low:c(1),high:Expr::undefined(64,"unavailable chunk")},Endian::Little));assert_eq!(evaluate(&r,&Backend::new(Endian::Little)),Err(EvalError::UnknownAtomicValue));
 }
}
`
