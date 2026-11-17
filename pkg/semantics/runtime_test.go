package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustScalarEvaluator(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runtime.rs"), []byte(RustRuntime), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "runtime.rs", "-Dwarnings", "-o", filepath.Join(dir, "runtime-tests"))
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile recipe evaluator: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "runtime-tests"))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("evaluate scalar recipes: %v\n%s", err, out)
	}
}

func TestRustAtomicEvaluator(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runtime.rs"), []byte(RustRuntime+rustAtomicBehaviorTests), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "runtime.rs", "-Dwarnings", "-o", filepath.Join(dir, "atomic-tests"))
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile native atomic recipes: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "atomic-tests"), "atomic_behavior::")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute native atomic recipes: %v\n%s", err, out)
	}
}

const rustAtomicBehaviorTests = `
#[cfg(test)]
mod atomic_behavior {
 use super::*;
 use std::cell::Cell;
 #[derive(Clone)]
 struct Backend { bytes:[u8;16], monitor:Option<ExclusiveReservation>, fail_sc:bool, calls:Cell<usize>, monitor_reads:Cell<usize> }
 impl Backend {
  fn new()->Self {let mut bytes=[0;16];bytes[..2].copy_from_slice(&[0x12,0x34]);Self{bytes,monitor:None,fail_sc:false,calls:Cell::new(0),monitor_reads:Cell::new(0)}}
  fn write(bytes:&mut[u8;16],address:u64,value:Value,endian:Endian){let count=usize::from(value.width/8);let encoded=match endian{Endian::Little=>value.bits.to_le_bytes(),Endian::Big=>value.bits.to_be_bytes()};let source=match endian{Endian::Little=>&encoded[..count],Endian::Big=>&encoded[8-count..]};bytes[address as usize..address as usize+count].copy_from_slice(source);}
  fn commit(&self,t:&Transition)->Self {
   let mut next=self.clone();
   for event in &t.events {match event {
    OrderedEvent::Atomic(index)=>{let a=&t.atomics[*index];if let(Some(r),Some(v))=(&a.request,a.stored){assert_eq!(a.observation.as_ref().unwrap().witness,*index as u64+100);Self::write(&mut next.bytes,r.address,v,r.endian);}match a.monitor{ExclusiveMonitorEffect::Set(r)=>next.monitor=Some(r),ExclusiveMonitorEffect::Cleared=>next.monitor=None,ExclusiveMonitorEffect::Preserved=>{}}}
    OrderedEvent::Store(index)=>{let w=&t.memory[*index];Self::write(&mut next.bytes,w.address,w.value,w.endian);}
    OrderedEvent::ExclusiveMonitorClear=>next.monitor=None,
    OrderedEvent::Barrier(_)=>{}
    OrderedEvent::AllocationTagStore(_)=>panic!("unexpected allocation tag store in scalar atomic test"),
    OrderedEvent::WideStore(_)=>panic!("unexpected wide store in scalar atomic test"),
    OrderedEvent::TimedWait{..}|OrderedEvent::Wait{..}|OrderedEvent::SendEvent{..}=>panic!("unexpected wait/event in scalar atomic test"),
   }}next
  }
 }
 impl Machine for Backend {
  fn read_register(&self,_:Register)->Value{Value::known(64,0)}
  fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("atomic path used ordinary read_memory")}
  fn read_exclusive_monitor(&self)->Result<Option<ExclusiveReservation>,EvalError>{self.monitor_reads.set(self.monitor_reads.get()+1);Ok(self.monitor)}
  fn evaluate_atomic(&self,r:&AtomicRequest,previous:&[AtomicTransition])->Result<AtomicObservation,EvalError>{
   self.calls.set(self.calls.get()+1);
   if r.scope==MemoryScope::Named("unsupported"){return Err(EvalError::Unsupported);}
   let mut bytes=self.bytes;for a in previous{if let(Some(p),Some(v))=(&a.request,a.stored){Self::write(&mut bytes,p.address,v,p.endian);}}
   let read=matches!(r.kind,AtomicRequestKind::Load|AtomicRequestKind::ReadModifyWrite{..}|AtomicRequestKind::CompareExchange{..}|AtomicRequestKind::LoadLinked);
   let old=if read{let mut bits=0u64;let count=usize::from(r.width/8);for i in 0..count{let shift=match r.endian{Endian::Little=>i,Endian::Big=>count-i-1};bits|=u64::from(bytes[r.address as usize+i])<<(shift*8);}Some(Value::known(r.width,bits))}else{None};
   Ok(AtomicObservation{old,store_succeeded:matches!(r.kind,AtomicRequestKind::StoreConditional{..}).then(||!self.fail_sc&&r.reservation.is_some_and(|x|x.address==r.address&&x.width==r.width&&x.scope==r.scope&&x.token==7)),reservation_token:matches!(r.kind,AtomicRequestKind::LoadLinked).then_some(7),witness:previous.len() as u64+100})
  }
 }
 fn operation(kind:AtomicOperationKind)->AtomicOperation{AtomicOperation{memory:Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,0)),width:16,endian:Endian::Big},ordering:MemoryOrdering::Monotonic,scope:MemoryScope::System,kind}}
 fn write(r:&mut Recipe,index:u16,value:Expr){r.write(register("test",index,value.ty.width,value.ty.width),WritePolicy::Preserve,value);}
 #[test] fn native_ordered_results_and_endian_commit(){
  let state=Backend::new();let mut r=Recipe::new(4,64);
  let mut load=operation(AtomicOperationKind::Load);load.ordering=MemoryOrdering::Acquire;load.scope=MemoryScope::Named("inner-shareable");
  let old=r.atomic(load).value.unwrap();
  let mut rmw=operation(AtomicOperationKind::ReadModifyWrite{operation:AtomicRmwOp::Add,value:Expr::binary(BinaryOp::Add,old.clone(),Expr::constant(16,1))});rmw.ordering=MemoryOrdering::AcquireRelease;
  let observed=r.atomic(rmw).value.unwrap();
  let mut store=operation(AtomicOperationKind::Store{value:observed.clone()});store.ordering=MemoryOrdering::Release;store.memory.address=Box::new(Expr::constant(64,4));store.memory.endian=Endian::Little;r.atomic(store);
  write(&mut r,0,Expr::binary(BinaryOp::Add,observed,Expr::constant(16,2)));
  let t=evaluate(&r,&state).unwrap();assert_eq!(state.calls.get(),3);assert_eq!(state.bytes[0..2],[0x12,0x34]);assert!(t.memory.is_empty());assert_eq!(t.atomics.len(),3);assert_eq!(t.events,[OrderedEvent::Atomic(0),OrderedEvent::Atomic(1),OrderedEvent::Atomic(2)]);assert_eq!(t.registers[0].value.bits,0x1236);
  assert_eq!(t.atomics[0].request.as_ref().unwrap().ordering,MemoryOrdering::Acquire);assert_eq!(t.atomics[0].request.as_ref().unwrap().scope,MemoryScope::Named("inner-shareable"));
  assert_eq!(t.atomics[1].value.unwrap().bits,0x1234);assert_eq!(t.atomics[1].stored.unwrap().bits,0x2469);
  let next=state.commit(&t);assert_eq!(next.bytes[0..2],[0x24,0x69]);assert_eq!(next.bytes[4..6],[0x34,0x12]);
 }
 #[test] fn native_strong_cas_success_failure_and_result_reuse(){
  let state=Backend::new();let mut r=Recipe::new(4,64);
  let cas=|expected,replacement|operation(AtomicOperationKind::CompareExchange{expected:Expr::constant(16,expected),replacement:Expr::constant(16,replacement),failure_ordering:MemoryOrdering::Acquire});
  let mut first=cas(0x1234,0xbeef);first.ordering=MemoryOrdering::AcquireRelease;let first=r.atomic(first);
  let mut second=cas(0x1234,0x4444);second.ordering=MemoryOrdering::SequentiallyConsistent;let second=r.atomic(second);
  write(&mut r,0,first.value.unwrap());write(&mut r,1,second.value.clone().unwrap());write(&mut r,2,first.success.clone().unwrap());write(&mut r,3,second.success.unwrap());r.branch(FlowKind::Branch,first.success.unwrap(),Expr::cast(second.value.unwrap(),64,false));
  let t=evaluate(&r,&state).unwrap();assert_eq!(t.atomics[0].success,Some(true));assert_eq!(t.atomics[0].stored.unwrap().bits,0xbeef);assert_eq!(t.atomics[1].success,Some(false));assert!(t.atomics[1].stored.is_none());assert_eq!(t.registers.iter().map(|x|x.value.bits).collect::<Vec<_>>(),[0x1234,0xbeef,1,0]);assert_eq!(t.next_pc.bits,0xbeef);assert_eq!(state.commit(&t).bytes[0..2],[0xbe,0xef]);
 }
 #[test] fn native_all_rmw_operations_wrap_and_sign(){
  for(op,expected)in[(AtomicRmwOp::Exchange,2),(AtomicRmwOp::Add,0),(AtomicRmwOp::Subtract,0xfc),(AtomicRmwOp::And,2),(AtomicRmwOp::Or,0xfe),(AtomicRmwOp::Xor,0xfc),(AtomicRmwOp::SignedMax,2),(AtomicRmwOp::SignedMin,0xfe),(AtomicRmwOp::UnsignedMax,0xfe),(AtomicRmwOp::UnsignedMin,2)]{
   let mut state=Backend::new();state.bytes[0]=0xfe;let mut r=Recipe::new(4,64);let mut a=operation(AtomicOperationKind::ReadModifyWrite{operation:op,value:Expr::constant(8,2)});a.memory.width=8;r.atomic(a);let t=evaluate(&r,&state).unwrap();assert_eq!(t.atomics[0].value.unwrap().bits,0xfe);assert_eq!(t.atomics[0].stored.unwrap().bits,expected);assert_eq!(state.commit(&t).bytes[0],expected as u8);
  }
  let mut state=Backend::new();state.bytes[..8].fill(0xff);let mut r=Recipe::new(4,64);let mut a=operation(AtomicOperationKind::ReadModifyWrite{operation:AtomicRmwOp::Add,value:Expr::constant(64,1)});a.memory.width=64;r.atomic(a);assert_eq!(evaluate(&r,&state).unwrap().atomics[0].stored.unwrap().bits,0);
 }
 #[test] fn native_ll_sc_monitor_success_failure_clear_and_interference(){
  for (clear,interference,success)in[(false,false,true),(true,false,false),(false,true,false)]{
   let mut state=Backend::new();state.fail_sc=interference;let mut r=Recipe::new(4,64);let linked=r.atomic(operation(AtomicOperationKind::LoadLinked));if clear{r.clear_exclusive();}
   let stored=r.atomic(operation(AtomicOperationKind::StoreConditional{value:Expr::binary(BinaryOp::Add,linked.value.unwrap(),Expr::constant(16,1))}));write(&mut r,0,stored.success.unwrap());
   let repeated=r.atomic(operation(AtomicOperationKind::StoreConditional{value:Expr::constant(16,0xffff)}));write(&mut r,1,repeated.success.unwrap());
   let t=evaluate(&r,&state).unwrap();assert_eq!(state.monitor_reads.get(),0);assert_eq!(t.registers[0].value.bits,success as u64);assert_eq!(t.registers[1].value.bits,0);assert_eq!(t.atomics.last().unwrap().monitor,ExclusiveMonitorEffect::Cleared);let next=state.commit(&t);assert!(next.monitor.is_none());assert_eq!(next.bytes[0..2],if success{[0x12,0x35]}else{[0x12,0x34]});
  }
  let mut state=Backend::new();state.monitor=Some(ExclusiveReservation{address:0,width:16,scope:MemoryScope::System,token:7});let mut r=Recipe::new(4,64);r.atomic(operation(AtomicOperationKind::StoreConditional{value:Expr::constant(16,5)}));assert_eq!(evaluate(&r,&state).unwrap().atomics[0].success,Some(true));assert_eq!(state.monitor_reads.get(),1);
 }
 struct Missing;
 impl Machine for Missing{fn read_register(&self,_:Register)->Value{Value::known(64,0)}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("plain memory fallback")}}
 #[test] fn native_missing_backend_unknown_values_and_predication(){
  let mut r=Recipe::new(4,64);r.atomic(operation(AtomicOperationKind::Load));assert_eq!(evaluate(&r,&Missing),Err(EvalError::Unsupported));
  r.guard=Expr::constant(1,0);let t=evaluate(&r,&Missing).unwrap();assert!(t.atomics.is_empty());assert!(t.events.is_empty());
  let mut r=Recipe::new(4,64);let mut a=operation(AtomicOperationKind::Load);a.scope=MemoryScope::Named("unsupported");r.atomic(a);assert_eq!(evaluate(&r,&Backend::new()),Err(EvalError::Unsupported));
  let mut r=Recipe::new(4,64);r.atomic(operation(AtomicOperationKind::Store{value:Expr::undefined(16,"unknown source")}));assert_eq!(evaluate(&r,&Backend::new()),Err(EvalError::UnknownAtomicValue));
  let mut r=Recipe::new(4,64);let mut a=operation(AtomicOperationKind::Load);a.memory.address=Box::new(Expr::undefined(64,"unknown address"));r.atomic(a);assert_eq!(evaluate(&r,&Backend::new()),Err(EvalError::UnknownAddress));
 }
 struct Bad(AtomicObservation);
 impl Machine for Bad{fn read_register(&self,_:Register)->Value{Value::known(64,0)}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("plain memory fallback")}fn read_exclusive_monitor(&self)->Result<Option<ExclusiveReservation>,EvalError>{Ok(None)}fn evaluate_atomic(&self,_:&AtomicRequest,_:&[AtomicTransition])->Result<AtomicObservation,EvalError>{Ok(self.0.clone())}}
 struct NoMonitor;
 impl Machine for NoMonitor{fn read_register(&self,_:Register)->Value{Value::known(64,0)}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("plain memory fallback")}fn evaluate_atomic(&self,_:&AtomicRequest,_:&[AtomicTransition])->Result<AtomicObservation,EvalError>{Ok(AtomicObservation{old:None,store_succeeded:Some(false),reservation_token:None,witness:0})}}
 #[test] fn native_failed_planning_and_missing_monitor_do_not_commit(){
  let state=Backend::new();let mut r=Recipe::new(4,64);r.atomic(operation(AtomicOperationKind::LoadLinked));let mut unsupported=operation(AtomicOperationKind::Store{value:Expr::constant(16,9)});unsupported.scope=MemoryScope::Named("unsupported");r.atomic(unsupported);assert_eq!(evaluate(&r,&state),Err(EvalError::Unsupported));assert_eq!(state.bytes[..2],[0x12,0x34]);assert!(state.monitor.is_none());
  let mut r=Recipe::new(4,64);r.atomic(operation(AtomicOperationKind::StoreConditional{value:Expr::constant(16,1)}));assert_eq!(evaluate(&r,&NoMonitor),Err(EvalError::Unsupported));
 }
 #[test] fn native_malformed_backend_outcomes_never_fabricate_results(){
  for old in [None,Some(Value::known(8,1)),Some(Value::unknown(16))]{let mut r=Recipe::new(4,64);r.atomic(operation(AtomicOperationKind::Load));assert_eq!(evaluate(&r,&Bad(AtomicObservation{old,store_succeeded:None,reservation_token:None,witness:0})),Err(EvalError::InvalidAtomicOutcome));}
  let mut r=Recipe::new(4,64);r.atomic(operation(AtomicOperationKind::LoadLinked));assert_eq!(evaluate(&r,&Bad(AtomicObservation{old:Some(Value::known(16,1)),store_succeeded:None,reservation_token:None,witness:0})),Err(EvalError::InvalidAtomicOutcome));
  let mut r=Recipe::new(4,64);r.atomic(operation(AtomicOperationKind::StoreConditional{value:Expr::constant(16,1)}));assert_eq!(evaluate(&r,&Bad(AtomicObservation{old:None,store_succeeded:Some(true),reservation_token:None,witness:0})),Err(EvalError::InvalidAtomicOutcome));
 }
 #[test] fn native_atomic_graph_and_ordering_validation(){
  for kind in [AtomicOperationKind::Load,AtomicOperationKind::LoadLinked]{let mut r=Recipe::new(4,64);let mut a=operation(kind);a.ordering=MemoryOrdering::Release;r.atomic(a);assert_eq!(r.validate(),Err(EvalError::InvalidExpression));}
  let mut r=Recipe::new(4,64);let mut a=operation(AtomicOperationKind::Store{value:Expr::constant(16,1)});a.ordering=MemoryOrdering::Acquire;r.atomic(a);assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
  let mut r=Recipe::new(4,64);let mut a=operation(AtomicOperationKind::StoreConditional{value:Expr::constant(16,1)});a.ordering=MemoryOrdering::AcquireRelease;r.atomic(a);assert!(r.validate().is_ok());
  for (width,scope) in [(24,MemoryScope::System),(16,MemoryScope::Named(" "))]{let mut r=Recipe::new(4,64);let mut a=operation(AtomicOperationKind::Load);a.memory.width=width;a.scope=scope;r.atomic(a);assert_eq!(r.validate(),Err(EvalError::InvalidExpression));}
  let orders=[MemoryOrdering::Monotonic,MemoryOrdering::Acquire,MemoryOrdering::Release,MemoryOrdering::AcquireRelease,MemoryOrdering::SequentiallyConsistent];
  for(success_index,success)in orders.iter().enumerate(){for(failure_index,failure)in orders.iter().enumerate(){let allowed=match success_index{0|2=>failure_index==0,1|3=>failure_index==0||failure_index==1,_=>failure_index==0||failure_index==1||failure_index==4};let mut r=Recipe::new(4,64);let mut a=operation(AtomicOperationKind::CompareExchange{expected:Expr::constant(16,0),replacement:Expr::constant(16,1),failure_ordering:*failure});a.ordering=*success;r.atomic(a);assert_eq!(r.validate().is_ok(),allowed);}}
  let mut r=Recipe::new(4,64);let value=Expr{ty:Type{width:16,signedness:Signedness::Unsigned},kind:ExprKind::AtomicResult{step:0,projection:AtomicProjection::Value}};r.atomic(operation(AtomicOperationKind::Store{value}));r.guard=Expr::constant(1,0);assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
  let mut r=Recipe::new(4,64);let value=r.bind(Expr::constant(16,1));r.atomic(operation(AtomicOperationKind::Store{value}));assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
  let mut r=Recipe::new(4,64);r.atomic(operation(AtomicOperationKind::Load));write(&mut r,0,Expr{ty:Type{width:1,signedness:Signedness::Unsigned},kind:ExprKind::AtomicResult{step:0,projection:AtomicProjection::Success}});assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
 }
 #[test] fn native_barriers_and_monitor_clear_are_ordered_events(){
  let mut r=Recipe::new(4,64);r.effects.push(Effect::Store{memory:Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,4)),width:8,endian:Endian::Little},value:Expr::constant(8,7)});
  r.effects.push(Effect::Barrier{kind:BarrierKind::DataSynchronization,scope:BarrierScope::InnerShareable,access:BarrierAccess::Writes,condition:None});r.effects.push(Effect::ExclusiveMonitorClear);
  r.effects.push(Effect::Store{memory:Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,5)),width:8,endian:Endian::Little},value:Expr::constant(8,9)});
  let mut state=Backend::new();state.monitor=Some(ExclusiveReservation{address:0,width:16,scope:MemoryScope::System,token:7});let t=evaluate(&r,&state).unwrap();assert_eq!(t.events,[OrderedEvent::Store(0),OrderedEvent::Barrier(Barrier{kind:BarrierKind::DataSynchronization,scope:BarrierScope::InnerShareable,access:BarrierAccess::Writes}),OrderedEvent::ExclusiveMonitorClear,OrderedEvent::Store(1)]);let next=state.commit(&t);assert_eq!(next.bytes[4..6],[7,9]);assert!(next.monitor.is_none());
  r.guard=Expr::constant(1,0);assert!(evaluate(&r,&state).unwrap().events.is_empty());
 }
 #[test] fn native_context_rejection_is_lazy_and_distinct_from_undefined(){
  for (condition,expected) in [(Expr::constant(1,1),Ok(Value::known(1,1))),(Expr::constant(1,0),Err(EvalError::UnsupportedContext)),(Expr::undefined(1,"unavailable"),Err(EvalError::UnknownCondition))]{assert_eq!(evaluate_expression(&Expr::require_context(condition,"execution mode"),&Missing,&[]),expected);}
  let rejected=Expr::require_context(Expr::constant(1,0),"invalid IT state");let selected=Expr::select(Expr::constant(1,0),rejected.clone(),Expr::constant(1,1));assert_eq!(evaluate_expression(&selected,&Missing,&[]),Ok(Value::known(1,1)));
  let mut r=Recipe::new(4,64);r.guard=rejected;r.atomic(operation(AtomicOperationKind::Load));assert_eq!(evaluate(&r,&Missing),Err(EvalError::UnsupportedContext));
  assert_eq!(validate_expression(&Expr::require_context(Expr::constant(8,1),"bad predicate"),&[]),Err(EvalError::InvalidExpression));assert!(!evaluate_expression(&Expr::undefined(1,"architectural undefined"),&Missing,&[]).unwrap().is_known());
 }
 #[test] fn native_float_environment_widths_are_exact(){
  for environment in [FloatEnvironment::A64,FloatEnvironment::A32Vfp,FloatEnvironment::A32Neon,FloatEnvironment::X86Mxcsr]{for width in [16,32,64]{let f=Expr::float(FloatExpression{operation:FloatOperation::Add,environment,width,inputs:vec![Expr::constant(width,0),Expr::constant(width,0)],control:Box::new(Expr::constant(32,0)),status:Box::new(Expr::constant(32,0)),projection:FloatProjection::Value});assert!(validate_expression(&f,&[]).is_ok());}}
  for operation in [FloatOperation::Divide,FloatOperation::SquareRoot,FloatOperation::Scale] {let f=Expr::float(FloatExpression{operation,environment:FloatEnvironment::A32Neon,width:16,inputs:vec![Expr::constant(16,0);if operation==FloatOperation::SquareRoot{1}else{2}],control:Box::new(Expr::constant(32,0)),status:Box::new(Expr::constant(32,0)),projection:FloatProjection::Value});assert_eq!(validate_expression(&f,&[]),Err(EvalError::InvalidExpression));}

 }
}
`
