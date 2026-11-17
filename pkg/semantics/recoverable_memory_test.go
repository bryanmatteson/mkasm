package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustRecoverableMemory(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "runtime.rs"), []byte(RustRuntime+rustRecoverableMemoryTests), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "runtime.rs", "-Dwarnings", "-o", filepath.Join(dir, "recoverable-tests"))
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile recoverable memory recipes: %v\n%s", err, out)
	}
	command = exec.Command(filepath.Join(dir, "recoverable-tests"), "recoverable_memory::")
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute recoverable memory recipes: %v\n%s", err, out)
	}
}

const rustRecoverableMemoryTests = `
#[cfg(test)] mod recoverable_memory {
use super::*;
use std::cell::RefCell;
struct State { fault: Option<EvalError>, calls: RefCell<Vec<(u64,u8,Endian)>> }
impl State { fn new(fault:Option<EvalError>)->Self { Self {fault,calls:RefCell::new(Vec::new())} } }
impl Machine for State {
 fn read_register(&self,_:Register)->Value { Value::unknown(64) }
 fn read_memory(&self,address:u64,width:u8,endian:Endian)->Result<Value,EvalError> {
  self.calls.borrow_mut().push((address,width,endian));
  if address==8 { if let Some(error)=&self.fault { return Err(error.clone()); } }
  Ok(Value::known(width,address+17))
 }
 fn try_read_memory(&self,address:u64,width:u8,endian:Endian)->Result<Value,EvalError> {self.read_memory(address,width,endian)}
}
fn memory(address:u64,width:u8,endian:Endian)->Memory {Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,address)),width,endian}}
fn output(recipe:&mut Recipe,index:u16,value:Expr) {recipe.write(register("out",index,value.ty.width,value.ty.width),WritePolicy::Preserve,value);}
const KINDS:[MemoryFaultKind;7]=[MemoryFaultKind::Translation,MemoryFaultKind::Permission,MemoryFaultKind::Alignment,MemoryFaultKind::Access,MemoryFaultKind::TagCheck,MemoryFaultKind::ExternalAbort,MemoryFaultKind::Atomicity];
#[test] fn declared_faults_return_zero_and_failure_only_for_exact_class() {
 for kind in KINDS { for width in [8,16,32,64] {for endian in [Endian::Little,Endian::Big] {
  let mut recipe=Recipe::new(4,64);
  let(value,success)=recipe.try_load_ordered(Expr::constant(1,1),memory(8,width,endian),vec![kind]).unwrap();
  output(&mut recipe,0,value);output(&mut recipe,1,success);
  let state=State::new(Some(EvalError::MemoryFault(kind)));
  let transition=evaluate(&recipe,&state).unwrap();
  assert_eq!(transition.registers.iter().map(|w|w.value).collect::<Vec<_>>(),[Value::known(width,0),Value::known(1,0)]);
  assert_eq!(*state.calls.borrow(),[(8,width,endian)]);
  for other in KINDS.into_iter().filter(|other|*other!=kind) {
   assert_eq!(evaluate(&recipe,&State::new(Some(EvalError::MemoryFault(other)))),Err(EvalError::MemoryFault(other)));
  }
 }}}
}
#[test] fn backend_and_capability_errors_are_never_suppressed() {
 let mut recipe=Recipe::new(4,64);
 recipe.try_load_ordered(Expr::constant(1,1),memory(8,64,Endian::Little),KINDS.to_vec()).unwrap();
 for error in [EvalError::Memory,EvalError::Unsupported,EvalError::InvalidExpression,EvalError::UnknownAddress,EvalError::UnsupportedContext] {
  assert_eq!(evaluate(&recipe,&State::new(Some(error.clone()))),Err(error));
 }
}
#[test] fn missing_attempt_capability_never_falls_back_to_ordinary_access() {
 struct OrdinaryOnly;
 impl Machine for OrdinaryOnly {
  fn read_register(&self,_:Register)->Value{Value::unknown(64)}
  fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("ordinary fallback");}
 }
 let mut recipe=Recipe::new(4,64);recipe.try_load_ordered(Expr::constant(1,1),memory(8,64,Endian::Little),KINDS.to_vec()).unwrap();
 assert_eq!(evaluate(&recipe,&OrdinaryOnly),Err(EvalError::Unsupported));
}
#[test] fn first_read_remains_faulting_and_later_reads_stop_in_order() {
 let mut recipe=Recipe::new(4,64);
 recipe.load_ordered(memory(8,16,Endian::Big)).unwrap();
 recipe.try_load_ordered(Expr::constant(1,1),memory(16,16,Endian::Big),KINDS.to_vec()).unwrap();
 let state=State::new(Some(EvalError::MemoryFault(MemoryFaultKind::Translation)));
 assert_eq!(evaluate(&recipe,&state),Err(EvalError::MemoryFault(MemoryFaultKind::Translation)));
 assert_eq!(*state.calls.borrow(),[(8,16,Endian::Big)]);
}
#[test] fn later_addresses_and_predicates_observe_prior_recovery_once() {
 for fault in [None,Some(EvalError::MemoryFault(MemoryFaultKind::Permission))] {
  let mut recipe=Recipe::new(4,64);
  let first=recipe.load_ordered(memory(0,32,Endian::Little)).unwrap();
  let(value,success)=recipe.try_load_ordered(Expr::constant(1,1),memory(8,32,Endian::Big),vec![MemoryFaultKind::Permission]).unwrap();
  let last=recipe.load_ordered_conditional(success.clone(),Memory{kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::cast(first.clone(),64,false)),width:8,endian:Endian::Little}).unwrap();
  output(&mut recipe,0,first);output(&mut recipe,1,value);output(&mut recipe,2,success.clone());
  output(&mut recipe,3,Expr::select(success,last,Expr::constant(8,99)));
  let state=State::new(fault.clone());let transition=evaluate(&recipe,&state).unwrap();
  assert_eq!(transition.registers[3].value.bits,if fault.is_some(){99}else{34});
  let mut expected=vec![(0,32,Endian::Little),(8,32,Endian::Big)];if fault.is_none(){expected.push((17,8,Endian::Little));}
  assert_eq!(*state.calls.borrow(),expected);
 }
}
#[test] fn skipped_read_never_resolves_address_and_success_is_unavailable() {
 let mut recipe=Recipe::new(4,64);
 let mut access=memory(8,64,Endian::Little);access.address=Box::new(Expr::register(register("unknown",0,64,64)));
 let(value,success)=recipe.try_load_ordered(Expr::constant(1,0),access,KINDS.to_vec()).unwrap();
 output(&mut recipe,0,Expr::select(Expr::constant(1,0),value,Expr::constant(64,5)));
 let state=State::new(None);assert_eq!(evaluate(&recipe,&state).unwrap().registers[0].value.bits,5);assert!(state.calls.borrow().is_empty());
 output(&mut recipe,1,success);assert_eq!(evaluate(&recipe,&state),Err(EvalError::UnavailableMemoryResult));
}
#[test] fn malformed_and_forward_dependencies_are_rejected_before_memory() {
 for kinds in [vec![],vec![MemoryFaultKind::Permission,MemoryFaultKind::Permission],vec![MemoryFaultKind::Permission,MemoryFaultKind::Translation]] {
  assert_eq!(Recipe::new(4,64).try_load_ordered(Expr::constant(1,1),memory(8,64,Endian::Little),kinds),Err(EvalError::InvalidExpression));
 }
 for width in [0,7,24,48] { assert_eq!(Recipe::new(4,64).try_load_ordered(Expr::constant(1,1),memory(8,width,Endian::Little),KINDS.to_vec()),Err(EvalError::InvalidExpression)); }
 let mut recipe=Recipe::new(4,64);recipe.try_load_ordered(Expr::constant(1,1),memory(8,64,Endian::Little),KINDS.to_vec()).unwrap();
 recipe.wide_load_conditions[0]=Some(Expr{ty:Type{width:1,signedness:Signedness::Unsigned},kind:ExprKind::WideLoadSuccess{step:0}});
 let state=State::new(None);assert_eq!(evaluate(&recipe,&state),Err(EvalError::InvalidExpression));assert!(state.calls.borrow().is_empty());
 recipe.wide_load_conditions[0]=None;recipe.wide_load_recovery.clear();assert_eq!(recipe.validate(),Err(EvalError::InvalidExpression));
}
}
`
