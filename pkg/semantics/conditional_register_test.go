package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustConditionalRegisterWrites(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "runtime.rs")
	if err := os.WriteFile(source, []byte(RustRuntime+rustConditionalRegisterTests), 0644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "conditional-register-tests")
	command := exec.Command("rustc", "--edition=2021", "--test", source, "-Dwarnings", "-o", binary)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile conditional register writes: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary, "conditional_register::", "--nocapture").CombinedOutput(); err != nil {
		t.Fatalf("execute conditional register writes: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

const rustConditionalRegisterTests = `
#[cfg(test)]
mod conditional_register {
 use super::*;
 use std::cell::Cell;
 struct State { parent:Value, condition:Value, parents:Cell<usize>, conditions:Cell<usize>, memory:Cell<usize> }
 impl State {
  fn new()->Self { Self {parent:Value::known(64,0x1122_3344_5566_7788),condition:Value::known(1,1),parents:Cell::new(0),conditions:Cell::new(0),memory:Cell::new(0)} }
 }
 impl Machine for State {
  fn read_register(&self,r:Register)->Value {
   if r.bank=="condition" {self.conditions.set(self.conditions.get()+1);self.condition}
   else {assert_eq!(r.bank,"parent");self.parents.set(self.parents.get()+1);self.parent}
  }
  fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError> {self.memory.set(self.memory.get()+1);Err(EvalError::Memory)}
 }
 fn low()->RegisterSlice {register("parent",0,8,64)}
 fn faulting()->Expr {Expr::load(Memory {kind: Default::default(), privilege: Default::default(),address:Box::new(Expr::constant(64,0x1000)),width:8,endian:Endian::Little})}
 #[test] fn false_write_skips_unavailable_value_and_parent_preservation() {
  let mut s=State::new();s.parent=Value::unknown(64);
  let mut r=Recipe::new(4,64);r.write_conditional(Expr::constant(1,0),low(),WritePolicy::Preserve,faulting());
  assert_eq!(r.validate(),Ok(()));
  let t=evaluate(&r,&s).unwrap();assert!(t.registers.is_empty());assert_eq!(s.parents.get(),0);assert_eq!(s.memory.get(),0);
  // A structurally valid unavailable register value is equally unobserved.
  r.effects.clear();r.write_conditional(Expr::constant(1,0),low(),WritePolicy::Preserve,Expr::register(low()));
  assert!(evaluate(&r,&s).unwrap().registers.is_empty());assert_eq!(s.parents.get(),0);
 }
 #[test] fn selected_unknown_condition_rejects_before_value_or_parent() {
  let mut s=State::new();s.condition=Value::unknown(1);
  let mut r=Recipe::new(4,64);r.write_conditional(Expr::register(register("condition",0,1,1)),low(),WritePolicy::Preserve,faulting());
  assert_eq!(evaluate(&r,&s),Err(EvalError::UnknownCondition));assert_eq!(s.conditions.get(),1);assert_eq!(s.parents.get(),0);assert_eq!(s.memory.get(),0);
  r.guard=Expr::constant(1,0);assert!(evaluate(&r,&s).unwrap().registers.is_empty());assert_eq!(s.conditions.get(),1);
 }
 #[test] fn selected_write_preserves_unknown_parent_bits_without_fabrication() {
  let mut s=State::new();s.parent=Value::unknown(64);
  let mut r=Recipe::new(4,64);r.write_conditional(Expr::constant(1,1),low(),WritePolicy::Preserve,Expr::constant(8,0xab));
  let t=evaluate(&r,&s).unwrap();assert_eq!(t.registers.len(),1);assert_eq!(t.registers[0].value,Value{width:64,bits:0xab,defined:0xff});assert_eq!(s.parents.get(),1);
  r.effects.clear();r.write_conditional(Expr::constant(1,1),low(),WritePolicy::ZeroUpper,Expr::constant(8,0xab));
  assert_eq!(evaluate(&r,&s).unwrap().registers[0].value,Value::known(64,0xab));assert_eq!(s.parents.get(),1);
 }
 #[test] fn selected_value_error_is_transactional_and_precedes_preservation() {
  let s=State::new();let mut r=Recipe::new(4,64);
  r.write(register("parent",0,64,64),WritePolicy::Preserve,Expr::constant(64,0xdead));
  r.write_conditional(Expr::constant(1,1),low(),WritePolicy::Preserve,faulting());
  assert_eq!(evaluate(&r,&s),Err(EvalError::Memory));assert_eq!(s.parents.get(),0);assert_eq!(s.memory.get(),1);assert_eq!(s.parent.bits,0x1122_3344_5566_7788);
 }
 #[test] fn values_capture_incoming_state_and_preservation_merges_pending_writes() {
  let s=State::new();let mut r=Recipe::new(4,64);
  r.write(register("parent",0,64,64),WritePolicy::Preserve,Expr::constant(64,0xffff_ffff_ffff_ff00));
  r.write_conditional(Expr::constant(1,1),low(),WritePolicy::Preserve,Expr::register(low()));
  let t=evaluate(&r,&s).unwrap();assert_eq!(t.registers.len(),2);assert_eq!(t.registers[1].value,Value::known(64,0xffff_ffff_ffff_ff88));assert_eq!(s.parents.get(),1);assert_eq!(s.parent.bits,0x1122_3344_5566_7788);
 }
 #[test] fn inactive_graphs_still_require_valid_condition_destination_and_value() {
  let mut r=Recipe::new(4,64);
  r.write_conditional(Expr::constant(8,0),low(),WritePolicy::Preserve,Expr::constant(8,0));assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
  r.effects.clear();let mut bad=low();bad.offset=63;r.write_conditional(Expr::constant(1,0),bad,WritePolicy::Preserve,Expr::constant(8,0));assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
  r.effects.clear();r.write_conditional(Expr::constant(1,0),low(),WritePolicy::Preserve,Expr::constant(16,0));assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
  r.effects.clear();let bad=Expr{ty:Type{width:8,signedness:Signedness::Unsigned},kind:ExprKind::Temporary(0)};
  r.write_conditional(Expr::constant(1,0),low(),WritePolicy::Preserve,bad);assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
 }
}
`
