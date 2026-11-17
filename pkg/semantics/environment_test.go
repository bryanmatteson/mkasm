package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustClosedEnvironmentEffects(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"runtime.rs": RustRuntime, "tests.rs": closedEnvironmentTests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "tests.rs", "-Dwarnings", "-o", "tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "tests"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}

const closedEnvironmentTests = `
#[allow(dead_code)]mod runtime;
use runtime::*;
use std::cell::RefCell;
struct State{trap:bool,trace:RefCell<Vec<&'static str>>}
impl Machine for State{
 fn read_register(&self,_:Register)->Value{panic!("unexpected state")}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unexpected memory")}
 fn wait(&self,allow:bool)->Result<WaitOutcome,EvalError>{self.trace.borrow_mut().push(if allow{"wait-two"}else{"wait-one"});Ok(if self.trap{WaitOutcome::ProtectionTrap}else{WaitOutcome::FallThrough})}
 fn send_event(&self,local:bool)->Result<(),EvalError>{self.trace.borrow_mut().push(if local{"local"}else{"global"});Ok(())}
}
fn state(trap:bool)->State{State{trap,trace:RefCell::new(Vec::new())}}
#[test]fn ordered_environment_boundaries_survive_success(){let s=state(false);let mut r=Recipe::new(0x1004,64);
 r.effects.push(Effect::SendEvent{local:true});r.effects.push(Effect::Wait{allow_protection_trap:false});r.effects.push(Effect::SendEvent{local:false});r.effects.push(Effect::Wait{allow_protection_trap:true});
 let t=evaluate(&r,&s).unwrap();assert_eq!(&*s.trace.borrow(),&["local","wait-one","global","wait-two"]);assert_eq!(t.trap,None);assert_eq!(t.next_pc,Value::known(64,0x1004));
 assert_eq!(t.events,vec![OrderedEvent::SendEvent{local:true},OrderedEvent::Wait{allow_protection_trap:false,outcome:WaitOutcome::FallThrough},OrderedEvent::SendEvent{local:false},OrderedEvent::Wait{allow_protection_trap:true,outcome:WaitOutcome::FallThrough}]);assert!(t.atomics.is_empty());assert!(t.registers.is_empty());assert!(t.memory.is_empty());
}
#[test]fn selected_protection_outcome_terminates_later_effects(){let s=state(true);let mut r=Recipe::new(4,64);r.effects.push(Effect::Wait{allow_protection_trap:true});r.effects.push(Effect::SendEvent{local:false});
 let t=evaluate(&r,&s).unwrap();assert_eq!(t.trap,Some(TrapKind::Protection));assert_eq!(&*s.trace.borrow(),&["wait-two"]);assert_eq!(t.events,vec![OrderedEvent::Wait{allow_protection_trap:true,outcome:WaitOutcome::ProtectionTrap}]);
}
#[test]fn callback_cannot_escape_the_declared_outcome_domain(){let s=state(true);let mut r=Recipe::new(4,64);r.effects.push(Effect::Wait{allow_protection_trap:false});assert_eq!(evaluate(&r,&s),Err(EvalError::InvalidEnvironmentOutcome));}
#[test]fn false_guard_suppresses_all_environment_callbacks(){let s=state(true);let mut r=Recipe::new(4,64);r.guard=Expr::constant(1,0);r.effects.push(Effect::Wait{allow_protection_trap:true});r.effects.push(Effect::SendEvent{local:false});let t=evaluate(&r,&s).unwrap();assert!(s.trace.borrow().is_empty());assert!(t.events.is_empty());assert_eq!(t.trap,None);}
struct NoEnvironment;
impl Machine for NoEnvironment{fn read_register(&self,_:Register)->Value{panic!()}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!()}}
#[test]fn missing_environment_is_an_explicit_capability_error(){for effect in [Effect::Wait{allow_protection_trap:false},Effect::SendEvent{local:true}]{let mut r=Recipe::new(4,64);r.effects.push(effect);assert_eq!(evaluate(&r,&NoEnvironment),Err(EvalError::Unsupported));}}
#[test]fn whole_graph_is_validated_before_external_callbacks(){let s=state(false);let mut r=Recipe::new(4,64);r.effects.push(Effect::SendEvent{local:true});r.effects.push(Effect::WriteRegister{destination:register("bad",0,8,8),policy:WritePolicy::ZeroUpper,value:Expr::constant(16,1)});assert_eq!(evaluate(&r,&s),Err(EvalError::InvalidExpression));assert!(s.trace.borrow().is_empty());}
`
