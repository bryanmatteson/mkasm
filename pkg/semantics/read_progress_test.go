package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustReadProgress(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "runtime.rs")
	if err := os.WriteFile(source, []byte(RustRuntime+rustReadProgressTests), 0644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "read-progress-tests")
	command := exec.Command("rustc", "--edition=2021", "--test", source, "-Dwarnings", "-o", binary)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile read progress: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary, "read_progress_behavior::", "--nocapture").CombinedOutput(); err != nil {
		t.Fatalf("execute read progress: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

const rustReadProgressTests = `
#[cfg(test)] mod read_progress_behavior {
    use super::*;
    use std::cell::RefCell;
    struct State { calls: RefCell<Vec<u64>> }
    impl Machine for State {
        fn read_register(&self, _: Register) -> Value { Value::known(64, 0xaabbccdd) }
        fn read_memory(&self, address:u64, width:u8, _:Endian)->Result<Value,EvalError>{
            self.calls.borrow_mut().push(address);
            if address==8 {Err(EvalError::MemoryFault(MemoryFaultKind::Translation))}
            else {Ok(Value::known(width,42))}
        }
    }
    fn recipe()->Recipe {
        let mut r=Recipe::new(0x1004,64);
        let input=r.bind_before_reads(Expr::register(register("test",0,64,64))).unwrap();
        let a=r.load_ordered_conditional(Expr::constant(1,1),Memory{kind:Default::default(),privilege:Default::default(),address:Box::new(Expr::constant(64,0)),width:32,endian:Endian::Little}).unwrap();
        r.load_ordered_conditional(Expr::constant(1,1),Memory{kind:Default::default(),privilege:Default::default(),address:Box::new(Expr::constant(64,8)),width:32,endian:Endian::Little}).unwrap();
        let step=|after_read,value|ReadUpdate{after_read,update:RegisterUpdate{destination:register("test",0,64,64),policy:WritePolicy::ZeroUpper,value},condition:None};
        r.read_progress=Some(ReadProgress{restart:Expr::constant(64,0x1000),updates:vec![step(0,input),step(1,Expr::cast(a,64,false))]});
        r.write(register("test",1,64,64),WritePolicy::ZeroUpper,Expr::constant(64,99));r
    }
    #[test]fn only_explicit_progress_survives_a_later_fault(){
        let state=State{calls:Default::default()};let mut r=recipe();r.validate().unwrap();
        let failure=evaluate_with_progress(&r,&state).unwrap_err();assert_eq!(failure.error,EvalError::MemoryFault(MemoryFaultKind::Translation));
        let t=failure.published.unwrap();assert_eq!(t.next_pc,Value::known(64,0x1000));assert_eq!(t.registers.len(),2);assert_eq!(t.registers.last().unwrap().value,Value::known(64,42));assert!(t.events.is_empty());assert_eq!(*state.calls.borrow(),vec![0,8]);
        r.read_progress=None;assert!(evaluate_with_progress(&r,&state).unwrap_err().published.is_none());
        r=recipe();r.guard=Expr::constant(1,0);state.calls.borrow_mut().clear();let t=evaluate_with_progress(&r,&state).unwrap();assert_eq!(t.next_pc.bits,0x1004);assert!(t.registers.is_empty());assert!(state.calls.borrow().is_empty());
        r.guard=Expr::constant(1,1);r.preflight_traps.push((TrapKind::InvalidInstruction,Expr::constant(1,1)));let t=evaluate_with_progress(&r,&state).unwrap();assert_eq!(t.trap,Some(TrapKind::InvalidInstruction));assert!(t.registers.is_empty());assert!(state.calls.borrow().is_empty());
    }
    #[test]fn progress_rejects_future_reads_unsnapshotted_inputs_and_reordered_stages(){
        let mut r=recipe();r.read_progress.as_mut().unwrap().updates[1].after_read=0;assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
        let mut r=recipe();r.read_progress.as_mut().unwrap().updates[0].update.value=Expr::register(register("test",0,64,64));assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
        let mut r=recipe();r.read_progress.as_mut().unwrap().updates.swap(0,1);assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
        let mut r=recipe();r.wide_loads[1].address=Box::new(Expr::register(register("test",0,64,64)));assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
        let mut r=recipe();r.read_progress.as_mut().unwrap().updates[1].after_read=3;assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
        let mut r=recipe();r.flow.fallthrough=Expr::register(register("test",0,64,64));assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
    }
}
`
