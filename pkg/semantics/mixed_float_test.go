package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustMixedWidthFloatOperations(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"runtime.rs": RustRuntime, "mixed.rs": mixedWidthFloatTests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "mixed.rs", "-Dwarnings", "-o", "mixed-tests")
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile mixed-width float operations: %v\n%s", err, output)
	}
	command = exec.Command(filepath.Join(dir, "mixed-tests"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("execute mixed-width float operations: %v\n%s", err, output)
	}
}

const mixedWidthFloatTests = `
#[allow(dead_code)] mod runtime;
use runtime::*;
use std::cell::Cell;
const WIDEN: FloatOperation = FloatOperation::WideningFusedMultiplyAdd { source_width: 16 };
fn expression(operation:FloatOperation, inputs:&[(u8,u64)], projection:FloatProjection, control:u64,status:u64)->Expr {
    Expr::float(FloatExpression { operation, environment:FloatEnvironment::A64,width:32,
        inputs:inputs.iter().map(|(width,bits)|Expr::constant(*width,*bits)).collect(),
        control:Box::new(Expr::constant(32,control)),status:Box::new(Expr::constant(32,status)),projection })
}
struct NoEngine;
impl Machine for NoEngine {
    fn read_register(&self,_:Register)->Value {panic!("unexpected register")}
    fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError> {panic!("unexpected memory")}
}
// Literal architectural fixtures test the callback/transition contract. Native
// numeric results are checked independently by the consumer lowerer tests.
struct Fixture {
    operation:FloatOperation, inputs:Vec<Value>,control:u64,status:u64,
    value:u64,new_status:u64,trapped:bool,calls:Cell<usize>,
}
impl Machine for Fixture {
    fn read_register(&self,_:Register)->Value {panic!("unexpected register")}
    fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError> {panic!("unexpected memory")}
    fn evaluate_float(&self,f:&FloatExpression,inputs:&[Value],control:Value,status:Value)->Result<Value,EvalError> {
        self.calls.set(self.calls.get()+1);
        assert_eq!(f.operation,self.operation);
        assert_eq!(f.environment,FloatEnvironment::A64);
        assert_eq!(f.width,32);
        assert_eq!(inputs,self.inputs);
        assert_eq!(control,Value::known(32,self.control));
        assert_eq!(status,Value::known(32,self.status));
        if inputs.iter().any(|v|!v.is_known()) { return Ok(Value::unknown(match f.projection { FloatProjection::Value|FloatProjection::Status=>32,FloatProjection::Trapped=>1 })); }
        Ok(match f.projection {
            FloatProjection::Value=>Value::known(32,self.value),
            FloatProjection::Status=>Value::known(32,self.new_status),
            FloatProjection::Trapped=>Value::known(1,u64::from(self.trapped)),
        })
    }
}
fn fixture(operation:FloatOperation,inputs:&[(u8,u64)],control:u64,status:u64,value:u64,new_status:u64,trapped:bool)->Fixture {
    Fixture{operation,inputs:inputs.iter().map(|(w,v)|Value::known(*w,*v)).collect(),control,status,value,new_status,trapped,calls:Cell::new(0)}
}
#[test] fn heterogeneous_dimensions_are_closed_and_a64_only() {
    for (operation,inputs) in [(WIDEN,vec![(32,0),(16,0),(16,0)]),(FloatOperation::BFloatDotAdd,vec![(32,0),(16,0),(16,0),(16,0),(16,0)])] {
        for projection in [FloatProjection::Value,FloatProjection::Status,FloatProjection::Trapped] {
            let e=expression(operation,&inputs,projection,0,0);
            assert_eq!(validate_expression(&e,&[]),Ok(()));
            assert_eq!(evaluate_expression(&e,&NoEngine,&[]),Err(EvalError::Unsupported));
            for environment in [FloatEnvironment::A32Vfp,FloatEnvironment::A32Neon,FloatEnvironment::X86Mxcsr] {
                let mut bad=e.clone();if let ExprKind::Float(f)=&mut bad.kind {f.environment=environment;}
                assert_eq!(validate_expression(&bad,&[]),Err(EvalError::InvalidExpression));
            }
            for index in 0..inputs.len() {
                let mut bad=e.clone();if let ExprKind::Float(f)=&mut bad.kind {f.inputs[index]=Expr::constant(if index==0{16}else{32},0);}
                assert_eq!(validate_expression(&bad,&[]),Err(EvalError::InvalidExpression));
            }
            let mut bad=e.clone();if let ExprKind::Float(f)=&mut bad.kind {f.inputs.pop();}
            assert_eq!(validate_expression(&bad,&[]),Err(EvalError::InvalidExpression));
            let mut bad=e.clone();if let ExprKind::Float(f)=&mut bad.kind {f.control=Box::new(Expr::constant(16,0));}
            assert_eq!(validate_expression(&bad,&[]),Err(EvalError::InvalidExpression));
        }
    }
    for source_width in [8,32,64] {
        let e=expression(FloatOperation::WideningFusedMultiplyAdd{source_width},&[(32,0),(source_width,0),(source_width,0)],FloatProjection::Value,0,0);
        assert_eq!(validate_expression(&e,&[]),Err(EvalError::InvalidExpression));
    }
    let mut e=expression(WIDEN,&[(32,0),(16,0),(16,0)],FloatProjection::Value,0,0);
    if let ExprKind::Float(f)=&mut e.kind {f.width=64;}e.ty.width=64;
    assert_eq!(validate_expression(&e,&[]),Err(EvalError::InvalidExpression));
}
#[test] fn callbacks_receive_original_addend_first_and_each_typed_projection() {
    for (operation,inputs,value) in [
        (WIDEN,vec![(32,0x3f800000),(16,0x4000),(16,0x4200)],0x40e00000), // 1+2*3=7
        (FloatOperation::BFloatDotAdd,vec![(32,0x3f800000),(16,0x4000),(16,0x4040),(16,0x4080),(16,0x40a0)],0x41c00000), // 1+2*4+3*5=24
    ] {
        let state=fixture(operation,&inputs,0,0x20,value,0x20,false);
        for (projection,width,bits) in [(FloatProjection::Value,32,value),(FloatProjection::Status,32,0x20),(FloatProjection::Trapped,1,0)] {
            assert_eq!(evaluate_expression(&expression(operation,&inputs,projection,0,0x20),&state,&[]),Ok(Value::known(width,bits)));
        }
        assert_eq!(state.calls.get(),3);
    }
}
#[test] fn unmasked_mixed_nan_updates_status_before_trap_without_destination_commit() {
    // Half signaling NaN wins over the binary32 quiet addend. IOC is enabled.
    let inputs=[(32,0x7fc00111),(16,0x7c01),(16,0x3c00)];
    let state=fixture(WIDEN,&inputs,1<<8,0x20,0x7fc02000,0x21,true);
    let mut recipe=Recipe::new(4,64);
    recipe.write(register("fpsr",0,32,32),WritePolicy::ZeroUpper,expression(WIDEN,&inputs,FloatProjection::Status,1<<8,0x20));
    recipe.effects.push(Effect::Trap{kind:TrapKind::FloatingPoint,condition:expression(WIDEN,&inputs,FloatProjection::Trapped,1<<8,0x20)});
    recipe.write(register("destination",0,32,32),WritePolicy::ZeroUpper,expression(WIDEN,&inputs,FloatProjection::Value,1<<8,0x20));
    let transition=evaluate(&recipe,&state).unwrap();
    assert_eq!(transition.trap,Some(TrapKind::FloatingPoint));
    assert_eq!(transition.registers.len(),1);
    assert_eq!(transition.registers[0].register.bank,"fpsr");
    assert_eq!(transition.registers[0].value,Value::known(32,0x21));
    assert_eq!(state.calls.get(),2,"uncommitted value projection must not execute");
}
#[test] fn unknown_chunks_and_inactive_branches_are_not_fabricated_values() {
    let mut state=fixture(WIDEN,&[(32,0),(16,0),(16,0)],0,0,0,0,false);
    state.inputs[1]=Value::unknown(16);
    let mut e=expression(WIDEN,&[(32,0),(16,0),(16,0)],FloatProjection::Value,0,0);
    if let ExprKind::Float(f)=&mut e.kind {f.inputs[1]=Expr::undefined(16,"missing half");}
    assert_eq!(evaluate_expression(&e,&state,&[]),Ok(Value::unknown(32)));
    let skipped=Expr::select(Expr::constant(1,0),e,Expr::constant(32,0x12345678));
    assert_eq!(evaluate_expression(&skipped,&NoEngine,&[]),Ok(Value::known(32,0x12345678)));
}
`
