package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustX86DecompositionFloatOperations(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"runtime.rs": RustRuntime, "special.rs": x86DecompositionTests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "special.rs", "-Dwarnings", "-o", "special-tests")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile x86 decomposition: %v\n%s", err, output)
	}
	cmd = exec.Command(filepath.Join(dir, "special-tests"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute x86 decomposition: %v\n%s", err, output)
	}
}

const x86DecompositionTests = `
#[allow(dead_code)] mod runtime;
use runtime::*;
struct NoEngine;
impl Machine for NoEngine {
 fn read_register(&self,_:Register)->Value {panic!("unexpected register")}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unexpected memory")}
}
fn expression(operation:FloatOperation,width:u8,projection:FloatProjection)->Expr {
 Expr::float(FloatExpression {operation,environment:FloatEnvironment::X86Mxcsr,width,
 inputs:vec![Expr::constant(width,1)],control:Box::new(Expr::constant(32,0x1e80)),
 status:Box::new(Expr::constant(32,0x1f80)),projection})
}
#[test] fn all_formats_projections_intervals_and_sign_controls_are_typed() {
 for width in [16,32,64] { for projection in [FloatProjection::Value,FloatProjection::Status,FloatProjection::Trapped] {
  let exponent=expression(FloatOperation::GetExponent,width,projection);
  assert_eq!(validate_expression(&exponent,&[]),Ok(()));
  assert_eq!(evaluate_expression(&exponent,&NoEngine,&[]),Err(EvalError::Unsupported));
  for interval in 0..4 { for sign_control in 0..4 {
   let e=expression(FloatOperation::GetMantissa{interval,sign_control},width,projection);
   assert_eq!(validate_expression(&e,&[]),Ok(()));
   for environment in [FloatEnvironment::A64,FloatEnvironment::A32Vfp,FloatEnvironment::A32Neon] {
    let mut bad=e.clone();if let ExprKind::Float(f)=&mut bad.kind{f.environment=environment;}
    assert_eq!(validate_expression(&bad,&[]),Err(EvalError::InvalidExpression));
   }
  }}
 }}
 for operation in [FloatOperation::GetExponent,FloatOperation::GetMantissa{interval:0,sign_control:0},FloatOperation::GetMantissa{interval:4,sign_control:0},FloatOperation::GetMantissa{interval:0,sign_control:4}] {
  let mut e=expression(operation,16,FloatProjection::Value);
  if matches!(operation,FloatOperation::GetMantissa{interval:4,..}|FloatOperation::GetMantissa{sign_control:4,..}) {assert_eq!(validate_expression(&e,&[]),Err(EvalError::InvalidExpression));continue;}
  if let ExprKind::Float(f)=&mut e.kind{f.inputs[0]=Expr::constant(32,1);}
  assert_eq!(validate_expression(&e,&[]),Err(EvalError::InvalidExpression));
 }
}
struct Fixture;
impl Machine for Fixture {
 fn read_register(&self,_:Register)->Value {panic!("unexpected register")}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unexpected memory")}
 fn evaluate_float(&self,f:&FloatExpression,inputs:&[Value],control:Value,status:Value)->Result<Value,EvalError>{
  assert_eq!(f.operation,FloatOperation::GetExponent);assert_eq!(f.environment,FloatEnvironment::X86Mxcsr);assert_eq!(f.width,16);
  assert_eq!(inputs,[Value::known(16,1)]);assert_eq!(control,Value::known(32,0x1e80));assert_eq!(status,Value::known(32,0x1f80));
  Ok(match f.projection{FloatProjection::Value=>Value::known(16,0xce00),FloatProjection::Status=>Value::known(32,0x1f82),FloatProjection::Trapped=>Value::known(1,1)})
 }
}
#[test] fn getexp_denormal_trap_commits_status_before_blocking_the_destination() {
 let mut r=Recipe::new(4,64);
 r.write(register("x86.mxcsr",0,32,32),WritePolicy::ZeroUpper,expression(FloatOperation::GetExponent,16,FloatProjection::Status));
 r.effects.push(Effect::Trap{kind:TrapKind::FloatingPoint,condition:expression(FloatOperation::GetExponent,16,FloatProjection::Trapped)});
 r.write(register("x86.vector64",0,16,64),WritePolicy::Preserve,expression(FloatOperation::GetExponent,16,FloatProjection::Value));
 let t=evaluate(&r,&Fixture).unwrap();assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert_eq!(t.registers.len(),1);
 assert_eq!(t.registers[0].register.bank,"x86.mxcsr");assert_eq!(t.registers[0].value,Value::known(32,0x1f82));
 let skipped=Expr::select(Expr::constant(1,0),expression(FloatOperation::GetExponent,16,FloatProjection::Value),Expr::constant(16,0x1234));
 assert_eq!(evaluate_expression(&skipped,&NoEngine,&[]),Ok(Value::known(16,0x1234)));
}
`

func TestRustX86ScalingFloatOperations(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"runtime.rs": RustRuntime, "scaling.rs": x86ScalingTests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "scaling.rs", "-Dwarnings", "-o", "scaling-tests")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile x86 scaling: %v\n%s", err, output)
	}
	cmd = exec.Command(filepath.Join(dir, "scaling-tests"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute x86 scaling: %v\n%s", err, output)
	}
}

const x86ScalingTests = `
#[allow(dead_code)] mod runtime;
use runtime::*;
struct NoEngine;
impl Machine for NoEngine {
 fn read_register(&self,_:Register)->Value {panic!("unexpected register")}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unexpected memory")}
}
fn expression(operation:FloatOperation,width:u8)->Expr {
 Expr::float(FloatExpression{operation,environment:FloatEnvironment::X86Mxcsr,width,
 inputs:vec![Expr::constant(width,1);if operation==FloatOperation::Scale{2}else{1}],
 control:Box::new(Expr::constant(32,0x1f80)),status:Box::new(Expr::constant(32,0x1f80)),projection:FloatProjection::Value})
}
#[test] fn every_immediate_and_format_is_typed_without_silent_backend_fallback(){
 for width in [16,32,64]{
  let scale=expression(FloatOperation::Scale,width);
  assert_eq!(validate_expression(&scale,&[]),Ok(()));
  assert_eq!(evaluate_expression(&scale,&NoEngine,&[]),Err(EvalError::Unsupported));
  for imm in 0_u16..256 {
   let rounding=if imm&4!=0{FloatRounding::Environment}else{[FloatRounding::NearestEven,FloatRounding::NegativeInfinity,FloatRounding::PositiveInfinity,FloatRounding::Zero][imm as usize&3]};
   for operation in [FloatOperation::Reduce{scale:(imm>>4)as u8,rounding,exact:imm&8==0},FloatOperation::RoundScale{scale:(imm>>4)as u8,rounding,exact:imm&8==0}]{
    let e=expression(operation,width);assert_eq!(validate_expression(&e,&[]),Ok(()));
    assert_eq!(evaluate_expression(&e,&NoEngine,&[]),Err(EvalError::Unsupported));
    let inactive=Expr::select(Expr::constant(1,0),e.clone(),Expr::constant(width,7));
    assert_eq!(evaluate_expression(&inactive,&NoEngine,&[]),Ok(Value::known(width,7)));
    for environment in [FloatEnvironment::A64,FloatEnvironment::A32Vfp,FloatEnvironment::A32Neon]{
     let mut bad=e.clone();if let ExprKind::Float(f)=&mut bad.kind{f.environment=environment;}
     assert_eq!(validate_expression(&bad,&[]),Err(EvalError::InvalidExpression));
    }
   }
  }
 }
 for operation in [FloatOperation::Reduce{scale:16,rounding:FloatRounding::Zero,exact:false},FloatOperation::RoundScale{scale:0,rounding:FloatRounding::NearestAway,exact:false}]{assert_eq!(validate_expression(&expression(operation,16),&[]),Err(EvalError::InvalidExpression));}
 let mut bad=expression(FloatOperation::Scale,16);if let ExprKind::Float(f)=&mut bad.kind{f.inputs.pop();}assert_eq!(validate_expression(&bad,&[]),Err(EvalError::InvalidExpression));
}
struct Fixture;
impl Machine for Fixture {
 fn read_register(&self,_:Register)->Value{panic!("unexpected register")}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unexpected memory")}
 fn evaluate_float(&self,f:&FloatExpression,inputs:&[Value],control:Value,status:Value)->Result<Value,EvalError>{
  assert_eq!(f.operation,FloatOperation::Scale);assert_eq!(inputs,[Value::known(16,1);2]);
  assert_eq!(control,Value::known(32,0x1f80));assert_eq!(status,Value::known(32,0x1f80));
  Ok(match f.projection{FloatProjection::Value=>Value::known(16,0x7c00),FloatProjection::Status=>Value::known(32,0x1fa8),FloatProjection::Trapped=>Value::known(1,1)})
 }
}
#[test] fn scaling_exception_blocks_result_after_ordered_status_commit(){
 let mut r=Recipe::new(4,64);let value=expression(FloatOperation::Scale,16);
 let mut status=value.clone();if let ExprKind::Float(f)=&mut status.kind{f.projection=FloatProjection::Status;}status.ty.width=32;
 let mut trapped=value.clone();if let ExprKind::Float(f)=&mut trapped.kind{f.projection=FloatProjection::Trapped;}trapped.ty.width=1;
 r.write(register("x86.mxcsr",0,32,32),WritePolicy::ZeroUpper,status);
 r.effects.push(Effect::Trap{kind:TrapKind::FloatingPoint,condition:trapped});
 r.write(register("x86.vector64",0,16,64),WritePolicy::Preserve,value);
 let t=evaluate(&r,&Fixture).unwrap();assert_eq!(t.trap,Some(TrapKind::FloatingPoint));assert_eq!(t.registers.len(),1);assert_eq!(t.registers[0].value,Value::known(32,0x1fa8));
}
`

func TestRustX86HalfEstimateOperations(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	for name, source := range map[string]string{"runtime.rs": RustRuntime, "estimates.rs": x86HalfEstimateTests} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "estimates.rs", "-Dwarnings", "-o", "estimate-tests")
	cmd.Dir = dir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile x86 half estimate: %v\n%s", err, output)
	}
	cmd = exec.Command(filepath.Join(dir, "estimate-tests"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute x86 half estimate: %v\n%s", err, output)
	}
}

const x86HalfEstimateTests = `
#[allow(dead_code)]mod runtime;use runtime::*;
struct NoEngine;
impl Machine for NoEngine{
 fn read_register(&self,_:Register)->Value{panic!("unexpected register")}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unexpected memory")}
}
fn expression(operation:FloatOperation,projection:FloatProjection)->Expr{
 Expr::float(FloatExpression{operation,environment:FloatEnvironment::X86Mxcsr,width:16,inputs:vec![Expr::constant(16,0x4000)],control:Box::new(Expr::constant(32,0)),status:Box::new(Expr::constant(32,0)),projection})
}
#[test]fn half_estimates_have_a_distinct_closed_domain_and_no_implicit_fallback(){
 for operation in [FloatOperation::X86ReciprocalEstimate,FloatOperation::X86ReciprocalSquareRootEstimate]{
  for projection in [FloatProjection::Value,FloatProjection::Status,FloatProjection::Trapped]{
   let e=expression(operation,projection);assert_eq!(validate_expression(&e,&[]),Ok(()));
   assert_eq!(evaluate_expression(&e,&NoEngine,&[]),Err(EvalError::Unsupported));
   for environment in [FloatEnvironment::A64,FloatEnvironment::A32Vfp,FloatEnvironment::A32Neon]{let mut bad=e.clone();if let ExprKind::Float(f)=&mut bad.kind{f.environment=environment;}assert_eq!(validate_expression(&bad,&[]),Err(EvalError::InvalidExpression));}
   let inactive=Expr::select(Expr::constant(1,0),e.clone(),Expr::constant(e.ty.width,0));assert_eq!(evaluate_expression(&inactive,&NoEngine,&[]),Ok(Value::known(e.ty.width,0)));
  }
  for width in [32,64]{let mut bad=expression(operation,FloatProjection::Value);bad.ty.width=width;if let ExprKind::Float(f)=&mut bad.kind{f.width=width;f.inputs=vec![Expr::constant(width,1)];}assert_eq!(validate_expression(&bad,&[]),Err(EvalError::InvalidExpression));}
 }
}
struct EstimateEngine;
impl Machine for EstimateEngine{
 fn read_register(&self,_:Register)->Value{panic!("unexpected register")}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unexpected memory")}
 fn evaluate_float(&self,f:&FloatExpression,inputs:&[Value],control:Value,status:Value)->Result<Value,EvalError>{
  assert_eq!(f.operation,FloatOperation::X86ReciprocalEstimate);assert_eq!(inputs,[Value::known(16,0x4000)]);assert_eq!(control,Value::known(32,0));assert_eq!(status,Value::known(32,0));
  Ok(match f.projection{FloatProjection::Value=>Value::known(16,0x3800),FloatProjection::Status=>status,FloatProjection::Trapped=>Value::known(1,0)})
 }
}
#[test]fn estimate_result_is_typed_and_status_remains_unchanged(){
 for (projection,value)in [(FloatProjection::Value,Value::known(16,0x3800)),(FloatProjection::Status,Value::known(32,0)),(FloatProjection::Trapped,Value::known(1,0))]{assert_eq!(evaluate_expression(&expression(FloatOperation::X86ReciprocalEstimate,projection),&EstimateEngine,&[]),Ok(value));}
}
`
