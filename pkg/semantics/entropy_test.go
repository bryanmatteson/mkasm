package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustEntropyEvaluator(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "entropy.rs"), []byte(RustRuntime+rustEntropyTests), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "entropy.rs", "-Dwarnings", "-o", "entropy-tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile entropy evaluator: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "entropy-tests"), "entropy_behavior::", "--nocapture")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("entropy evaluator: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

const rustEntropyTests = `
#[cfg(test)]mod entropy_behavior{
 use super::*;use std::cell::RefCell;
 struct Provider{calls:RefCell<Vec<(usize,u8)>>}
 impl Machine for Provider{
  fn read_register(&self,r:Register)->Value{assert_eq!(r.bank,"incoming");Value::known(64,0)}
  fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{Err(EvalError::Memory)}
  fn choose(&self,sequence:usize,width:u8)->Result<Value,EvalError>{self.calls.borrow_mut().push((sequence,width));Ok(Value::known(width,if sequence==0{0}else{0xabcdef}))}
 }
 #[test]fn skipped_draw_retains_identity_and_unavailable_result_is_lazy(){
  let p=Provider{calls:Default::default()};let mut r=Recipe::new(4,64);
  let success=r.choose(1,None);let unavailable=r.choose(64,Some(success.clone()));let value=r.choose(32,None);
  let selected=Expr::select(success,unavailable,Expr::cast(value,64,false));r.write(register("out",0,64,64),WritePolicy::Preserve,selected);
  let t=evaluate(&r,&p).unwrap();assert_eq!(*p.calls.borrow(),vec![(0,1),(2,32)]);assert_eq!(t.registers[0].value,Value::known(64,0xabcdef));
  r.effects.clear();r.bind(Expr{ty:Type{width:64,signedness:Signedness::Unsigned},kind:ExprKind::ChoiceResult{step:1}});
  assert_eq!(evaluate(&r,&p),Err(EvalError::UnavailableChoiceResult));
 }
 #[test]fn selected_unknown_choice_guard_errors_without_calling_provider(){
  struct Unknown;impl Machine for Unknown{fn read_register(&self,_:Register)->Value{Value::unknown(64)}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!()}fn choose(&self,_:usize,_:u8)->Result<Value,EvalError>{panic!("unknown guard requested entropy")}}
  let mut r=Recipe::new(4,64);r.choose(64,Some(Expr::register(register("incoming",0,1,64))));assert_eq!(evaluate(&r,&Unknown),Err(EvalError::UnknownCondition));
 }
 #[test]fn entropy_predicates_only_reference_earlier_results(){
  let mut r=Recipe::new(4,64);let choice=r.choose(1,None);assert_eq!(validate_expression(&choice,&[]),Err(EvalError::InvalidExpression));
  r.choices[0].condition=Some(choice.clone());assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
  r.choices[0].condition=None;r.choices[0].width=65;assert_eq!(r.validate(),Err(EvalError::InvalidExpression));
 }
}
`
