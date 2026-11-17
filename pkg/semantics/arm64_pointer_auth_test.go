package semantics

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runPointerRust(t *testing.T, source string, extra map[string]string) {
	t.Helper()
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	dir := t.TempDir()
	files := map[string]string{"runtime.rs": RustRuntime, "tests.rs": source}
	for name, body := range extra {
		files[name] = body
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("rustc", "--edition=2021", "--test", "tests.rs", "-Dwarnings", "-o", "pointer-tests")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("compile pointer authentication: %v\n%s", err, out)
	}
	cmd = exec.Command(filepath.Join(dir, "pointer-tests"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("execute pointer authentication: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
func TestRustArm64PointerAuthentication(t *testing.T) {
	runPointerRust(t, pointerAuthenticationTests+pointerCorpusFixtures, nil)
}

// Compile the production QARMA engine directly when its sibling checkout is
// available. This tests the generated runtime/recipe boundary without invoking
// Cargo or substituting host cryptography. Only its crate import is adapted.
func TestRustArm64PointerAuthenticationNativeEngine(t *testing.T) {
	path := filepath.Join("..", "..", "..", "binary-toolkit", "crates", "isa", "arm", "src", "cpu", "pac.rs")
	source, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("native PAC consumer checkout unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	sourceText := strings.Replace(string(source), "use isa_core::{execution::*, *};", "use crate::native_contract::{execution::*, *};", 1)
	if sourceText == string(source) {
		t.Fatal("native PAC import changed; update the standalone consumer harness")
	}
	runPointerRust(t, pointerAuthenticationTests+pointerCorpusFixtures+pointerNativeTests, map[string]string{"native_pac.rs": sourceText})
}

const pointerAuthenticationTests = `
#[allow(dead_code)]mod runtime;
use runtime::*;
use runtime::arm64_pointer;
use std::cell::RefCell;
#[derive(Clone,Debug,PartialEq,Eq)]struct Call{op:PointerAuthOperation,key:PointerAuthKey,inputs:Vec<u64>}
struct State{
 x:[u64;31],sp:u64,present:bool,lr:bool,pacm:bool,enabled:bool,keys:u8,
 unknown_context:bool,unknown_pacm:bool,permit_inputs:bool,engine:bool,
 calls:RefCell<Vec<Call>>,reads:RefCell<Vec<(&'static str,u16)>>,
 memory:Vec<(u64,u8)>,loads:RefCell<Vec<(u64,u8,Endian)>>,
}
impl Default for State{fn default()->Self{Self{x:[0;31],sp:0x8000,present:true,lr:true,pacm:false,enabled:false,keys:15,unknown_context:false,unknown_pacm:false,permit_inputs:true,engine:true,calls:RefCell::default(),reads:RefCell::default(),memory:vec![],loads:RefCell::default()}}}
impl Machine for State{
 fn read_register(&self,r:Register)->Value{
  self.reads.borrow_mut().push((r.bank,r.index));
  if r.bank.starts_with("a64.p"){
   if self.unknown_context||(self.unknown_pacm&&r.bank=="a64.pacm"){return Value::unknown(1);}
   return Value::known(1,u64::from(match r.bank{"a64.pauth_present"=>self.present,"a64.pauth_lr_present"=>self.lr,"a64.pacm"=>self.pacm,"a64.pacm_enabled"=>self.enabled,"a64.pac_key_enabled"=>self.keys&(1<<r.index)!=0,_=>panic!("{r:?}")}));
  }
  assert!(self.permit_inputs,"disabled feature read {r:?}");
  match r.bank{"a64.gpr"=>Value::known(64,self.x[r.index as usize]),"a64.sp"=>Value::known(64,self.sp),_=>panic!("{r:?}")}
 }
 fn read_memory(&self,address:u64,width:u8,endian:Endian)->Result<Value,EvalError>{
  self.loads.borrow_mut().push((address,width,endian));let mut bits=0;
  for i in 0..u64::from(width/8){let byte=self.memory.iter().find(|(a,_)|*a==address.wrapping_add(i)).ok_or(EvalError::Unsupported)?.1;
   let shift=if endian==Endian::Little{i*8}else{u64::from(width)-8-i*8};bits|=u64::from(byte)<<shift;
  }Ok(Value::known(width,bits))
 }
 fn evaluate_pointer_authentication(&self,p:&PointerAuthenticationExpression,inputs:&[Value])->Result<Value,EvalError>{
  if !self.engine{return Err(EvalError::Unsupported);}
  self.calls.borrow_mut().push(Call{op:p.operation,key:p.key,inputs:inputs.iter().map(|v|{assert_eq!(v.width,64);assert!(v.is_known());v.bits}).collect()});
  // A typed backend boundary fixture. Cryptographic outcomes are exercised
  // separately against the actual production QARMA implementation below.
  Ok(Value::known(64,0x1234))
 }
}
fn run(word:u32,address:u64,s:&impl Machine)->Transition{let r=arm64_pointer::a64(word,address).unwrap();assert_eq!(r.support,Support::Full,"{word:08x}");r.validate().unwrap();evaluate(&r,s).unwrap()}
fn output(t:&Transition,index:u16)->Option<u64>{t.registers.iter().find(|w|w.register.bank=="a64.gpr"&&w.register.index==index).map(|w|{assert!(w.value.is_known());w.value.bits})}
fn inputs(s:&State,op:PointerAuthOperation,key:PointerAuthKey,values:&[u64]){assert_eq!(*s.calls.borrow(),[Call{op,key,inputs:values.to_vec()}]);}
#[test]fn all_base_keys_zero_modifiers_aliases_and_sp(){
 for opcode in 0..8{for zero in [false,true]{for d in [0,1,31]{for n in [1,31]{
  if zero&&n!=31{continue;}
  let mut s=State::default();s.x[0]=0x111;s.x[1]=0x222;
  let word=0xdac10000|(opcode<<10)|(u32::from(zero)<<13)|(n<<5)|d;
  let t=run(word,0x1000,&s);
  let pointer=if d==31{0}else{s.x[d as usize]};let modifier=if zero{0}else if n==31{s.sp}else{s.x[n as usize]};
  inputs(&s,if opcode<4{PointerAuthOperation::Sign}else{PointerAuthOperation::Authenticate},[PointerAuthKey::InstructionA,PointerAuthKey::InstructionB,PointerAuthKey::DataA,PointerAuthKey::DataB][(opcode&3)as usize],&[pointer,modifier]);
  assert_eq!(output(&t,d as u16),if d==31{None}else{Some(0x1234)});
 }}}}
}
#[test]fn implicit_pacm_selects_second_modifier_and_disabled_modes_are_lazy(){
 for (word,d,op,key,sp)in[(0xd503233f,30,PointerAuthOperation::Sign,PointerAuthKey::InstructionA,true),(0xd50323ff,30,PointerAuthOperation::Authenticate,PointerAuthKey::InstructionB,true),(0xd503211f,17,PointerAuthOperation::Sign,PointerAuthKey::InstructionA,false),(0xd50321df,17,PointerAuthOperation::Authenticate,PointerAuthKey::InstructionB,false)]{
  for lr in [false,true]{for pacm in [false,true]{let mut s=State::default();s.lr=lr;s.pacm=pacm;s.x[d]=0x111;s.x[16]=0x222;s.x[15]=0x333;
   run(word,0x5000,&s);let mut expected=vec![0x111,if sp{s.sp}else{s.x[16]}];if lr&&pacm{expected.push(if sp{if op==PointerAuthOperation::Sign{0x5000}else{s.x[16]}}else{s.x[15]});}inputs(&s,op,key,&expected);
   if !lr{assert!(!s.reads.borrow().iter().any(|(bank,_)|*bank=="a64.pacm"));}
  }}
 }
 let mut s=State::default();s.present=false;s.lr=false;s.permit_inputs=false;s.engine=false;
 for word in [0xd503211f,0xd503215f,0xd503219f,0xd50321df,0xd503231f,0xd503235f,0xd503239f,0xd50323df,0xd503233f,0xd503237f,0xd50323bf,0xd50323ff,0xd50320ff,0xd50324ff]{let t=run(word,0x1000,&s);assert!(t.registers.is_empty());assert!(s.calls.borrow().is_empty());}
 let mut disabled=State::default();disabled.keys=0;disabled.engine=false;disabled.x[0]=0xfeed;
 let t=run(0xdac10020,0,&disabled);assert_eq!(output(&t,0),Some(0xfeed));assert!(disabled.calls.borrow().is_empty());assert!(!disabled.reads.borrow().contains(&("a64.gpr",1)));
 disabled.unknown_pacm=true;let t=run(0xdac103e0,0,&disabled);assert_eq!(output(&t,0),Some(0xfeed));assert!(!disabled.reads.borrow().contains(&("a64.pacm",0)));
}
#[test]fn fixed_lr_pc_relative_register_and_pacm_forms(){
 for (word,op,key,d,modifier,second)in[
  (0xdac1a3fe,PointerAuthOperation::Sign,PointerAuthKey::InstructionA,30,0x8000,0x1000),
  (0xdac187fe,PointerAuthOperation::Sign,PointerAuthKey::InstructionB,30,0x8000,0x1000),
  (0xdac18bfe,PointerAuthOperation::Sign,PointerAuthKey::InstructionA,17,0x222,0x333),
  (0xdac1bffe,PointerAuthOperation::Authenticate,PointerAuthKey::InstructionB,17,0x222,0x333),
  (0xf380007f,PointerAuthOperation::Authenticate,PointerAuthKey::InstructionA,30,0x8000,0xff4),
  (0xdac1943e,PointerAuthOperation::Authenticate,PointerAuthKey::InstructionB,30,0x8000,0x444),
 ]{let mut s=State::default();s.x[d]=0x111;s.x[16]=0x222;s.x[15]=0x333;s.x[1]=0x444;run(word,0x1000,&s);inputs(&s,op,key,&[0x111,modifier,second]);}
 for enabled in [false,true]{let mut s=State::default();s.enabled=enabled;let t=run(0xd50324ff,0,&s);assert_eq!(t.registers.len(),1);assert_eq!(t.registers[0].register.bank,"a64.pacm");assert_eq!(t.registers[0].value,Value::known(1,u64::from(enabled)));}
 let mut s=State::default();s.x[30]=0x111;run(0xf380007f,4,&s);inputs(&s,PointerAuthOperation::Authenticate,PointerAuthKey::InstructionA,&[0x111,s.sp,u64::MAX-7]);
}
#[test]fn branch_call_return_capture_incoming_link_and_authentication(){
 for (word,kind,key,expected)in[
  (0xd71f0822,FlowKind::Branch,PointerAuthKey::InstructionA,vec![0x111,0x222]),
  (0xd63f0fdf,FlowKind::Call,PointerAuthKey::InstructionB,vec![0x333,0]),
  (0xd65f0bff,FlowKind::Return,PointerAuthKey::InstructionA,vec![0x333,0x8000]),
  (0xd65f0fe2,FlowKind::Return,PointerAuthKey::InstructionB,vec![0x333,0x8000,0x222]),
  (0x5520007f,FlowKind::Return,PointerAuthKey::InstructionB,vec![0x333,0x8000,0xff4]),
 ]{let mut s=State::default();s.x[1]=0x111;s.x[2]=0x222;s.x[30]=0x333;
  let r=arm64_pointer::a64(word,0x1000).unwrap();assert_eq!(r.flow.kind,kind);let t=evaluate(&r,&s).unwrap();assert_eq!(t.next_pc,Value::known(64,0x1234));inputs(&s,PointerAuthOperation::Authenticate,key,&expected);assert_eq!(output(&t,30),if kind==FlowKind::Call{Some(0x1004)}else{None});
 }
}
#[test]fn authenticated_load_uses_authenticated_base_offset_original_width_and_endian(){
 for endian in [Endian::Little,Endian::Big]{for keyb in [false,true]{for writeback in [false,true]{for n in [1,31]{for rt in [0,31]{
  let mut s=State::default();s.x[1]=0xfeed;s.sp=0x8000;s.memory=(0..8).map(|i|(0x1224+i,i as u8+1)).collect();
  let word=0xf8200400|(u32::from(keyb)<<23)|(1<<22)|(510<<12)|(u32::from(writeback)<<11)|(n<<5)|rt; // signed10-bit -2 scaled8
  let r=arm64_pointer::a64_with_endian(word,0x1000,endian).unwrap();let t=evaluate(&r,&s).unwrap();
  inputs(&s,PointerAuthOperation::Authenticate,if keyb{PointerAuthKey::DataB}else{PointerAuthKey::DataA},&[if n==31{s.sp}else{s.x[1]},0]);
  assert_eq!(*s.loads.borrow(),[(0x1224,64,endian)]);assert_eq!(output(&t,rt as u16),if rt==31{None}else{Some(if endian==Endian::Little{0x0807060504030201}else{0x0102030405060708})});
  if writeback{let w=t.registers.last().unwrap();assert_eq!(w.value,Value::known(64,0x1224));assert_eq!(w.register.bank,if n==31{"a64.sp"}else{"a64.gpr"});}
 }}}}}
 assert!(matches!(arm64_pointer::a64(0xf8202c21,0).unwrap().support,Support::Unsupported(_)));
 let mut s=State::default();s.sp=1;let r=arm64_pointer::a64(0xf82007e0,0).unwrap();assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));assert!(s.calls.borrow().is_empty());assert!(s.loads.borrow().is_empty());
}
struct UnknownPointer;
impl Machine for UnknownPointer{
 fn read_register(&self,_:Register)->Value{Value::unknown(64)}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unexpected pointer memory")}
 fn evaluate_pointer_authentication(&self,_:&PointerAuthenticationExpression,_:&[Value])->Result<Value,EvalError>{panic!("unknown data entered known-input PAC backend")}
}
struct MalformedPointer(bool);
impl Machine for MalformedPointer{
 fn read_register(&self,_:Register)->Value{panic!("unexpected register")}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{panic!("unexpected memory")}
 fn evaluate_pointer_authentication(&self,_:&PointerAuthenticationExpression,_:&[Value])->Result<Value,EvalError>{Ok(if self.0{Value::unknown(64)}else{Value::known(32,0)})}
}
#[test]fn pointer_graph_validation_unknown_results_and_lazy_branches_are_typed(){
 let expression=Expr::pointer_authentication(PointerAuthenticationExpression{operation:PointerAuthOperation::Authenticate,key:PointerAuthKey::InstructionA,inputs:vec![Expr::register(register("incoming",0,64,64)),Expr::constant(64,0)]}).unwrap();
 assert_eq!(evaluate_expression(&expression,&UnknownPointer,&[]),Ok(Value::unknown(64)));
 let known=Expr::pointer_authentication(PointerAuthenticationExpression{operation:PointerAuthOperation::StripData,key:PointerAuthKey::None,inputs:vec![Expr::constant(64,0)]}).unwrap();
 for malformed in [false,true]{assert_eq!(evaluate_expression(&known,&MalformedPointer(malformed),&[]),Err(EvalError::InvalidExpression));}
 let inactive=Expr::select(Expr::constant(1,0),known.clone(),Expr::constant(64,7));assert_eq!(evaluate_expression(&inactive,&UnknownPointer,&[]),Ok(Value::known(64,7)));
 let mut bad=known;if let ExprKind::PointerAuthentication(p)=&mut bad.kind{p.inputs[0]=Expr::constant(32,0);}
 assert_eq!(validate_expression(&Expr::select(Expr::constant(1,0),bad,Expr::constant(64,7)),&[]),Err(EvalError::InvalidExpression));
}
#[test]fn primitive_dimensions_unknowns_missing_backend_and_context_are_explicit(){
 for (op,key,n,valid)in[(PointerAuthOperation::Sign,PointerAuthKey::InstructionA,3,true),(PointerAuthOperation::Authenticate,PointerAuthKey::DataA,3,false),(PointerAuthOperation::StripData,PointerAuthKey::None,1,true),(PointerAuthOperation::Generic,PointerAuthKey::Generic,2,true),(PointerAuthOperation::Generic,PointerAuthKey::InstructionA,2,false)]{
  let result=Expr::pointer_authentication(PointerAuthenticationExpression{operation:op,key,inputs:vec![Expr::constant(64,0);n]});assert_eq!(result.is_ok(),valid);
 }
 let mut s=State::default();s.engine=false;let r=arm64_pointer::a64(0xdac10020,0).unwrap();assert_eq!(evaluate(&r,&s),Err(EvalError::Unsupported));
 s.engine=true;s.unknown_context=true;assert_eq!(evaluate(&r,&s),Err(EvalError::UnknownCondition));
 s.unknown_context=false;s.present=false;assert_eq!(evaluate(&r,&s),Err(EvalError::UnsupportedContext));
 for word in [0xdac12000,0xd61f0800,0xd503201f]{assert!(arm64_pointer::a64(word,0).is_none(),"reserved/unrelated {word:08x}");}
 for word in [0xd69f0bff,0xd69f0fff]{assert!(matches!(arm64_pointer::a64(word,0).unwrap().support,Support::Unsupported(_)));}
}
`

const pointerNativeTests = `
#[allow(dead_code)]mod native_contract{
 pub(crate) use crate::{PointerAuthOperation,PointerAuthKey};
 pub mod execution{
  #[derive(Clone,Copy,Debug,PartialEq,Eq)]pub enum PointerAuthenticationPolicy{AssumeValid,Strict}
  #[derive(Debug,PartialEq,Eq)]pub enum ExecutionFault{Invalid(String),Unavailable(String)}
  pub struct CpuConfiguration{
   pub virtual_address_bits:u8,pub top_byte_ignore:bool,pub pointer_authentication:PointerAuthenticationPolicy,
   pub pointer_authentication_keys:Option<[[u64;2];4]>,pub pointer_authentication_generic_key:Option<[u64;2]>,
  }
 }
}
#[path="native_pac.rs"]mod native_pac;
struct Native{state:State,configuration:native_contract::execution::CpuConfiguration}
impl Default for Native{fn default()->Self{Self{state:State::default(),configuration:native_contract::execution::CpuConfiguration{
 virtual_address_bits:48,top_byte_ignore:true,pointer_authentication:native_contract::execution::PointerAuthenticationPolicy::Strict,
 pointer_authentication_keys:Some([[0x84be85ce9804e94b,0xec2802d4e0a488e9];4]),pointer_authentication_generic_key:Some([0x84be85ce9804e94b,0xec2802d4e0a488e9]),
}}}}
impl Machine for Native{
 fn read_register(&self,r:Register)->Value{self.state.read_register(r)}
 fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{self.state.read_memory(a,w,e)}
 fn evaluate_pointer_authentication(&self,p:&PointerAuthenticationExpression,values:&[Value])->Result<Value,EvalError>{
  let get=|i:usize|values.get(i).map(|v|v.bits);
  native_pac::evaluate(&self.configuration,p.operation,p.key,get(0).unwrap(),get(1).unwrap_or(0),matches!(p.key,PointerAuthKey::DataA|PointerAuthKey::DataB)||p.operation==PointerAuthOperation::StripData,get(2)).map(|v|Value::known(64,v)).map_err(|_|EvalError::Unsupported)
 }
}
#[test]fn native_pac2_signed_pc_roundtrip_and_wrong_second_modifier_failure(){
 let mut s=Native::default();s.state.x[30]=0x12345678;
 let signed=output(&run(0xdac1a3fe,0x1000,&s),30).unwrap();assert_ne!(signed,s.state.x[30]);s.state.x[30]=signed;
 assert_eq!(output(&run(0xf380007f,0x100c,&s),30),Some(0x12345678));
 assert_eq!(output(&run(0xf380017f,0x100c,&s),30),Some(0x2000000012345678)); // signing PC differs by bit5
 s.state.sp+=15;assert_eq!(output(&run(0xf380007f,0x100c,&s),30),Some(0x12345678)); // modifier1 low4 excluded
 s.state.sp+=1;assert_eq!(output(&run(0xf380007f,0x100c,&s),30),Some(0x2000000012345678));
}
#[test]fn native_pacga_matches_published_qarma5_and_strip_retains_data_tag_identity(){
 let mut s=Native::default();s.state.x[1]=0xfb623599da6e8127;s.state.x[2]=0x477d469dec0b8762;
 assert_eq!(output(&run(0x9ac23020,0,&s),0),Some(0xc003b93900000000));
 s.state.x[0]=0xab80123456789abc;
 assert_eq!(output(&run(0xdac143e0,0,&s),0),Some(0xffff123456789abc));
 assert_eq!(output(&run(0xdac147e0,0,&s),0),Some(0xabff123456789abc));
 s.configuration.pointer_authentication_generic_key=None;assert_eq!(evaluate(&arm64_pointer::a64(0x9ac23020,0).unwrap(),&s),Err(EvalError::Unsupported));
}
#[test]fn native_authenticated_call_captures_link_before_write_and_load_preserves_endian(){
 let mut s=Native::default();s.state.x[30]=0x12345678;
 let signed=output(&run(0xdac123fe,0,&s),30).unwrap();s.state.x[30]=signed;
 let t=run(0xd63f0bdf,0x1000,&s);assert_eq!(t.next_pc,Value::known(64,0x12345678));assert_eq!(output(&t,30),Some(0x1004));
 for endian in [Endian::Little,Endian::Big]{
  let mut s=Native::default();let base=0x2000;
  s.state.x[1]=native_pac::evaluate(&s.configuration,PointerAuthOperation::Sign,PointerAuthKey::DataA,base,0,true,None).unwrap();
  s.state.memory=(0..8).map(|i|(base+16+i,i as u8+1)).collect();
  let r=arm64_pointer::a64_with_endian(0xf8202c20,0,endian).unwrap();let t=evaluate(&r,&s).unwrap();
  assert_eq!(output(&t,0),Some(if endian==Endian::Little{0x0807060504030201}else{0x0102030405060708}));assert_eq!(output(&t,1),Some(base+16));
 }
}
// Fixed scalar results transcribed from June2026 InsertPAC/Authenticate,
// using the published QARMA5 key. These check field construction, rather than
// accepting whichever corruption or range selection the native engine chooses.
#[test]fn native_primary_noncanonical_signing_vectors(){
 for (word,input,tbi,expected)in[
  (0xdac123e0,0x0001000012345678,false,0x5072000012345678),
  (0xdac12be0,0xab01000012345678,true,0xab50000012345678),
  (0xdac123e0,0x8000000012345678,false,0x52e3000012345678),
 ]{
  let mut s=Native::default();s.configuration.top_byte_ignore=tbi;s.state.x[0]=input;
  assert_eq!(output(&run(word,0,&s),0),Some(expected));
 }
}
#[test]fn native_authentication_failure_obeys_tbi_and_key_error_code(){
 for (sign,auth,tbi,expected)in[
  (0xdac123e0,0xdac133e0,false,0x2000000012345678),
  (0xdac127e0,0xdac137e0,false,0x4000000012345678),
  (0xdac12be0,0xdac13be0,false,0x2000000012345678),
  (0xdac12fe0,0xdac13fe0,false,0x4000000012345678),
  (0xdac12be0,0xdac13be0,true,0xab20000012345678),
  (0xdac12fe0,0xdac13fe0,true,0xab40000012345678),
 ]{
  let mut s=Native::default();s.configuration.top_byte_ignore=tbi;
  s.state.x[0]=if tbi{0xab00000012345678}else{0x12345678};
  let signed=output(&run(sign,0,&s),0).unwrap();s.state.x[0]=signed^(1<<48);
  assert_eq!(output(&run(auth,0,&s),0),Some(expected));
 }
}
#[test]fn assume_valid_retains_strip_policy_with_unknown_keys(){
 let mut s=Native::default();s.configuration.pointer_authentication=native_contract::execution::PointerAuthenticationPolicy::AssumeValid;s.configuration.pointer_authentication_keys=None;
 s.state.x[0]=0x8000000012345678;
 // AssumeValid intentionally strips even Sign; its address restoration uses
 // bit55 and does not acquire strict signing's bit63/cipher dependencies.
 for word in[0xdac123e0,0xdac133e0,0xdac143e0]{assert_eq!(output(&run(word,0,&s),0),Some(0x12345678));}
 s.state.x[0]=0xab80123456789abc;
 assert_eq!(output(&run(0xdac147e0,0,&s),0),Some(0xabff123456789abc));
}
#[test]fn native_missing_key_rejects_selected_operation_but_disabled_key_is_identity(){
 let mut s=Native::default();s.configuration.pointer_authentication_keys=None;s.state.x[0]=0xabcdef;
 let r=arm64_pointer::a64(0xdac10020,0).unwrap();assert_eq!(evaluate(&r,&s),Err(EvalError::Unsupported));
 s.state.keys=0;assert_eq!(output(&evaluate(&r,&s).unwrap(),0),Some(0xabcdef));
}
`

// Canonical words independently derived from every PAC-related physical
// encoding's June2026 register diagram and encoding bitdiff constraints.
const pointerCorpusFixtures = `
#[test]fn every_primary_pointer_authentication_form_has_an_honest_recipe(){
 for(word,name)in [
(0xdac1a3fe,"PACIASPPC_64LR_dp_1src"),
(0xdac1a7fe,"PACIBSPPC_64LR_dp_1src"),
(0xdac183fe,"PACNBIASPPC_64LR_dp_1src"),
(0xdac187fe,"PACNBIBSPPC_64LR_dp_1src"),
(0xdac18bfe,"PACIA171615_64LR_dp_1src"),
(0xdac18ffe,"PACIB171615_64LR_dp_1src"),
(0xdac1bbfe,"AUTIA171615_64LR_dp_1src"),
(0xdac1bffe,"AUTIB171615_64LR_dp_1src"),
(0xdac1903e,"AUTIASPPCR_64LRR_dp_1src"),
(0xdac1943e,"AUTIBSPPCR_64LRR_dp_1src"),
(0xf380007f,"AUTIASPPC_only_dp_1src_imm"),
(0xf3a0007f,"AUTIBSPPC_only_dp_1src_imm"),
(0xd65f0be2,"RETAASPPCR_64M_branch_reg"),
(0xd65f0fe2,"RETABSPPCR_64M_branch_reg"),
(0x5500007f,"RETAASPPC_only_miscbranch"),
(0x5520007f,"RETABSPPC_only_miscbranch"),
(0xd71f0822,"BRAA_64P_branch_reg"),
(0xd61f083f,"BRAAZ_64_branch_reg"),
(0xd71f0c22,"BRAB_64P_branch_reg"),
(0xd61f0c3f,"BRABZ_64_branch_reg"),
(0xd73f0822,"BLRAA_64P_branch_reg"),
(0xd63f083f,"BLRAAZ_64_branch_reg"),
(0xd73f0c22,"BLRAB_64P_branch_reg"),
(0xd63f0c3f,"BLRABZ_64_branch_reg"),
(0xd65f0bff,"RETAA_64E_branch_reg"),
(0xd65f0fff,"RETAB_64E_branch_reg"),
(0xf8202420,"LDRAA_64_ldst_pac"),
(0xf8202c20,"LDRAA_64W_ldst_pac"),
(0xf8a02420,"LDRAB_64_ldst_pac"),
(0xf8a02c20,"LDRAB_64W_ldst_pac"),
(0xd69f0bff,"ERETAA_64E_branch_reg"),
(0xd69f0fff,"ERETAB_64E_branch_reg"),
(0xdac10020,"PACIA_64P_dp_1src"),
(0xdac123e0,"PACIZA_64Z_dp_1src"),
(0xd503211f,"PACIA1716_HI_hints"),
(0xd503233f,"PACIASP_HI_hints"),
(0xd503231f,"PACIAZ_HI_hints"),
(0xdac10420,"PACIB_64P_dp_1src"),
(0xdac127e0,"PACIZB_64Z_dp_1src"),
(0xd503215f,"PACIB1716_HI_hints"),
(0xd503237f,"PACIBSP_HI_hints"),
(0xd503235f,"PACIBZ_HI_hints"),
(0xdac10820,"PACDA_64P_dp_1src"),
(0xdac12be0,"PACDZA_64Z_dp_1src"),
(0xdac10c20,"PACDB_64P_dp_1src"),
(0xdac12fe0,"PACDZB_64Z_dp_1src"),
(0xdac11020,"AUTIA_64P_dp_1src"),
(0xdac133e0,"AUTIZA_64Z_dp_1src"),
(0xd503219f,"AUTIA1716_HI_hints"),
(0xd50323bf,"AUTIASP_HI_hints"),
(0xd503239f,"AUTIAZ_HI_hints"),
(0xdac11420,"AUTIB_64P_dp_1src"),
(0xdac137e0,"AUTIZB_64Z_dp_1src"),
(0xd50321df,"AUTIB1716_HI_hints"),
(0xd50323ff,"AUTIBSP_HI_hints"),
(0xd50323df,"AUTIBZ_HI_hints"),
(0xdac11820,"AUTDA_64P_dp_1src"),
(0xdac13be0,"AUTDZA_64Z_dp_1src"),
(0xdac11c20,"AUTDB_64P_dp_1src"),
(0xdac13fe0,"AUTDZB_64Z_dp_1src"),
(0xdac147e0,"XPACD_64Z_dp_1src"),
(0xdac143e0,"XPACI_64Z_dp_1src"),
(0xd50320ff,"XPACLRI_HI_hints"),
(0x9ac23020,"PACGA_64P_dp_2src"),
(0xd50324ff,"PACM_HI_hints"),
 ]{
  for endian in [Endian::Little,Endian::Big]{
   let r=arm64_pointer::a64_with_endian(word,0x1000,endian).unwrap_or_else(||panic!("missing {name} {word:08x}"));
   if name.starts_with("ERET"){assert!(matches!(r.support,Support::Unsupported(_)));}else{assert_eq!(r.support,Support::Full,"{name}");r.validate().unwrap();}
  }
 }
}
`
