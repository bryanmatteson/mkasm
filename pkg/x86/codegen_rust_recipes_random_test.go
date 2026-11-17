package x86

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The production catalog is decoded and executed; rustc avoids a Cargo build.
func TestRustX86RandomRecipes(t *testing.T) {
	input := os.Getenv("MKASM_X86_OPCODESDB")
	if input == "" {
		t.Skip("set MKASM_X86_OPCODESDB to the pinned production catalog")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseOpcodesDB(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SupplementXEDFP16(c); err != nil {
		t.Fatal(err)
	}
	if _, err := SupplementXEDInteger(c); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := GenerateRust(c, dir); err != nil {
		t.Fatal(err)
	}
	tests := x86RecipeTests + x86CorpusBoundaryTests + x86ExpandedRecipeTests + x86MaskedMemoryTests + x86HalfRecipeTests + x86BfloatRecipeTests + x86FP16RecipeTests + x86Avx512IntegerRecipeTests + x86XEDIntegerRecipeTests + x86RandomRecipeTests
	if err := os.WriteFile(filepath.Join(dir, "random_tests.rs"), []byte(tests), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--edition=2021", "--crate-name", "x86_64", "--crate-type", "rlib", "src/lib.rs", "-Dwarnings", "-o", "libx86_64.rlib"}, {"--edition=2021", "--test", "random_tests.rs", "--extern", "x86_64=libx86_64.rlib", "-Dwarnings", "-o", "random_tests"}} {
		cmd := exec.Command("rustc", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated Rust: %v\n%s", err, out)
		}
	}
	cmd := exec.Command(filepath.Join(dir, "random_tests"), "--nocapture")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("production random recipes: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
	t.Logf("validated production catalog: %d forms", len(c.Encodings))
}

const x86RandomRecipeTests = `
struct EntropyState{success:bool,value:u64,calls:std::cell::RefCell<Vec<(usize,u8)>>,malformed:u8}
impl EntropyState{fn new(success:bool,value:u64)->Self{Self{success,value,calls:Default::default(),malformed:0}}}
impl Machine for EntropyState{
 fn read_register(&self,r:s::Register)->Value{assert_eq!(r.bank,"x86.gpr","random recipe read flags or unrelated state");Value::known(64,0x0123456789abcdef)}
 fn read_memory(&self,_:u64,_:u8,_:s::Endian)->Result<Value,EvalError>{panic!("random recipe read memory")}
 fn choose(&self,step:usize,width:u8)->Result<Value,EvalError>{self.calls.borrow_mut().push((step,width));if self.malformed==1{return Err(EvalError::Unsupported)}if self.malformed==2{return Ok(Value::unknown(width))}if self.malformed==3{return Ok(Value::known(if width==1{2}else{1},1))}Ok(Value::known(width,if step==0{u64::from(self.success)}else{assert_eq!(step,1);self.value}))}
}
fn random_bytes(group:u8,mode:Mode,width:u8,dest:u8)->Vec<u8>{let mut b=vec![];if (mode==Mode::Mode16)!=(width==16){b.push(0x66)}if width==64||dest>=8{b.push(0x40|if width==64{8}else{0}|if dest>=8{1}else{0})}b.extend_from_slice(&[0x0f,0xc7,0xc0|(group<<3)|(dest&7)]);b}
#[test]fn random_actual_forms_all_modes_widths_registers_success_and_failure(){
 let mut forms=0;for i in 0..encoding_count(){let e=encoding(i).unwrap();if !matches!(e.mnemonic,"RDRAND"|"RDSEED"){continue}forms+=1;let group=if e.mnemonic=="RDRAND"{6}else{7};
  for mode in[Mode::Mode16,Mode::Mode32,Mode::Mode64]{for width in[16u8,32,64]{if width==64&&mode!=Mode::Mode64{continue}for dest in if mode==Mode::Mode64{vec![0,3,9,15]}else{vec![0,3,7]}{let bytes=random_bytes(group,mode,width,dest);let d=decode(&bytes,mode).unwrap();assert_eq!(d.encoding().mnemonic,e.mnemonic);assert_eq!(d.operands()[0].register.unwrap().number,dest);let r=d.semantic_recipe(0xffff);assert_eq!(r.support,Support::Full,"{bytes:02x?} {mode:?}");r.validate().unwrap();assert_eq!(r.choices.len(),2);assert_eq!(r.choices[0].width,1);assert_eq!(r.choices[1].width,width);
   for success in[false,true]{for value in[0,u64::MAX,0x800012345678abcd]{let st=EntropyState::new(success,value);let t=s::evaluate(&r,&st).unwrap();assert_eq!(*st.calls.borrow(),if success{vec![(0,1),(1,width)]}else{vec![(0,1)]});let mask=if width==64{u64::MAX}else{(1u64<<width)-1};let old=0x0123456789abcdef;let bits=if success{value&mask}else{0};let expected=if width==16||(width==32&&mode!=Mode::Mode64){old&!mask|bits}else{bits};assert_eq!(x(&t,u16::from(dest)),expected,"{} {mode:?} w{width} {success}",e.form_id);assert_eq!(flag(&t,0),Value::known(1,u64::from(success)));for flag_index in 1..6{assert_eq!(flag(&t,flag_index),Value::known(1,0))}assert_eq!(t.registers.len(),7);assert!(t.memory.is_empty());assert_eq!(t.next_pc.bits,(0xffff+bytes.len() as u64)&if mode==Mode::Mode64{u64::MAX}else{0xffff_ffff});}}
  }}}
 }assert_eq!(forms,2);
}
#[test]fn ordinary_random_fallthrough_uses_eip_independent_of_operand_default(){
 for group in[6,7]{for mode in[Mode::Mode16,Mode::Mode32,Mode::Mode64]{for width in[16,32,64]{if width==64&&mode!=Mode::Mode64{continue}let bytes=random_bytes(group,mode,width,0);let d=decode(&bytes,mode).unwrap();for ip in[0x10000-bytes.len() as u64,0xffff_fffd,u64::MAX-1]{for success in[false,true]{let st=EntropyState::new(success,0x123456789abcdef0);let r=d.semantic_recipe(ip);let t=s::evaluate(&r,&st).unwrap();let expected=ip.wrapping_add(bytes.len() as u64)&if mode==Mode::Mode64{u64::MAX}else{0xffff_ffff};assert_eq!(t.next_pc,Value::known(if mode==Mode::Mode64{64}else{32},expected),"group{group} {mode:?} w{width} ip{ip:x}");assert_eq!(flag(&t,0),Value::known(1,u64::from(success)));}}}}}
 // All ordinary constructors share EIP advancement: scalar, packed integer,
 // shifts, FP arithmetic, vector transfers, and x87/environment instructions.
 for mode in[Mode::Mode16,Mode::Mode32,Mode::Mode64]{for bytes in[&[0x90][..],&[0x89,0xc0],&[0x01,0xc0],&[0x66,0x0f,0xfc,0xc1],&[0x66,0x0f,0x71,0xf0,1],&[0xf3,0x0f,0x58,0xc1],&[0x66,0x0f,0xd7,0xc1],&[0xdb,0xe3],&[0x0f,0xae,0x00]]{let d=decode(bytes,mode).unwrap();let ip=0x10000-bytes.len() as u64;let mut r=d.semantic_recipe(ip);assert_eq!(r.support,Support::Full,"{} {mode:?} {bytes:02x?}",d.encoding().mnemonic);r.validate().unwrap();assert_eq!(r.flow.kind,s::FlowKind::Next);assert_eq!(r.flow.fallthrough,s::Expr::constant(if mode==Mode::Mode64{64}else{32},0x10000));r.guard=s::Expr::constant(1,0);assert_eq!(s::evaluate(&r,&EntropyState::new(false,0)).unwrap().next_pc.bits,0x10000);}}
}
#[test]fn random_invalid_prefixes_and_memory_encodings_do_not_claim_full(){
 for mode in[Mode::Mode16,Mode::Mode32,Mode::Mode64]{for group in[6,7]{for prefix in[0xf0,0xf2,0xf3]{let bytes=[prefix,0x0f,0xc7,0xc0|(group<<3)];if let Ok(d)=decode(&bytes,mode){assert_ne!(d.semantic_recipe(0).support,Support::Full,"{bytes:02x?}")}}if let Ok(d)=decode(&[0x0f,0xc7,group<<3],mode){assert!(!matches!(d.encoding().mnemonic,"RDRAND"|"RDSEED"));}}}
}
#[test]fn random_missing_or_unknown_entropy_is_an_error_and_failure_suppresses_value(){
 let r=decode(&[0x48,0x0f,0xc7,0xf0],Mode::Mode64).unwrap().semantic_recipe(0);for malformed in 1..=3{let mut st=EntropyState::new(true,4);st.malformed=malformed;assert_eq!(s::evaluate(&r,&st),Err(if malformed==1{EvalError::Unsupported}else{EvalError::InvalidChoiceOutcome}));assert_eq!(*st.calls.borrow(),vec![(0,1)]);}
 struct NoEntropy;impl Machine for NoEntropy{fn read_register(&self,_:s::Register)->Value{panic!("read before unavailable entropy")}fn read_memory(&self,_:u64,_:u8,_:s::Endian)->Result<Value,EvalError>{panic!()}}
 assert_eq!(s::evaluate(&r,&NoEntropy),Err(EvalError::Unsupported));let mut guarded=r.clone();guarded.guard=s::Expr::constant(1,0);assert!(s::evaluate(&guarded,&NoEntropy).unwrap().registers.is_empty());
 struct Fresh(bool);impl Machine for Fresh{fn read_register(&self,_:s::Register)->Value{panic!("full random destination read unavailable incoming state")}fn read_memory(&self,_:u64,_:u8,_:s::Endian)->Result<Value,EvalError>{panic!()}fn choose(&self,step:usize,width:u8)->Result<Value,EvalError>{Ok(Value::known(width,if step==0{u64::from(self.0)}else{0xabcdef0123456789}))}}
 for group in[6,7]{for width in[32,64]{for success in[false,true]{let d=decode(&random_bytes(group,Mode::Mode64,width,0),Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&Fresh(success)).unwrap();assert_eq!(x(&t,0),if !success{0}else if width==32{0x23456789}else{0xabcdef0123456789});assert!(t.registers.iter().all(|w|w.value.is_known()));}}}
}
#[test]fn random_choice_graph_validation_precedes_provider_and_checks_inactive_paths(){
 let r=decode(&[0x0f,0xc7,0xf8],Mode::Mode64).unwrap().semantic_recipe(0);
 let mut forward=r.clone();forward.choices[0].condition=Some(s::Expr{ty:s::Type{width:1,signedness:s::Signedness::Unsigned},kind:s::ExprKind::ChoiceResult{step:1}});
 let mut bad_width=r.clone();bad_width.choices[1].width=0;
 let mut inactive=r.clone();inactive.choices[1].condition=Some(s::Expr::select(s::Expr::constant(1,0),s::Expr{ty:s::Type{width:1,signedness:s::Signedness::Unsigned},kind:s::ExprKind::ChoiceResult{step:2}},s::Expr::constant(1,0)));
 for graph in[forward,bad_width,inactive]{let st=EntropyState::new(true,0);assert_eq!(s::evaluate(&graph,&st),Err(EvalError::InvalidExpression));assert!(st.calls.borrow().is_empty());}
}
`
