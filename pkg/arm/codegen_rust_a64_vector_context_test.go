package arm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Exercise the production generated decoder with different CurrentVL/SVL in the
// same recipe context. Nonstreaming ZA accesses must retain SVL, not CurrentVL.
func TestRustA64IndependentVectorContexts(t *testing.T) {
	path := os.Getenv("MKASM_A64_RECIPES_CORPUS")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		path = filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("June primary A64 corpus unavailable")
	}
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	corpus, err := OpenTarXMLCorpus(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	parser := NewARMParser(ARMParserConfig{EncodingIndexPath: ArchAArch64.SpecIndexFile(), Corpus: corpus, OutputDirectory: dir, Arch: ArchAArch64, Languages: []CodegenLang{LangRust}})
	defer func() {
		if err := parser.Close(5 * time.Second); err != nil {
			t.Error(err)
		}
	}()
	if err := parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contexts.rs"), []byte(a64IndependentVectorContexts), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"rustc", "--edition=2021", "--crate-name", "aarch64", "--crate-type", "lib", "src/lib.rs", "-o", "libaarch64.rlib"},
		{"rustc", "--edition=2021", "--test", "contexts.rs", "--extern", "aarch64=libaarch64.rlib", "-Dwarnings", "-Copt-level=1", "-o", "contexts-tests"},
		{filepath.Join(dir, "contexts-tests")},
	} {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated independent contexts %v: %v\n%s", args, err, out)
		} else {
			t.Log(string(out))
		}
	}
}

const a64IndependentVectorContexts = `
use aarch64::{decode,recipes::RecipeContext,semantics::*};
use std::cell::RefCell;
const LENGTHS:[u16;5]=[128,256,512,1024,2048];
struct State { sm:bool, svl:u16, reads:RefCell<Vec<(u64,u8,Endian)>>, inputs:RefCell<Vec<Register>> }
impl Machine for State {
 fn read_register(&self,r:Register)->Value{
  self.inputs.borrow_mut().push(r);
  let (width,bits)=match r.bank {
   "a64.svcr" => (2,2|u64::from(self.sm)),
   "a64.gpr" => (64,match r.index{2=>0x4000,12=>u64::from(self.svl/8-1),_=>panic!("unexpected GPR {r:?}")}),
   "a64.predicate64" => (64,u64::MAX),
   "a64.vector64" | "a64.za64" => (64,0xa5a5a5a5a5a5a5a5),
   _ => panic!("unexpected register {r:?}"),
  }; Value::known(width,bits)
 }
 fn read_memory(&self,a:u64,w:u8,e:Endian)->Result<Value,EvalError>{
  assert_eq!(w,8);self.reads.borrow_mut().push((a,w,e));Ok(Value::known(8,a&255))
 }
}
fn recipe(word:u32,vl:u16,svl:Option<u16>,endian:Endian)->Recipe{
 decode(word).unwrap().semantic_recipe_with_context(0x1000,RecipeContext{vector_length:vl,streaming_vector_length:svl,endian})
}
#[test] fn sve_uses_current_vl_and_nonstreaming_za_uses_independent_svl(){
 for vl in LENGTHS {for svl in LENGTHS {for sm in [false,true] {for endian in [Endian::Little,Endian::Big] {
  let s=State{sm,svl,reads:RefCell::new(vec![]),inputs:RefCell::new(vec![])};
  // LD2B {Z0.B,Z1.B},P0/Z,[X2]: element/member order at CurrentVL.
  let r=recipe(0xa420e040,vl,Some(svl),endian);assert_eq!(r.support,Support::Full);evaluate(&r,&s).unwrap();
  assert_eq!(*s.reads.borrow(),(0..2*u64::from(vl/8)).map(|i|(0x4000+i,8,endian)).collect::<Vec<_>>());
  s.reads.borrow_mut().clear();s.inputs.borrow_mut().clear();
  // LDR ZA[W12,#0],[X2]: legal with SM=0,ZA=1; byte transfers use SVL.
  let r=recipe(0xe1000040,vl,Some(svl),endian);assert_eq!(r.support,Support::Full);let t=evaluate(&r,&s).unwrap();
  assert_eq!(*s.reads.borrow(),(0..u64::from(svl/8)).map(|i|(0x4000+i,8,Endian::Little)).collect::<Vec<_>>());
  let row=svl/8-1;let value=t.registers.iter().find(|w|w.register.bank=="a64.za64"&&w.register.index==row*32).unwrap().value;
  assert_eq!(value,Value::known(64,0x0706050403020100));
 }}}}
}
#[test] fn sme_bfloat_dispatch_uses_svl_independently_of_current_vl(){
 // Six June SME2 BFloat class witnesses; compare the whole typed graph, so
 // register groups, active lanes, and accumulator slices all use SVL.
 for word in [0xc1501018,0xc1509018,0xc1201010,0xc1301010,0xc1a01010,0xc1a11010] {
  let expected=recipe(word,128,Some(128),Endian::Little);assert_eq!(expected.support,Support::Full);
  assert_eq!(recipe(word,2048,Some(128),Endian::Little),expected);
 }
}
#[test] fn omitted_svl_means_current_vl_and_both_context_lengths_validate_before_inputs(){
 for vl in LENGTHS {
  let default=RecipeContext{vector_length:vl,..RecipeContext::default()};assert!(default.valid());assert_eq!(default.streaming_vector_length(),vl);
  for word in [0xa420e040,0xe1000040,0x04bf5820] {
   assert_eq!(recipe(word,vl,None,Endian::Little),recipe(word,vl,Some(vl),Endian::Little));
  }
 }
 for bad in [0,64,192,384,4096] {for (vl,svl) in [(128,Some(bad)),(bad,Some(128)),(bad,None)] {
  let s=State{sm:false,svl:128,reads:RefCell::new(vec![]),inputs:RefCell::new(vec![])};
  for word in [0xa420e040,0xe1000040,0xd503477f] {
   let r=recipe(word,vl,svl,Endian::Big);assert!(matches!(r.support,Support::Unsupported(_)));assert!(evaluate(&r,&s).is_err());
  }
  assert!(s.inputs.borrow().is_empty());assert!(s.reads.borrow().is_empty());
 }}
}
`
