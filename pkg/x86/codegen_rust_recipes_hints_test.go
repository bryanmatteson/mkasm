package x86

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRustX86IgnoredHintRecipes(t *testing.T) {
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
	catalog, err := ParseOpcodesDB(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = GenerateRust(catalog, dir); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "hint_tests.rs"), []byte(x86IgnoredHintTests), 0644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"--edition=2021", "--crate-name", "x86_64", "--crate-type", "rlib", "src/lib.rs", "-Dwarnings", "-o", "libx86_64.rlib"}, {"--edition=2021", "--test", "hint_tests.rs", "--extern", "x86_64=libx86_64.rlib", "-Dwarnings", "-o", "hint-tests"}} {
		cmd := exec.Command("rustc", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated hints %v: %v\n%s", args, err, out)
		}
	}
	cmd := exec.Command(filepath.Join(dir, "hint-tests"), "--nocapture")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("hint behavior: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

const x86IgnoredHintTests = `
use x86_64::{decode,Mode};
use x86_64::semantics::*;
struct NoInputs;
impl Machine for NoInputs {
 fn read_register(&self,_:Register)->Value {panic!("ignored hint read architectural input")}
 fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError> {panic!("ignored hint performed memory access")}
}
fn check(bytes:&[u8],mode:Mode,name:&str) {
 let d=decode(bytes,mode).unwrap_or_else(|e|panic!("{bytes:02x?} {mode:?}: {e:?}"));assert_eq!(d.encoding().mnemonic,name,"{bytes:02x?} {mode:?}");
 for ip in [0xffff,0xffff_fffe,u64::MAX-1] {
  let recipe=d.semantic_recipe(ip);assert_eq!(recipe.support,Support::Full,"{bytes:02x?} {mode:?}");recipe.validate().unwrap();
  assert!(recipe.temporaries.is_empty()&&recipe.effects.is_empty()&&recipe.wide_loads.is_empty()&&recipe.atomics.is_empty()&&recipe.choices.is_empty());
  let result=evaluate(&recipe,&NoInputs).unwrap();assert!(result.registers.is_empty()&&result.memory.is_empty()&&result.events.is_empty());assert_eq!(result.trap,None);
  assert_eq!(result.next_pc,Value::known(if mode==Mode::Mode64{64}else{32},ip.wrapping_add(bytes.len() as u64)));
 }
}
#[test]fn pause_all_modes_is_a_finite_zero_delay_hint(){for mode in [Mode::Mode16,Mode::Mode32,Mode::Mode64]{check(&[0xf3,0x90],mode,"PAUSE")}}
#[test]fn ignored_prefixes_sib_absolute_and_ip_relative_forms_need_no_inputs(){
 for mode in [Mode::Mode16,Mode::Mode32,Mode::Mode64] {
  for prefix in [&[0x67][..],&[0x64],&[0x65],&[0x67,0x65]] {
   let mut bytes=prefix.to_vec();bytes.extend_from_slice(&[0xf3,0x90]);check(&bytes,mode,"PAUSE");
  }
  // Absolute disp16 in 16-bit addressing; disp32 absolute/IP-relative and
  // base-less SIB in 32/64-bit addressing. None may resolve a segment/base.
  if mode==Mode::Mode16 {check(&[0x0f,0x18,0x0e,0xff,0xff],mode,"PREFETCHT0");}
  else {
   check(&[0x0f,0x18,0x0d,0xff,0xff,0xff,0x7f],mode,"PREFETCHT0");
   check(&[0x65,0x0f,0x18,0x0c,0x25,0xff,0xff,0xff,0x7f],mode,"PREFETCHT0");
   check(&[0x64,0x0f,0x0d,0x4c,0xc8,0x7f],mode,"PREFETCHW");
  }
 }
 for rex in [0x40,0x44,0x48,0x4c] {check(&[0xf3,rex,0x90],Mode::Mode64,"PAUSE");}
 for rex in 0x40..=0x4f {check(&[0x65,rex,0x0f,0x18,0x0c,0xc8],Mode::Mode64,"PREFETCHT0");}
}
#[test]fn all_prefetch_addresses_and_legacy_modes_ignore_unavailable_inputs(){
 for mode in [Mode::Mode16,Mode::Mode32,Mode::Mode64] {
  for (opcode,group,name) in [(0x18,0,"PREFETCHNTA"),(0x18,1,"PREFETCHT0"),(0x18,2,"PREFETCHT1"),(0x18,3,"PREFETCHT2"),(0x0d,1,"PREFETCHW")] {
   for prefix in [&[][..],&[0x66],&[0x67],&[0x64],&[0x65],&[0x67,0x65]] {
    for rm in [0,1,3,7] {let mut bytes=prefix.to_vec();bytes.extend_from_slice(&[0x0f,opcode,(group<<3)|rm]);check(&bytes,mode,name);}
    let mut bytes=prefix.to_vec();bytes.extend_from_slice(&[0x0f,opcode,0x80|(group<<3)]);
    bytes.extend_from_slice(if (mode==Mode::Mode16 && !prefix.contains(&0x67)) || (mode==Mode::Mode32 && prefix.contains(&0x67)) {&[0xff,0x7f][..]}else{&[0xff,0xff,0xff,0x7f][..]});check(&bytes,mode,name);
   }
  }
 }
}
#[test]fn hints_do_not_claim_locked_neighbors_or_prefetchwt1(){
 for mode in [Mode::Mode16,Mode::Mode32,Mode::Mode64] {
  for bytes in [&[0xf0,0xf3,0x90][..],&[0xf3,0xf0,0x90],&[0x66,0xf0,0xf3,0x90],&[0xf0,0x0f,0x18,0],&[0x65,0xf0,0x0f,0x18,8],&[0xf0,0x0f,0x0d,8],&[0x0f,0x0d,16],&[0x0f,0x18,0xc0],&[0x0f,0x18,0xc8],&[0x0f,0x18,0xd0],&[0x0f,0x18,0xd8],&[0x0f,0x0d,0xc8]] {
   if let Ok(d)=decode(bytes,mode) {assert_ne!(d.semantic_recipe(0).support,Support::Full,"{bytes:02x?} {mode:?} {}",d.encoding().mnemonic);}
  }
 }
}
`
