package arm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/bryanmatteson/mkasm/pkg/ir"
	"github.com/bryanmatteson/mkasm/pkg/semantics"
	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

// Decode the real instruction words before consuming their generated recipes.
// Exact fixture fields intentionally do not assert any mnemonic-based semantics.
func TestRustA64ScalarRecipes(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0755); err != nil {
		t.Fatal(err)
	}
	words := []uint32{0x92001c20, 0xb24003e0, 0xaa2103e0, 0x8b224020, 0xba010000, 0xfa010000, 0xea010000, 0xf8626820, 0xf8408421, 0x17ffffff, 0x94000002, 0x72a24680, 0x2b010000, 0xab010000, 0xeb010002, 0x8b010000, 0x110003ff, 0x2a1f03e0, 0x92800000, 0xf2a24680, 0x93401c20, 0xd37ff820, 0x9ac12000, 0x9a810400, 0x54000040, 0xb4000040, 0xb6f80040, 0xd63f03c0, 0xf8408420, 0xf81f8c22, 0xb9400020, 0x39800020, 0x58000040, 0x10000040, 0xd503201f, 0xd4000001, 0x4e208400, 0xc85f7c20, 0x91910b1a, 0xd1910b1a}
	var instructions []*ir.InstructionIR
	for _, word := range words {
		v := uint64(word)
		instructions = append(instructions, &ir.InstructionIR{EncodingID: fmt.Sprintf("word_%08x", word), Mnemonic: "fixture", BitPattern: fmt.Sprintf("%032b", word), Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{{Name: "word", Start: 0, End: 31, Fixed: &v}}}})
	}
	data, err := buildRustDecoderData(BuildCatalog(instructions))
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("rust").ParseFS(assettemplates.FS, "rust/decoders.rs.tmpl", "rust/recipes.rs.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	if err := execTmplWrite(tmpl, "decoders.rs.tmpl", filepath.Join(src, "decoders.rs"), data); err != nil {
		t.Fatal(err)
	}
	if err := execTmplWrite(tmpl, "recipes.rs.tmpl", filepath.Join(src, "recipes.rs"), nil); err != nil {
		t.Fatal(err)
	}
	if err := semantics.WriteRust(src); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{"Cargo.toml": "[package]\nname=\"recipe_test\"\nversion=\"0.1.0\"\nedition=\"2021\"\n", "src/lib.rs": "#![allow(dead_code)]\npub mod semantics;pub mod recipes;mod decoders;pub use decoders::Decoded;\n" + a64RecipeTests} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("cargo", "test", "--lib", "--quiet")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-Dwarnings")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("A64 recipes: %v\n%s", err, out)
	}
}

const a64RecipeTests = `
#[cfg(test)]mod recipe_tests{
 use super::*;use semantics::*;use std::collections::HashMap;
 #[derive(Default)]struct State{regs:HashMap<Register,u64>,mem:HashMap<u64,u64>}
 impl State{fn reg(&mut self,bank:&'static str,n:u16,v:u64){self.regs.insert(Register{bank,index:n},v);}fn x(&mut self,n:u16,v:u64){self.reg("a64.gpr",n,v)}}
 impl Machine for State{fn read_register(&self,r:Register)->Value{Value::known(64,*self.regs.get(&r).unwrap_or(&0))}fn read_memory(&self,a:u64,w:u8,_:Endian)->Result<Value,EvalError>{self.mem.get(&a).map(|v|Value::known(w,*v)).ok_or(EvalError::Memory)}}
 fn run(word:u32,s:&State)->Transition{let d=decoders::decode(word).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{word:08x}");evaluate(&r,s).unwrap()}
 fn reg(t:&Transition,bank:&str,n:u16)->Value{t.registers.iter().rev().find(|v|v.register.bank==bank&&v.register.index==n).unwrap().value}
 fn x(t:&Transition,n:u16)->u64{reg(t,"a64.gpr",n).bits}
 fn flag(t:&Transition,n:u16)->u64{reg(t,"a64.nzcv",n).bits}
 #[test]fn add_sub_alias_and_flags(){let mut s=State::default();s.x(0,0x7fffffffffffffff);s.x(1,1);let t=run(0xab010000,&s);assert_eq!(x(&t,0),0x8000000000000000);assert_eq!([flag(&t,0),flag(&t,1),flag(&t,2),flag(&t,3)],[1,0,0,1]);s.x(0,u64::MAX);let t=run(0xab010000,&s);assert_eq!(x(&t,0),0);assert_eq!(flag(&t,2),1);s.x(0,0);let t=run(0xeb010002,&s);assert_eq!(x(&t,2),u64::MAX);assert_eq!(flag(&t,2),0);assert_eq!(flag(&t,3),0)}
 #[test]fn stack_zero_register_and_zero_upper(){let mut s=State::default();s.reg("a64.sp",0,0xffffffff00000009);let t=run(0x110003ff,&s);assert_eq!(reg(&t,"a64.sp",0),Value::known(64,9));s.x(0,u64::MAX);let t=run(0x2a1f03e0,&s);assert_eq!(x(&t,0),0)}
 #[test]fn constant_construction_extensions_and_shifts(){let mut s=State::default();assert_eq!(x(&run(0x92800000,&s),0),u64::MAX);s.x(0,u64::MAX);assert_eq!(x(&run(0xf2a24680,&s),0),0xffffffff1234ffff);s.x(1,0x80);assert_eq!(x(&run(0x93401c20,&s),0),0xffffffffffffff80);s.x(1,3);assert_eq!(x(&run(0xd37ff820,&s),0),6);s.x(0,9);s.x(1,64);assert_eq!(x(&run(0x9ac12000,&s),0),9)}
 #[test]fn conditions_and_link_target_snapshot(){let mut s=State::default();s.x(0,7);s.x(1,11);s.reg("a64.nzcv",1,0);assert_eq!(x(&run(0x9a810400,&s),0),12);s.reg("a64.nzcv",1,1);assert_eq!(x(&run(0x9a810400,&s),0),7);assert_eq!(run(0x54000040,&s).next_pc.bits,0x1008);s.reg("a64.nzcv",1,0);assert_eq!(run(0x54000040,&s).next_pc.bits,0x1004);s.x(0,0);assert_eq!(run(0xb4000040,&s).next_pc.bits,0x1008);s.x(0,1<<63);assert_eq!(run(0xb6f80040,&s).next_pc.bits,0x1004);s.x(30,0x2222);let t=run(0xd63f03c0,&s);assert_eq!(t.next_pc.bits,0x2222);assert_eq!(x(&t,30),0x1004)}
 #[test]fn scalar_memory_and_writeback_are_snapshotted(){let mut s=State::default();s.x(1,0x2000);s.x(2,0xabcdef);s.mem.insert(0x2000,0x7654);let t=run(0xf8408420,&s);assert_eq!(x(&t,0),0x7654);assert_eq!(x(&t,1),0x2008);let t=run(0xf81f8c22,&s);assert_eq!(t.memory[0].address,0x1ff8);assert_eq!(t.memory[0].value.bits,0xabcdef);assert_eq!(x(&t,1),0x1ff8);s.mem.insert(0x2000,0x80000000);assert_eq!(x(&run(0xb9400020,&s),0),0x80000000);s.mem.insert(0x2000,0x80);assert_eq!(x(&run(0x39800020,&s),0),0xffffffffffffff80);s.mem.insert(0x1008,0x5555);assert_eq!(x(&run(0x58000040,&s),0),0x5555);assert_eq!(x(&run(0x10000040,&s),0),0x1008)}
 #[test]fn logical_extended_carry_and_address_families(){let mut s=State::default();s.x(1,0x12345678);assert_eq!(x(&run(0x92001c20,&s),0),0x78);assert_eq!(x(&run(0xb24003e0,&s),0),1);assert_eq!(x(&run(0xaa2103e0,&s),0),!0x12345678u64);s.x(2,0xffffffff00000005);assert_eq!(x(&run(0x8b224020,&s),0),0x1234567d);s.x(0,u64::MAX);s.x(1,0);s.reg("a64.nzcv",2,1);let t=run(0xba010000,&s);assert_eq!(x(&t,0),0);assert_eq!(flag(&t,2),1);s.x(0,0);s.reg("a64.nzcv",2,0);let t=run(0xfa010000,&s);assert_eq!(x(&t,0),u64::MAX);assert_eq!(flag(&t,2),0);s.x(0,0xffffffff);s.x(1,1);let t=run(0x2b010000,&s);assert_eq!(x(&t,0),0);assert_eq!(flag(&t,2),1);s.x(0,u64::MAX);assert_eq!(x(&run(0x72a24680,&s),0),0x1234ffff);s.x(1,0x2000);s.x(2,16);s.mem.insert(0x2010,42);assert_eq!(x(&run(0xf8626820,&s),0),42);assert_eq!(run(0x17ffffff,&s).next_pc.bits,0xffc);let t=run(0x94000002,&s);assert_eq!(t.next_pc.bits,0x1008);assert_eq!(x(&t,30),0x1004);assert!(matches!(decoders::decode(0xf8408421).unwrap().semantic_recipe(0).support,Support::Unsupported(_)))}
 #[test]fn exclusive_load_keeps_its_native_capability_boundary(){let r=decoders::decode(0xc85f7c20).unwrap().semantic_recipe(0);assert_eq!(r.support,Support::Full);r.validate().unwrap();assert_eq!(r.atomics.len(),1);assert!(matches!(&r.atomics[0],AtomicStep::Memory(AtomicOperation{kind:AtomicOperationKind::LoadLinked,..})));assert_eq!(evaluate(&r,&State::default()),Err(EvalError::Unsupported));}
 #[test]fn unmodeled_supervisor_call_is_explicitly_unsupported(){for word in [0xd4000001]{let r=decoders::decode(word).unwrap().semantic_recipe(0);assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x} {:?}",r.support);assert_eq!(evaluate(&r,&State::default()),Err(EvalError::Unsupported))}}
 #[test]fn vector_add_wraps_each_byte_lane(){let mut s=State::default();s.reg("a64.vector64",0,0x00ff807fff01027f);s.reg("a64.vector64",1,0x0101010101010101);let t=run(0x4e208400,&s);assert_eq!(reg(&t,"a64.vector64",0).bits,0x00fe00fefe0204fe);assert_eq!(reg(&t,"a64.vector64",1).bits,0x0202020202020202);}
 #[test]fn tagged_add_sub_follow_the_explicit_disabled_mte_context(){let mut s=State::default();s.x(24,0x2000);s.reg("a64.mte_enabled",0,0);assert_eq!(x(&run(0x91910b1a,&s),26),0x2110);assert_eq!(x(&run(0xd1910b1a,&s),26),0x1ef0);}
}
`

func TestRustA32ScalarRecipes(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.Mkdir(src, 0755); err != nil {
		t.Fatal(err)
	}
	words := []uint32{0xe2900001, 0xe2b00000, 0xe2d00000, 0xe3b00102, 0xe3b00000, 0x02900001, 0x0b000000, 0xe28f0004, 0xe3a0f000, 0xef000000, 0xe3000001, 0xe3400001, 0xe328f001, 0xe321f001, 0xe320f000, 0xfa000000, 0xe25ef004, 0xe1200070, 0xe1400070, 0xe1600070, 0xf8100a00}
	var instructions []*ir.InstructionIR
	for _, word := range words {
		v := uint64(word)
		instructions = append(instructions, &ir.InstructionIR{EncodingID: fmt.Sprintf("word_%08x", word), Mnemonic: "fixture", BitPattern: fmt.Sprintf("%032b", word), Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{{Name: "word", Start: 0, End: 31, Fixed: &v}}}})
	}
	data, err := buildRustDecoderData(BuildCatalog(instructions))
	if err != nil {
		t.Fatal(err)
	}
	tmpl, err := template.New("arm32").ParseFS(assettemplates.FS, "rust/decoders.rs.tmpl", "arm32_rust/recipes.rs.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	if err := execTmplWrite(tmpl, "decoders.rs.tmpl", filepath.Join(src, "a32.rs"), data); err != nil {
		t.Fatal(err)
	}
	if err := execTmplWrite(tmpl, "recipes.rs.tmpl", filepath.Join(src, "recipes.rs"), nil); err != nil {
		t.Fatal(err)
	}
	if err := semantics.WriteRust(src); err != nil {
		t.Fatal(err)
	}
	// The real ARM32 wrapper exposes the same mode/length/raw boundary; keep
	// this fixture focused on decoder-to-recipe integration, without print forms.
	wrapper := `#![allow(dead_code)]
 pub mod semantics;pub mod recipes;mod a32;
 #[derive(PartialEq,Eq)]pub enum Mode{Arm,Thumb}
 pub struct Decoded{raw:u32,pub mode:Mode,pub length:usize}
 impl Decoded{pub fn raw(&self)->u32{self.raw}}
 fn decode(word:u32)->Decoded{Decoded{raw:a32::decode(word).unwrap().raw,mode:Mode::Arm,length:4}}
 `
	for path, body := range map[string]string{"Cargo.toml": "[package]\nname=\"recipe_a32_test\"\nversion=\"0.1.0\"\nedition=\"2021\"\n", "src/lib.rs": wrapper + a32RecipeTests} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("cargo", "test", "--lib", "--quiet")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-Dwarnings")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("A32 recipes: %v\n%s", err, out)
	}
}

const a32RecipeTests = `
#[cfg(test)]mod recipe_tests{
 use super::*;use semantics::*;use std::collections::HashMap;
 #[derive(Default)]struct State{regs:HashMap<Register,u64>}
 impl State{fn reg(&mut self,bank:&'static str,n:u16,v:u64){self.regs.insert(Register{bank,index:n},v);}}
 impl Machine for State{fn read_register(&self,r:Register)->Value{Value::known(32,*self.regs.get(&r).unwrap_or(&0))}fn read_memory(&self,_:u64,_:u8,_:Endian)->Result<Value,EvalError>{Err(EvalError::Memory)}}
 fn run(word:u32,s:&State)->Transition{let r=decode(word).semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);evaluate(&r,s).unwrap()}
 fn reg(t:&Transition,bank:&str,n:u16)->u64{t.registers.iter().rev().find(|v|v.register.bank==bank&&v.register.index==n).unwrap().value.bits}
 #[test]fn arithmetic_and_predication(){let mut s=State::default();s.reg("a32.gpr",0,0x7fffffff);let t=run(0xe2900001,&s);assert_eq!(reg(&t,"a32.gpr",0),0x80000000);assert_eq!(reg(&t,"a32.nzcv",3),1);assert_eq!(reg(&t,"a32.nzcv",2),0);s.reg("a32.gpr",0,u32::MAX as u64);s.reg("a32.nzcv",2,1);let t=run(0xe2b00000,&s);assert_eq!(reg(&t,"a32.gpr",0),0);assert_eq!(reg(&t,"a32.nzcv",2),1);s.reg("a32.gpr",0,0);s.reg("a32.nzcv",2,0);let t=run(0xe2d00000,&s);assert_eq!(reg(&t,"a32.gpr",0),u32::MAX as u64);assert_eq!(reg(&t,"a32.nzcv",2),0);assert!(run(0x02900001,&s).registers.is_empty());s.reg("a32.nzcv",1,1);assert_eq!(reg(&run(0x02900001,&s),"a32.gpr",0),1)}
 #[test]fn rotated_immediate_carry_and_preserved_flags(){let s=State::default();let t=run(0xe3b00102,&s);assert_eq!(reg(&t,"a32.gpr",0),0x80000000);assert_eq!(reg(&t,"a32.nzcv",2),1);assert!(t.registers.iter().all(|r|r.register.bank!="a32.nzcv"||r.register.index!=3));let t=run(0xe3b00000,&s);assert_eq!(reg(&t,"a32.nzcv",2),0)}
 #[test]fn architectural_pc_and_branch_link(){let mut s=State::default();assert_eq!(reg(&run(0xe28f0004,&s),"a32.gpr",0),0x100c);s.reg("a32.nzcv",1,1);let t=run(0x0b000000,&s);assert_eq!(t.next_pc.bits,0x1008);assert_eq!(reg(&t,"a32.gpr",14),0x1004)}
 #[test]fn immediate_class_overlaps_and_exception_forms_stay_unsupported(){for word in[0xe321f001,0xe320f000,0xe25ef004,0xe1400070,0xe1600070,0xf8100a00]{let r=decode(word).semantic_recipe(0x1000);assert!(matches!(r.support,Support::Unsupported(_)),"{word:08x}");assert!(r.effects.is_empty())}}
 #[test]fn apsr_immediate_write_uses_system_flags_without_scalar_side_effects(){let mut s=State::default();for index in 0..4{s.reg("a32.nzcv",index,1);}s.reg("a32.q",0,1);s.reg("a32.gpr",0,0xdeadbeef);let t=run(0xe328f001,&s);for index in 0..4{assert_eq!(reg(&t,"a32.nzcv",index),0);}assert_eq!(reg(&t,"a32.q",0),0);assert_eq!(t.next_pc.bits,0x1004);assert!(t.registers.iter().all(|r|matches!(r.register.bank,"a32.nzcv"|"a32.q")));}
 #[test]fn constant_construction_pc_write_and_unhandled_system(){let mut s=State::default();s.reg("a32.gpr",0,0xabcd1234);assert_eq!(reg(&run(0xe3000001,&s),"a32.gpr",0),1);assert_eq!(reg(&run(0xe3400001,&s),"a32.gpr",0),0x00011234);assert_eq!(run(0xe3a0f000,&s).next_pc.bits,0);assert_eq!(reg(&run(0xfa000000,&s),"a32.thumb_state",0),1);assert!(matches!(decode(0xef000000).semantic_recipe(0).support,Support::Unsupported(_)))}
}
`
