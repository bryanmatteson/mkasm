package x86

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func recipeCatalog() *Catalog {
	c := codecCatalog()
	c.Encodings = append(c.Encodings, Encoding{ID: "JNE8", FormID: "JNE8/recipe", Mnemonic: "JNE", Kind: EncodingLegacy, Opcode: 0x75, Modes: modeAll, W: BitAny, Tail: []TailWidth{Tail8}, Operands: []Operand{{Type: "REL", Symbol: "REL", EncodedIn: "RB"}}})
	scalar := func(id, mnemonic string, opcode byte, reg uint8, operands []Operand, tail ...TailWidth) Encoding {
		return Encoding{ID: id, FormID: id + "/recipe", Mnemonic: mnemonic, Kind: EncodingLegacy, Opcode: opcode, Modes: modeAll, W: BitAny, HasModRM: true, Mod: ModRegister, RegMask: 7, RegValue: reg, Tail: tail, Operands: operands}
	}
	gpr := func(enc, symbol string) Operand {
		return Operand{Type: "REG", Symbol: symbol, EncodedIn: enc, Read: true, Write: true}
	}
	for _, op := range []struct {
		id, mnemonic string
		opcode       byte
		reg          uint8
	}{{"ADD8imm", "ADD", 0x80, 0}, {"ADC8imm", "ADC", 0x80, 2}, {"SBB8imm", "SBB", 0x80, 3}, {"SUB8imm", "SUB", 0x80, 5}, {"CMP8imm", "CMP", 0x80, 7}} {
		c.Encodings = append(c.Encodings, scalar(op.id, op.mnemonic, op.opcode, op.reg, []Operand{gpr("RM", "GPR8"), {Type: "IMM", EncodedIn: "IB"}}, Tail8))
	}
	for _, op := range []struct {
		id, name string
		reg      uint8
	}{{"SHLcl", "SHL", 4}, {"SHRcl", "SHR", 5}, {"SARcl", "SAR", 7}} {
		c.Encodings = append(c.Encodings, scalar(op.id, op.name, 0xd3, op.reg, []Operand{gpr("RM", "GPRv"), {Type: "REG", Value: "CL", Read: true}}))
	}
	for _, op := range []struct {
		id, name string
		reg      uint8
	}{{"SHL8cl", "SHL", 4}, {"SHR8cl", "SHR", 5}, {"SAR8cl", "SAR", 7}, {"ROL8cl", "ROL", 0}, {"ROR8cl", "ROR", 1}} {
		c.Encodings = append(c.Encodings, scalar(op.id, op.name, 0xd2, op.reg, []Operand{gpr("RM", "GPR8"), {Type: "REG", Value: "CL", Read: true}}))
	}
	for _, op := range []struct {
		id, name string
		opcode   byte
		operands []Operand
	}{{"MOV8", "MOV", 0x88, []Operand{gpr("RM", "GPR8"), gpr("REG", "GPR8")}}, {"XCHG64", "XCHG", 0x87, []Operand{gpr("RM", "GPRv"), gpr("REG", "GPRv")}}} {
		e := scalar(op.id, op.name, op.opcode, 0, op.operands)
		e.RegMask = 0
		c.Encodings = append(c.Encodings, e)
	}
	for _, op := range []struct {
		id, name string
		opcode   byte
		source   Operand
	}{{"MOVSX8", "MOVSX", 0xbe, gpr("RM", "GPR8")}, {"CMOVE64", "CMOVE", 0x44, gpr("RM", "GPRv")}} {
		e := scalar(op.id, op.name, op.opcode, 0, []Operand{gpr("REG", "GPRv"), op.source})
		e.RegMask = 0
		e.Map = Map0F
		c.Encodings = append(c.Encodings, e)
	}
	for _, op := range []struct {
		id, name string
		opcode   byte
		size     string
	}{{"MOVload", "MOV", 0x8b, "SZ_V"}, {"LEA", "LEA", 0x8d, ""}} {
		e := scalar(op.id, op.name, op.opcode, 0, []Operand{gpr("REG", "GPRv"), {Type: "MEM", EncodedIn: "RM", Size: op.size, Read: true}})
		e.RegMask = 0
		e.Mod = ModMemory
		c.Encodings = append(c.Encodings, e)
	}
	c.Encodings = append(c.Encodings, scalar("CALLrax", "CALL", 0xff, 2, []Operand{gpr("RM", "GPR64")}))
	c.Encodings = append(c.Encodings, Encoding{ID: "POPr64", FormID: "POPr64/recipe", Mnemonic: "POP", Kind: EncodingLegacy, Opcode: 0x58, OpcodePlusReg: true, Modes: mode64, W: BitAny, Operands: []Operand{gpr("OPCODE", "GPR64")}})
	c.Encodings = append(c.Encodings, Encoding{ID: "RET", FormID: "RET/recipe", Mnemonic: "RET", Kind: EncodingLegacy, Opcode: 0xc3, Modes: modeAll, W: BitAny})
	c.Encodings = append(c.Encodings, Encoding{ID: "RETfar", FormID: "RETfar/recipe", Mnemonic: "RET", Kind: EncodingLegacy, Opcode: 0xcb, Modes: mode64, W: BitAny})
	extraState := scalar("ADDhiddenControl", "ADD", 0x03, 0, []Operand{gpr("REG", "GPR64"), gpr("RM", "GPR64"), {Type: "REG", Symbol: "CREG", EncodedIn: "REG", Read: true, Write: true, Suppressed: true}})
	extraState.RegMask = 0
	extraState.W = BitOne
	c.Encodings = append(c.Encodings, extraState)
	c.Encodings = append(c.Encodings, Encoding{ID: "PUSHhiddenExtra", FormID: "PUSHhiddenExtra/recipe", Mnemonic: "PUSH", Kind: EncodingLegacy, Opcode: 0x6a, Modes: mode64, W: BitAny, Tail: []TailWidth{Tail8}, Operands: []Operand{{Type: "IMM", EncodedIn: "IB", DataType: "S8"}, {Type: "REG", Value: "RAX", Write: true, Suppressed: true}}})
	return c
}
func TestRustX86ScalarRecipes(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	dir := t.TempDir()
	if err := GenerateRust(recipeCatalog(), dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "recipes.rs"), []byte(x86RecipeTests+x86ExtraImplicitTests), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "recipes", "--quiet")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-Dwarnings")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("x86 recipes: %v\n%s", err, out)
	}
}

const x86RecipeTests = `
use x86_64::*;use x86_64::semantics::{self as s,Machine,Value,EvalError,Support,Transition};use std::collections::HashMap;
#[derive(Default)]struct State{regs:HashMap<s::Register,u64>,mem:HashMap<u64,u64>}
impl State{fn reg(&mut self,bank:&'static str,n:u16,v:u64){self.regs.insert(s::Register{bank,index:n},v);}fn x(&mut self,n:u16,v:u64){self.reg("x86.gpr",n,v)}}
impl Machine for State{fn read_register(&self,r:s::Register)->Value{Value::known(64,*self.regs.get(&r).unwrap_or(&0))}fn read_memory(&self,a:u64,w:u8,_:s::Endian)->Result<Value,EvalError>{self.mem.get(&a).map(|v|Value::known(w,*v)).ok_or(EvalError::Memory)}}
fn run(bytes:&[u8],state:&State)->Transition{let d=decode(bytes,Mode::Mode64).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full,"{bytes:02x?}");s::evaluate(&r,state).unwrap()}
fn reg(t:&Transition,bank:&str,n:u16)->Value{t.registers.iter().rev().find(|v|v.register.bank==bank&&v.register.index==n).unwrap().value}
fn x(t:&Transition,n:u16)->u64{reg(t,"x86.gpr",n).bits}
fn flag(t:&Transition,n:u16)->Value{reg(t,"x86.flags",n)}
#[test]fn add_alias_overflow_carry_and_borrow(){let mut st=State::default();st.x(0,0x7fffffffffffffff);st.x(1,1);let t=run(&[0x48,0x01,0xc8],&st);assert_eq!(x(&t,0),0x8000000000000000);assert_eq!(flag(&t,5).bits,1);assert_eq!(flag(&t,0).bits,0);st.x(0,9);assert_eq!(x(&run(&[0x48,0x01,0xc0],&st),0),18);st.x(0,0xff);let t=run(&[0x80,0xc0,1],&st);assert_eq!(x(&t,0),0);assert_eq!(flag(&t,0).bits,1);assert_eq!(flag(&t,2).bits,1);st.reg("x86.flags",0,1);st.x(0,0x7f);let t=run(&[0x80,0xd0,0],&st);assert_eq!(x(&t,0),0x80);assert_eq!(flag(&t,5).bits,1);st.x(0,0);let t=run(&[0x80,0xd8,0],&st);assert_eq!(x(&t,0),0xff);assert_eq!(flag(&t,0).bits,1)}
#[test]fn zero_upper_high_byte_and_undefined_flags(){let mut st=State::default();st.x(0,u64::MAX);let t=run(&[0x31,0xc0],&st);assert_eq!(x(&t,0),0);assert_eq!(flag(&t,2).defined,0);assert_eq!(flag(&t,0),Value::known(1,0));st.x(0,0x123456789abc0011);let t=run(&[0x88,0xc4],&st);assert_eq!(x(&t,0),0x123456789abc1111);st.x(1,0x80);assert_eq!(x(&run(&[0x48,0x0f,0xbe,0xc1],&st),0),0xffffffffffffff80)}
#[test]fn masked_zero_and_wide_shift_counts(){let mut st=State::default();st.x(0,0x80000001);st.x(1,32);for i in 0..6{st.reg("x86.flags",i,1)}let t=run(&[0xd3,0xe0],&st);assert_eq!(x(&t,0),0x80000001);for i in 0..6{assert_eq!(flag(&t,i),Value::known(1,1))}st.x(1,1);let t=run(&[0xd3,0xe0],&st);assert_eq!(x(&t,0),2);assert_eq!(flag(&t,0).bits,1);assert_eq!(flag(&t,5).bits,1);assert_eq!(flag(&t,2).defined,0);st.x(0,0x81);st.x(1,8);let t=run(&[0xd2,0xe0],&st);assert_eq!(x(&t,0),0);assert_eq!(flag(&t,0).defined,0);assert_eq!(flag(&t,5).defined,0);let t=run(&[0xd2,0xf8],&st);assert_eq!(x(&t,0),0xff);assert_eq!(flag(&t,0).bits,1);st.reg("x86.flags",0,0);let t=run(&[0xd2,0xc0],&st);assert_eq!(x(&t,0),0x81);assert_eq!(flag(&t,0).bits,1);st.x(1,9);let t=run(&[0xd2,0xc0],&st);assert_eq!(x(&t,0),3);assert_eq!(flag(&t,5).defined,0)}
#[test]fn memory_effective_addresses_and_read_modify_write_snapshot(){let mut st=State::default();st.x(4,0x2000);st.x(1,3);st.mem.insert(0x2008,7);let t=run(&[0x48,0x01,0x4c,0x24,8],&st);assert_eq!(t.memory[0].address,0x2008);assert_eq!(t.memory[0].value.bits,10);st.mem.insert(0x100f,0x1234);assert_eq!(x(&run(&[0x48,0x8b,0x05,8,0,0,0],&st),0),0x1234);st.reg("x86.segment_base",4,0x4000);st.x(0,0x20);st.mem.insert(0x4020,0x9876);assert_eq!(x(&run(&[0x64,0x48,0x8b,0x00],&st),0),0x9876);st.x(0,u64::MAX);let t=run(&[0x67,0x48,0x8d,0x40,2],&st);assert_eq!(x(&t,0),1)}
#[test]fn conditional_selection_branch_and_control_target_snapshot(){let mut st=State::default();st.x(0,7);st.x(1,11);assert_eq!(x(&run(&[0x48,0x0f,0x44,0xc1],&st),0),7);st.x(0,0xffffffff00000007);assert_eq!(x(&run(&[0x0f,0x44,0xc1],&st),0),7);st.x(0,7);st.reg("x86.flags",3,1);assert_eq!(x(&run(&[0x48,0x0f,0x44,0xc1],&st),0),11);assert_eq!(run(&[0x75,2],&st).next_pc.bits,0x1002);st.reg("x86.flags",3,0);assert_eq!(run(&[0x75,2],&st).next_pc.bits,0x1004);let t=run(&[0x48,0x87,0xc8],&st);assert_eq!(x(&t,0),11);assert_eq!(x(&t,1),7);st.x(0,0x5555);st.x(4,0x3000);let t=run(&[0xff,0xd0],&st);assert_eq!(t.next_pc.bits,0x5555);assert_eq!(x(&t,4),0x2ff8);assert_eq!(t.memory[0].value.bits,0x1002);st.mem.insert(0x3000,0x4444);let t=run(&[0xc3],&st);assert_eq!(t.next_pc.bits,0x4444);assert_eq!(x(&t,4),0x3008);st.mem.insert(0x3000,0x1234);assert_eq!(x(&run(&[0x5c],&st),4),0x1234)}
#[test]fn unimplemented_operand_forms_are_unsupported(){for bytes in [&[0x66,0x50][..]]{let d=decode(bytes,Mode::Mode64).unwrap();assert!(matches!(d.semantic_recipe(0).support,Support::Unsupported(_)),"{bytes:02x?}")}let d=decode(&[0x8b,0x00],Mode::Mode32).unwrap();assert_eq!(d.semantic_recipe(0).support,Support::Full)}
`

// This integration uses the complete source corpus rather than simplified
// fixtures, so genuinely implicit stack operands participate in admission.
func TestRustX86RecipeCorpusBoundaries(t *testing.T) {
	path := os.Getenv("MKASM_X86_OPCODESDB")
	if path == "" {
		t.Skip("set MKASM_X86_OPCODESDB for complete-corpus recipe admission checks")
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	var data []byte
	var err error
	if strings.HasSuffix(path, ".xz") {
		data, err = exec.Command("xz", "-dc", path).Output()
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := ParseOpcodesDB(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if report, err := SupplementXEDFP16(catalog); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("XED: imported %d, excluded %d", report.Imported, len(report.Excluded))
	}
	if report, err := SupplementXEDInteger(catalog); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("XED integer: imported %d, unrelated source classes %d", report.Imported, report.OtherClasses)
	}
	dir := t.TempDir()
	if err := GenerateRust(catalog, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	// Reuse independently specified scalar machine-state outcomes, then add
	// complete-corpus stack and dispatch boundary cases.
	// Bind this category to the catalog's physical prefix families. MMX and
	// MVEX share mnemonics with SSE/AVX, but have separate state contracts.
	var rearrangeForms strings.Builder
	rearrangeForms.WriteString("const SSE_AVX_FORMS: &[&str] = &[\n")
	for _, encoding := range catalog.Encodings {
		if encoding.Kind <= EncodingEVEX {
			fmt.Fprintf(&rearrangeForms, "%q,\n", encoding.FormID)
		}
	}
	rearrangeForms.WriteString("];\n")
	if err := os.WriteFile(filepath.Join(dir, "tests", "recipes.rs"), []byte(x86RecipeTests+x86CorpusBoundaryTests+x86ExpandedRecipeTests+x86MaskedMemoryTests+x86HalfRecipeTests+x86BfloatRecipeTests+x86FP16RecipeTests+x86Avx512IntegerRecipeTests+x86XEDIntegerRecipeTests+x86RearrangeRecipeTests+x86VariableShiftRecipeTests+x86MaskCompareRecipeTests+x86BMIRecipeTests+x86MigratedRecipeTests+x86IntegerMigrationRecipeTests+x86MovementMigrationRecipeTests+rearrangeForms.String()), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "recipes", "--quiet", "--", "--nocapture")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-Dwarnings")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("complete-corpus x86 recipes (%d forms): %v\n%s", len(catalog.Encodings), err, out)
	}
	t.Logf("%s", out)
	t.Logf("validated real decoded bytes with %d source forms", len(catalog.Encodings))
}

const x86CorpusBoundaryTests = `
#[test]fn xor_zero_idiom_is_independent_of_unknown_registers(){
 struct Unknown;
 impl Machine for Unknown {
  fn read_register(&self,_:s::Register)->Value{Value::unknown(64)}
  fn read_memory(&self,_:u64,_:u8,_:s::Endian)->Result<Value,EvalError>{Err(EvalError::Memory)}
 }
 for (bytes,defined) in [(&[0x30,0xc9][..],0xff),(&[0x66,0x31,0xc9][..],0xffff),(&[0x31,0xc9][..],u64::MAX),(&[0x48,0x31,0xc9][..],u64::MAX)] {
  let d=decode(bytes,Mode::Mode64).unwrap();let r=d.semantic_recipe(0x1000);assert_eq!(r.support,Support::Full);
  let t=s::evaluate(&r,&Unknown).unwrap();let v=reg(&t,"x86.gpr",1);assert_eq!(v.bits,0,"{bytes:02x?}");assert_eq!(v.defined,defined,"{bytes:02x?}");
  for (i,value) in [(0,0),(1,1),(3,1),(4,0),(5,0)]{assert_eq!(flag(&t,i),Value::known(1,value),"{bytes:02x?} flag {i}")}
  assert_eq!(flag(&t,2).defined,0);
 }
 let d=decode(&[0x30,0xe0],Mode::Mode64).unwrap();let t=s::evaluate(&d.semantic_recipe(0),&Unknown).unwrap();assert_eq!(reg(&t,"x86.gpr",0).defined&0xff,0);
 let mut st=State::default();st.x(0,0x1234);assert_eq!(x(&run(&[0x30,0xe0],&st),0),0x1226);
}
#[test]fn actual_corpus_stack_operands_and_snapshots(){
 let mut st=State::default();st.x(4,0x3000);st.x(0,0x5555);st.mem.insert(0x3000,0x4444);
 let d=decode(&[0x54],Mode::Mode64).unwrap();assert!(d.operands().iter().any(|o|o.implicit&&o.kind==OperandKind::Memory));let t=run(&[0x54],&st);assert_eq!(x(&t,4),0x2ff8);assert_eq!(t.memory[0].address,0x2ff8);assert_eq!(t.memory[0].value.bits,0x3000);
 let t=run(&[0x5c],&st);assert_eq!(x(&t,4),0x4444);
 let t=run(&[0xff,0xd4],&st);assert_eq!(t.next_pc.bits,0x3000);assert_eq!(t.memory[0].value.bits,0x1002);assert_eq!(x(&t,4),0x2ff8);
 let t=run(&[0xe8,4,0,0,0],&st);assert_eq!(t.next_pc.bits,0x1009);assert_eq!(t.memory[0].value.bits,0x1005);
 let t=run(&[0xc3],&st);assert_eq!(t.next_pc.bits,0x4444);assert_eq!(x(&t,4),0x3008);
 let t=run(&[0xc2,0x10,0],&st);assert_eq!(t.next_pc.bits,0x4444);assert_eq!(x(&t,4),0x3018);
 let t=run(&[0x6a,0xff],&st);assert_eq!(t.memory[0].value.bits,u64::MAX);
}
#[test]fn actual_counter_branch_hidden_register_is_exact(){let mut st=State::default();assert_eq!(run(&[0xe3,2],&st).next_pc.bits,0x1004);st.x(1,1);assert_eq!(run(&[0xe3,2],&st).next_pc.bits,0x1002);st.x(1,0x100000000);assert_eq!(run(&[0x67,0xe3,2],&st).next_pc.bits,0x1005);}
#[test]fn far_segment_control_system_and_prefix_boundaries(){
 for bytes in [&[0xcb][..],&[0xca,0x10,0],&[0xff,0x18],&[0xff,0x28],&[0x0f,0x20,0xc0],&[0x0f,0x22,0xc0],&[0x0f,0xa0],&[0x0f,0xa1],&[0x8e,0xd0],&[0x0f,0x05],&[0xcf],&[0x66,0x54],&[0xf2,0xe8,0,0,0,0],&[0x0f,0x1a,0x00],&[0x0f,0x18,0xe0]] {
  let d=decode(bytes,Mode::Mode64).unwrap_or_else(|e|panic!("{bytes:02x?}: {e:?}"));assert!(matches!(d.semantic_recipe(0x1000).support,Support::Unsupported(_)),"{bytes:02x?} {}",d.encoding().form_id);
 }
 for bytes in [&[0x90][..],&[0x0f,0x1f,0x00]]{assert_eq!(decode(bytes,Mode::Mode64).unwrap().semantic_recipe(0).support,Support::Full)}
}
`

const x86ExtraImplicitTests = `
#[test]fn unknown_hidden_state_and_far_opcode_cannot_be_discarded(){
 for bytes in [&[0xcb][..],&[0x48,0x03,0xc0],&[0x6a,1]]{let d=decode(bytes,Mode::Mode64).unwrap();assert!(matches!(d.semantic_recipe(0).support,Support::Unsupported(_)),"{bytes:02x?}")}
}
`
