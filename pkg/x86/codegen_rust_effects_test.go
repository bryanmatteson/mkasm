package x86

import (
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedArchitecturalEffects(t *testing.T) {
	f, err := os.Open("testdata/opcodesdb-mode-fixture.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	c, err := ParseOpcodesDB(z)
	if err != nil {
		t.Fatal(err)
	}
	// Unmodified real opcodesDB MOVSS/MOVSD records retain the register/memory
	// distinction that exposes partial XMM writes in the generated consumer.
	moves, err := os.ReadFile("testdata/opcodesdb-scalar-moves-fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	scalarMoves, err := ParseOpcodesDB(bytes.NewReader(moves))
	if err != nil {
		t.Fatal(err)
	}
	c.Encodings = append(c.Encodings, scalarMoves.Encodings...)
	custom := Encoding{ID: "CUSTOM", FormID: "CUSTOM/0", Mnemonic: "CUSTOM", Syntax: "CUSTOM", Opcode: 0xf1, Modes: modeAll, W: BitAny, IFlags: map[string]string{"cf": "RCW", "af": "U"}}
	shift := Encoding{ID: "SHL", FormID: "SHL/count", Mnemonic: "SHL", Syntax: "SHL", Opcode: 0xc1, Modes: modeAll, W: BitAny, HasModRM: true, Mod: ModRegister, RegMask: 7, RegValue: 4, Tail: []TailWidth{Tail8}, Operands: []Operand{{Type: "REG", Symbol: "GPRv", EncodedIn: "RM", Read: true, Write: true}, {Type: "IMM", EncodedIn: "IB", Size: "8"}}}
	variable := shift
	variable.Opcode = 0xd3
	variable.FormID = "SHL/cl"
	variable.Tail = nil
	variable.Operands = []Operand{{Type: "REG", Symbol: "GPRv", EncodedIn: "RM", Read: true, Write: true}, {Type: "REG", Value: "CL", Read: true}}
	rotate := shift
	rotate.ID = "ROL"
	rotate.FormID = "ROL/count"
	rotate.Mnemonic = "ROL"
	rotate.RegValue = 0
	c.Encodings = append(c.Encodings, custom, shift, variable, rotate)
	dir := t.TempDir()
	if err := GenerateRust(c, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests/effects.rs"), []byte(`use x86_64::*;
fn fx(text:&str)->EffectSummary {let b=assemble(text).unwrap();decode(b[0].bytes(),Mode::Mode64).unwrap().effects()}
#[test] fn scalar_flags_slices_addresses_and_stack(){
 let e16=decode(&[0x89,0xd8],Mode::Mode16).unwrap().effects();assert!(e16.registers.iter().any(|r|r.write&&r.register.width==Some(16)&&r.write_behavior==WriteBehavior::PreserveUpper));
 let e=fx("add eax, ebx");assert!(e.registers.iter().any(|r|r.write&&r.register.width==Some(32)&&r.write_behavior==WriteBehavior::ZeroUpper));assert_eq!(e.flags.iter().find(|f|f.name=="CF").unwrap().action,FlagAction::Write);
 let e=fx("mov ah, bl");assert!(e.registers.iter().any(|r|r.write&&r.register.offset==8&&r.register.number==Some(0)&&r.write_behavior==WriteBehavior::PreserveUpper));
 let e=fx("xor eax, ebx");assert_eq!(e.flags.iter().find(|f|f.name=="AF").unwrap().action,FlagAction::Undefined);assert_eq!(e.flags.iter().find(|f|f.name=="OF").unwrap().action,FlagAction::Clear);
 let e=fx("add qword ptr [rax+rcx*4], rdx");assert!(e.registers.iter().any(|r|r.address&&r.register.number==Some(0)));assert!(e.registers.iter().any(|r|r.address&&r.register.number==Some(1)));assert!(e.memory.iter().any(|m|m.read&&m.write&&m.width_bits==Some(64)));
 let eip=decode(&[0x67,0x8b,0x05,0x10,0,0,0],Mode::Mode64).unwrap().effects();assert!(eip.registers.iter().any(|r|r.address&&r.read&&r.register.bank=="ip"&&r.register.name=="EIP"&&r.register.width==Some(32)));
 let lea=fx("lea rax, [rbx+rcx*4]");assert!(lea.memory.is_empty());assert!(lea.registers.iter().any(|r|r.address&&r.read));
 let e=fx("call .+16");assert!(e.registers.iter().any(|r|r.implicit&&r.write&&r.register.number==Some(4)));assert!(e.memory.iter().any(|m|m.implicit&&m.write&&m.width_bits==Some(64)&&m.writeback==Writeback::Before));
}
#[test] fn conditional_flags_and_shift_counts(){
 let e=decode(&[0xf1],Mode::Mode64).unwrap().effects();let cf=e.flags.iter().find(|f|f.name=="CF").unwrap();assert!(cf.read&&cf.conditional);assert_eq!(cf.action,FlagAction::Write);assert_eq!(e.flags.iter().find(|f|f.name=="ZF").unwrap().action,FlagAction::Unknown);
 let e=decode(&[0xc1,0xe0,0],Mode::Mode64).unwrap().effects();assert!(e.flags.iter().all(|f|f.action==FlagAction::Preserve));
 let e=decode(&[0xc1,0xe0,1],Mode::Mode64).unwrap().effects();assert_eq!(e.flags.iter().find(|f|f.name=="OF").unwrap().action,FlagAction::Write);assert_eq!(e.flags.iter().find(|f|f.name=="AF").unwrap().action,FlagAction::Undefined);
 let rotation=decode(&[0xc1,0xc0,8],Mode::Mode64).unwrap().effects();assert_eq!(rotation.flags_knowledge,EffectKnowledge::Unknown);assert_eq!(rotation.flags.iter().find(|f|f.name=="CF").unwrap().action,FlagAction::Unknown);assert_eq!(rotation.flags.iter().find(|f|f.name=="ZF").unwrap().action,FlagAction::Preserve);
 let e=decode(&[0xd3,0xe0],Mode::Mode64).unwrap().effects();assert_eq!(e.flags_knowledge,EffectKnowledge::Unknown);assert!(e.flags.iter().any(|f|f.name=="CF"&&f.conditional&&f.action==FlagAction::Unknown));
}
#[test] fn masked_merging_and_zeroing(){let e=fx("vpaddd zmm1 {k2}, zmm2, zmm3");assert!(e.registers.iter().any(|r|r.write&&r.read&&r.conditional&&r.register.bank=="vector"&&r.register.number==Some(1)));assert!(e.registers.iter().any(|r|r.read&&r.register.bank=="mask"&&r.register.number==Some(2)));let e=fx("vpaddd zmm1 {k2} {z}, zmm2, zmm3");assert!(e.registers.iter().any(|r|r.write&&!r.read&&r.register.number==Some(1)));}
#[test] fn vector_upper_and_unknown(){let e=fx("vpaddd ymm1, ymm2, ymm3");assert!(e.registers.iter().any(|r|r.write&&r.write_behavior==WriteBehavior::ZeroUpper));assert_eq!(e.flags_knowledge,EffectKnowledge::Unknown);assert_eq!(e.knowledge,EffectKnowledge::Partial);}
`+x86EffectBoundaryTests), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "effects", "--quiet")
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("effects crate: %v\n%s", err, b)
	}
}

// Opt-in real-corpus integration exercises source form selection as well as
// the same durable byte-level checks that run in the small fixture by default.
func TestGeneratedEffectCorpusBoundaries(t *testing.T) {
	path := os.Getenv("MKASM_X86_OPCODESDB")
	if path == "" {
		t.Skip("set MKASM_X86_OPCODESDB for complete-corpus effects checks")
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
	dir := t.TempDir()
	if err := GenerateRust(catalog, dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "effects.rs"), []byte("use x86_64::*;\n"+x86EffectBoundaryTests), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "effects", "--quiet")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-Dwarnings")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("complete-corpus x86 effects (%d forms): %v\n%s", len(catalog.Encodings), err, out)
	}
	t.Logf("validated real decoded bytes with %d source forms", len(catalog.Encodings))
}

const x86EffectBoundaryTests = `
#[test]fn near_and_far_jump_flag_categories(){
 for (mode,bytes) in [
  (Mode::Mode16,&[0xea,0,0,0x28,0][..]),(Mode::Mode32,&[0xea,0,0,0,0,0x28,0][..]),
  (Mode::Mode16,&[0xff,0x28][..]),(Mode::Mode32,&[0xff,0x28][..]),(Mode::Mode64,&[0x48,0xff,0x28][..])
 ] {let d=decode(bytes,mode).unwrap();assert_eq!(d.encoding().mnemonic,"JMP");let e=d.effects();assert_eq!(e.flags_knowledge,EffectKnowledge::Unknown,"{mode:?} {bytes:02x?}");assert!(e.flags.iter().all(|f|f.action==FlagAction::Unknown));}
 for (mode,bytes) in [
  (Mode::Mode16,&[0xeb,0][..]),(Mode::Mode32,&[0xe9,0,0,0,0][..]),(Mode::Mode64,&[0xeb,0][..]),
  (Mode::Mode16,&[0xff,0xe0][..]),(Mode::Mode32,&[0xff,0xe0][..]),(Mode::Mode64,&[0xff,0xe0][..]),
  (Mode::Mode64,&[0xff,0x20][..])
 ] {let e=decode(bytes,mode).unwrap().effects();assert_eq!(e.flags_knowledge,EffectKnowledge::Complete,"{mode:?} {bytes:02x?}");assert!(e.flags.iter().all(|f|f.action==FlagAction::Preserve));}
}
#[test]fn legacy_scalar_moves_preserve_only_above_the_written_slice(){
 for (prefix,bits) in [(0xf3,32),(0xf2,64)] {
  for opcode in [0x10,0x11] {
   // Both opcode directions name destination XMM1 and source XMM2.
   let bytes=[prefix,0x0f,opcode,if opcode==0x10{0xca}else{0xd1}];
   let e=decode(&bytes,Mode::Mode64).unwrap().effects();
   let dst=e.registers.iter().find(|r|r.write).unwrap();assert_eq!(dst.register.bank,"vector");assert_eq!(dst.register.number,Some(1));assert_eq!(dst.register.offset,0);assert_eq!(dst.register.width,Some(bits));assert_eq!(dst.write_behavior,WriteBehavior::PreserveUpper);
   let src=e.registers.iter().find(|r|r.read).unwrap();assert_eq!(src.register.number,Some(2));assert_eq!(src.register.width,Some(bits));assert!(e.memory.is_empty());
  }
  // Memory loads clear the rest of XMM, preserving only above bit127.
  let e=decode(&[prefix,0x0f,0x10,0x08],Mode::Mode64).unwrap().effects();let dst=e.registers.iter().find(|r|r.write).unwrap();assert_eq!(dst.register.width,Some(128));assert_eq!(dst.write_behavior,WriteBehavior::PreserveUpper);assert!(!dst.read);assert_eq!(e.memory[0].width_bits,Some(bits));assert!(e.memory[0].read&&!e.memory[0].write);
  let e=decode(&[prefix,0x0f,0x11,0x08],Mode::Mode64).unwrap().effects();let src=e.registers.iter().find(|r|r.register.bank=="vector").unwrap();assert!(src.read&&!src.write);assert_eq!(src.register.width,Some(bits));assert_eq!(e.memory[0].width_bits,Some(bits));assert!(e.memory[0].write&&!e.memory[0].read);
 }
}
`
