package codec

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestEncodedAddressReferences(t *testing.T) {
	c := exampleCatalog(t)
	d, err := c.Decode([]byte{0xa0, 2})
	if err != nil {
		t.Fatal(err)
	}
	refs := d.AddressReferences(0x1000)
	if len(refs) != 1 || refs[0].Kind != ReferenceBranch || refs[0].Scale != 2 || refs[0].Bits[0].InstructionBit != 8 || !refs[0].Signed {
		t.Fatalf("incomplete reference: %+v", refs)
	}
	target := refs[0].Target
	out := bytes.Repeat([]byte{0xcc}, 4)
	if _, err = d.RewriteReference(0x1002, refs[0].OperandIndex, target, out); err != nil {
		t.Fatal(err)
	}
	next, err := c.Decode(out)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := next.BranchTarget(0x1002); got != target {
		t.Fatalf("target %x != %x", got, target)
	}
	before := append([]byte(nil), out...)
	if _, err = d.RewriteReference(0x1000, refs[0].OperandIndex, 0x1001, out); err == nil || !bytes.Equal(before, out) {
		t.Fatal("misaligned target wrote output")
	}
	refs[0].Bits[0].InstructionBit = 0
	if d.Encoding.Operands[0].Bits[0].InstructionBit == 0 {
		t.Fatal("reference metadata aliases catalog storage")
	}
}
func TestGeneratedEncodedReferences(t *testing.T) {
	c := exampleCatalog(t)
	out := t.TempDir()
	if err := c.GenerateRust(out); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(out, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "tests", "references.rs"), []byte(rustEncodedReferences), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("cargo", "test", "--test", "references", "--quiet")
	command.Dir = out
	command.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	if b, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated reference consumer: %v\n%s", err, b)
	}
}

const rustEncodedReferences = `use example::*;
#[test]fn refs_and_no_write(){
 let d=decode(&[0xa0,2]).unwrap();let refs=d.address_references(0x1000);assert_eq!(refs.len(),1);let r=&refs[0];assert_eq!(r.kind,AddressReferenceKind::Branch);assert_eq!(r.scale,2);assert_eq!(r.bits[0].instruction,8);assert!(r.domain.contains(4));
 let mut out=[0xcc;4];d.rewrite_reference(0x1002,0,r.target,&mut out).unwrap();assert_eq!(decode(&out).unwrap().branch_target(0x1002),Some(r.target));
 let before=out;assert_eq!(d.rewrite_reference(0x1000,0,0x1001,&mut out),Err(Error::Operand));assert_eq!(out,before);
 let d=decode(&[0xf0,0xff,0xff]).unwrap();assert_eq!(d.address_references(0x1000)[0].kind,AddressReferenceKind::Absolute);
}
#[test]fn fixed_form_blocks_keep_internal_and_external_targets(){
 // BR is two bytes, signed displacement scaled by two, PC bias two.
 let source=[0xa0,2,0xa0,0,0xa0,0xfe];let b=relocate_block(&source,0x1000,0x1002).unwrap();assert_eq!(b.bytes,[0xa0,1,0xa0,0,0xa0,0xfe]);assert_eq!(decode(&b.bytes).unwrap().branch_target(0x1002),Some(0x1006));assert_eq!(decode(&b.bytes[2..]).unwrap().branch_target(0x1004),Some(0x1006));assert_eq!(b.offsets,[(0,0),(2,2),(4,4)]);
 let mut out=[0xcc;2];let before=out;assert!(relocate_block_into(&source,0x1000,0x1002,&mut out).is_err());assert_eq!(out,before);
 assert_eq!(relocate_block(&source,u64::MAX,0x1002),Err(BlockRelocateError::AddressOverflow));
}
`

// Keep architecture width explicit: an absolute field's encoded width alone
// does not declare that the processor wraps its instruction pointer there.
func referenceRegressionCatalog(t *testing.T) *Catalog {
	t.Helper()
	var encodings []Encoding
	for _, tc := range []struct {
		id, flow string
		opcode   byte
		mask     uint64
		relative bool
	}{
		{"MASKED", "call", 0x0a, 0xfffe, false},
		{"CCALL", "conditional_call", 0xc4, 0xffff, false},
		{"CCALL_HYPHEN", "conditional-call", 0xc5, 0xffff, false},
		{"BR_WRAP", "branch", 0xa0, 0, true},
		{"DATA", "", 0x0b, 0, false},
		{"ABS", "branch", 0xc3, 0xffff, false},
	} {
		o := Operand{Name: "target", Kind: "address", Signed: tc.relative, Relative: tc.relative, Bits: []BitSlice{{InstructionBit: 8, Width: 16}}}
		if tc.relative {
			o.PCBias = 3
			o.PCWrapBits = 16
		}
		encodings = append(encodings, Encoding{ID: tc.id, Mnemonic: tc.id, Syntax: tc.id + " {target}", FlowControl: tc.flow, TargetMask: tc.mask, Mask: []byte{255, 0, 0}, Value: []byte{tc.opcode, 0, 0}, Operands: []Operand{o}})
	}
	encodings = append(encodings,
		Encoding{ID: "BR_WRAP32", Mnemonic: "br32", Syntax: "br32 {target}", FlowControl: "branch", Mask: []byte{255, 0, 0}, Value: []byte{0xa1, 0, 0}, Operands: []Operand{{Name: "target", Kind: "address", Signed: true, Relative: true, PCBias: 3, PCWrapBits: 32, Bits: []BitSlice{{InstructionBit: 8, Width: 16}}}}},
		Encoding{ID: "ABS32", Mnemonic: "abs32", Syntax: "abs32 {target}", FlowControl: "branch", TargetMask: 0xffffffff, Mask: []byte{255, 0, 0, 0, 0}, Value: []byte{0xc6, 0, 0, 0, 0}, Operands: []Operand{{Name: "target", Kind: "address", Bits: []BitSlice{{InstructionBit: 8, Width: 32}}}}},
	)
	fixed := uint64(2)
	encodings = append(encodings, Encoding{ID: "FIX", Mnemonic: "fix", Syntax: "fix", FlowControl: "branch", TargetMask: 0xffff, FixedTarget: &fixed, Mask: []byte{255}, Value: []byte{0xf0}})
	encodings = append(encodings, Encoding{ID: "NOP", Mnemonic: "nop", Syntax: "nop", Mask: []byte{255}, Value: []byte{0x90}})
	c, err := NewCatalog("reference_regressions", "fixture", encodings)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestArchitecturalReferenceTargets(t *testing.T) {
	c := referenceRegressionCatalog(t)
	for _, opcode := range []byte{0x0a, 0xc4, 0xc5} {
		d, err := c.Decode([]byte{opcode, 5, 0x10})
		if err != nil {
			t.Fatal(err)
		}
		refs := d.AddressReferences(0x1000)
		target := uint64(0x1005)
		if opcode == 0x0a {
			target = 0x1004
		}
		branch, ok := d.BranchTarget(0x1000)
		if !ok || branch != target || len(refs) != 1 || refs[0].Target != target || refs[0].Kind != ReferenceBranch {
			t.Fatalf("opcode %x: branch %x/%v refs %+v", opcode, branch, ok, refs)
		}
		out := bytes.Repeat([]byte{0xcc}, 5)
		before := append([]byte(nil), out...)
		if opcode == 0x0a {
			if _, err = d.RewriteReference(0x1000, 0, 0x2005, out); err == nil || !bytes.Equal(out, before) {
				t.Fatal("noncanonical target accepted or output modified")
			}
		}
		if _, err = d.RewriteReference(0x1000, 0, 0x2004, out); err != nil {
			t.Fatal(err)
		}
		back, err := c.Decode(out)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := back.BranchTarget(0x1000); got != 0x2004 {
			t.Fatalf("rewrite got %x", got)
		}
	}
	d, err := c.Decode([]byte{0x0b, 5, 0x10})
	if err != nil {
		t.Fatal(err)
	}
	if r := d.AddressReferences(0x1000)[0]; r.Kind != ReferenceAbsolute || r.Target != 0x1005 {
		t.Fatalf("data changed: %+v", r)
	}
}
func TestGeneratedArchitecturalReferences(t *testing.T) {
	c := referenceRegressionCatalog(t)
	out := t.TempDir()
	if err := c.GenerateRust(out); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(out, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "tests", "architectural.rs"), []byte(rustArchitecturalReferences), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("cargo", "test", "--test", "architectural", "--quiet")
	command.Dir = out
	command.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	if b, err := command.CombinedOutput(); err != nil {
		t.Fatalf("architectural reference consumer: %v\n%s", err, b)
	}
}

const rustArchitecturalReferences = `use reference_regressions::*;
#[test] fn masked_inspection_rewrite_and_block(){
 let d=decode(&[0x0a,5,0x10]).unwrap();assert_eq!(d.branch_target(0x1000),Some(0x1004));let r=&d.address_references(0x1000)[0];assert_eq!(r.target,0x1004);assert_eq!(r.kind,AddressReferenceKind::Branch);
 let mut out=[0xcc;8];for target in [0x2005,0x12004]{assert_eq!(d.rewrite_reference(0x1000,0,target,&mut out),Err(Error::Operand));assert_eq!(out,[0xcc;8]);}
 d.rewrite_reference(0x1000,0,0x2004,&mut out).unwrap();assert_eq!(decode(&out).unwrap().branch_target(0x1000),Some(0x2004));
 let source=[0x0a,5,0x10,0x90,0x90];let b=relocate_block(&source,0x1000,0x2000).unwrap();assert_eq!(decode(&b.bytes).unwrap().branch_target(0x2000),Some(0x2004));
 let before=out;assert_eq!(relocate_block_into(&source,0x1000,0x2001,&mut out),Err(BlockRelocateError::Encode(Error::Operand)));assert_eq!(out,before);
 let data=decode(&[0x0b,5,0x10]).unwrap();assert_eq!(data.address_references(0)[0].target,0x1005);assert_eq!(data.address_references(0)[0].kind,AddressReferenceKind::Absolute);
}
#[test] fn conditional_calls_and_wrapped_boundaries(){
 for opcode in [0xc4,0xc5]{
  let d=decode(&[opcode,4,0x10]).unwrap();assert_eq!(d.branch_target(0x1000),Some(0x1004));assert_eq!(d.address_references(0x1000)[0].kind,AddressReferenceKind::Branch);
  let b=relocate_block(&[opcode,4,0x10,0x90,0x90],0x1000,0x2000).unwrap();assert_eq!(decode(&b.bytes).unwrap().branch_target(0x2000),Some(0x2004));
  for (ip,target) in [(0x1000,0x1003),(0xffff,2)]{let source=[opcode,target as u8,(target>>8) as u8];let mut out=[0xcc;8];assert_eq!(relocate_block_into(&source,ip,0x2000,&mut out),Err(BlockRelocateError::PositionDiscovery));assert_eq!(out,[0xcc;8]);}
 }
 for source in [[0xa0,0,0,0x90],[0xc3,2,0,0x90]]{
  let b=relocate_block(&source,0xffff,0x1000).unwrap();assert_eq!(decode(&b.bytes).unwrap().branch_target(0x1000),Some(0x1003));
  let b=relocate_block(&source,0xffff,0xfffe).unwrap();assert_eq!(decode(&b.bytes).unwrap().branch_target(0xfffe),Some(1));
 }
 assert_eq!(relocate_block(&[0xa0,0xff,0xff,0x90],0xffff,0x1000),Err(BlockRelocateError::MidInstructionTarget));
 let b=relocate_block(&[0xa0,0,0],0xffff,0x1000).unwrap();assert_eq!(decode(&b.bytes).unwrap().branch_target(0x1000),Some(2));
 for source in [vec![0xa1,0,0,0x90],vec![0xc6,4,0,0,0,0x90]]{
  let b=relocate_block(&source,0xffffffff,0x1000).unwrap();assert_eq!(decode(&b.bytes).unwrap().branch_target(0x1000),Some(0x1000+source.len() as u64-1));
  let b=relocate_block(&source,0xffffffff,0xfffffffe).unwrap();assert_eq!(decode(&b.bytes).unwrap().branch_target(0xfffffffe),Some((0xfffffffe+source.len() as u64-1)&0xffffffff));
 }
 assert_eq!(relocate_block(&[0xf0,0x90,0x90,0x90],0xffff,0x1000),Err(BlockRelocateError::Unsupported));
 assert_eq!(relocate_block(&[0xf0,0x90,0x90,0x90],0xffff,0x1ffff).unwrap().bytes,[0xf0,0x90,0x90,0x90]);
 let mut huge=vec![0xc3,3,0];huge.resize(65537,0x90);assert_eq!(relocate_block(&huge,0,0x1000),Err(BlockRelocateError::Unsupported));
}
`
