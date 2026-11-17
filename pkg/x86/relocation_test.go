package x86

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGeneratedBlockRelocation(t *testing.T) {
	c := codecCatalog()
	for _, e := range []Encoding{
		{ID: "CALL_legacy", FormID: "CALL_legacy/0", Mnemonic: "CALL", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0xe8, Modes: mode16 | mode32, W: BitAny, Tail: []TailWidth{TailZ}, Operands: []Operand{{Type: "REL", Symbol: "REL", EncodedIn: "RZ"}}},
		{ID: "JMP8", FormID: "JMP8/0", Mnemonic: "JMP", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0xeb, Modes: modeAll, W: BitAny, Tail: []TailWidth{Tail8}, Operands: []Operand{{Type: "REL", Symbol: "REL", EncodedIn: "RB"}}},
		{ID: "JMP32", FormID: "JMP32/0", Mnemonic: "JMP", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0xe9, Modes: modeAll, W: BitAny, Tail: []TailWidth{TailZ}, Operands: []Operand{{Type: "REL", Symbol: "REL", EncodedIn: "RZ"}}},
		{ID: "JNE8", FormID: "JNE8/0", Mnemonic: "JNE", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0x75, Modes: modeAll, W: BitAny, Tail: []TailWidth{Tail8}, Operands: []Operand{{Type: "REL", Symbol: "REL", EncodedIn: "RB"}}},
		{ID: "JNE32", FormID: "JNE32/0", Mnemonic: "JNE", Kind: EncodingLegacy, Map: Map0F, Opcode: 0x85, Modes: modeAll, W: BitAny, Tail: []TailWidth{TailZ}, Operands: []Operand{{Type: "REL", Symbol: "REL", EncodedIn: "RZ"}}},
		{ID: "LOOP", FormID: "LOOP/0", Mnemonic: "LOOP", Kind: EncodingLegacy, Map: MapPrimary, Opcode: 0xe2, Modes: modeAll, W: BitAny, Tail: []TailWidth{Tail8}, Operands: []Operand{{Type: "REL", Symbol: "REL", EncodedIn: "RB"}}},
	} {
		c.Encodings = append(c.Encodings, e)
	}
	out := t.TempDir()
	if err := GenerateRust(c, out); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(out, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "tests", "relocation.rs"), []byte(rustBlockRelocationTests), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("cargo", "test", "--test", "relocation", "--quiet")
	command.Dir = out
	command.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	if b, err := command.CombinedOutput(); err != nil {
		t.Fatalf("relocation consumer: %v\n%s", err, b)
	}
}

const rustBlockRelocationTests = `use x86_64::*;
fn target(bytes:&[u8],ip:u64)->u64{decode(bytes,Mode::Mode64).unwrap().branch_target(ip).unwrap()}
#[test] fn internal_forward_and_backward(){
 let b=relocate_block(&[0xeb,1,0x90,0xeb,0xfb],0x1000,0x2000,Mode::Mode64).unwrap();
 assert_eq!(b.bytes,[0xeb,1,0x90,0xeb,0xfb]);assert_eq!(target(&b.bytes,0x2000),0x2003);assert_eq!(target(&b.bytes[3..],0x2003),0x2000);
 assert_eq!(b.relocated_address(3,0x2000),Some(0x2003));
}
#[test] fn widens_external_branches_and_keeps_targets(){
 for source in [&[0xeb,0x7f][..],&[0x75,0x7f][..]]{
  let b=relocate_block(source,0x1000,0x2000,Mode::Mode64).unwrap();assert!(b.bytes.len()>2);assert_eq!(target(&b.bytes,0x2000),0x1081);
 }
 let call=[0xe8,1,0,0,0];let b=relocate_block(&call,0x1000,0x2000,Mode::Mode64).unwrap();assert_eq!(target(&b.bytes,0x2000),0x1006);
}
#[test] fn growth_cascade_reaches_fixed_point(){
 // First conditional jump originally reaches the last nop at +129.
 // The external jump in its span must grow, forcing the conditional to grow.
 let mut source=vec![0x75,127,0xeb,0x80];source.resize(130,0x90);
 let b=relocate_block(&source,0x1000,0x3000,Mode::Mode64).unwrap();
 assert_eq!(&b.bytes[..2],&[0x0f,0x85]);assert_eq!(b.bytes[6],0xe9);
 assert_eq!(target(&b.bytes,0x3000),b.relocated_address(129,0x3000).unwrap());
 assert_eq!(target(&b.bytes[6..],0x3006),0xf84);
}
#[test] fn rip_data_preserves_original_target_even_inside_block(){
 let source=[0x48,0x8d,0x05,0,0,0,0,0x90];let b=relocate_block(&source,0x1000,0x2000,Mode::Mode64).unwrap();
 let d=decode(&b.bytes,Mode::Mode64).unwrap();let r=d.address_references(0x2000);assert_eq!(r[0].kind,AddressReferenceKind::Data);assert_eq!(r[0].target,0x1007);assert_eq!(r[0].bit_offset,24);assert_eq!(r[0].pc_bias,7);assert!(r[0].signed);
}
#[test] fn eip_relative_decode_rewrite_and_text_agree(){
 let source=[0x67,0x48,0x8d,0x05,0,0,0,0];let d=decode(&source,Mode::Mode64).unwrap();
 assert!(d.operands()[1].memory.rip_relative);assert_eq!(d.operands()[1].memory.address_size,32);
 assert!(d.format_intel(0).contains("[eip]"));
 let r=d.address_references(0xfffffff8);assert_eq!(r[0].kind,AddressReferenceKind::Data);assert_eq!(r[0].wrap_bits,32);assert_eq!(r[0].target,0);
 let b=relocate_block(&source,0xfffffff8,0x1000,Mode::Mode64).unwrap();let back=decode(&b.bytes,Mode::Mode64).unwrap();assert_eq!(back.address_references(0x1000)[0].target,0);
 assert!(assemble("lea rax, qword ptr [eip]").unwrap().iter().any(|e|e.bytes()==source));
 let desc=describe(&source).unwrap();assert!(desc.text.contains("eip"));assert!(assemble(&desc.text).unwrap().iter().any(|e|e.bytes()==source));
 let t=Template::parse("lea rax, qword ptr [eip+$d]").unwrap();assert_eq!(t.holes()[0].position(),Some(Position::WrappingInstructionRelative{bits:32}));
 assert_eq!(Position::WrappingInstructionRelative{bits:32}.target(0xfffffff8,8),Some(0));
}
#[test] fn errors_never_write(){
 let source=[0xe8,1,0,0,0];let d=decode(&source,Mode::Mode64).unwrap();let mut out=[0xcc;15];
 assert_eq!(relocate(&d,&source,0x1000,0x100000000,&mut out),Err(RelocateError::OutOfRange));assert_eq!(out,[0xcc;15]);
 assert_eq!(relocate(&d,&source[..4],0x1000,0x2000,&mut out),Err(RelocateError::Truncated));assert_eq!(out,[0xcc;15]);
 assert_eq!(rewrite_reference(&d,&source,0x1000,0,0x100000000,&mut out),Err(RelocateError::OutOfRange));assert_eq!(out,[0xcc;15]);
 let mut block=[0xcc;2];assert_eq!(relocate_block_into(&[0xeb,0x7f],0x1000,0x2000,Mode::Mode64,&mut block),Err(RelocateError::BufferTooSmall));assert_eq!(block,[0xcc;2]);
 assert_eq!(relocate_block_into(&[0xe8,0,0,0,0],0x1000,0x2000,Mode::Mode64,&mut block),Err(RelocateError::PositionDiscovery));assert_eq!(block,[0xcc;2]);
}
#[test] fn rejects_unsafe_or_unrepresentable_inputs(){
 assert_eq!(relocate_block(&[0xe8,0,0,0,0],0x1000,0x2000,Mode::Mode64),Err(RelocateError::PositionDiscovery));
 assert_eq!(relocate_block(&[0xeb,0xff],0x1000,0x2000,Mode::Mode64),Err(RelocateError::MidInstructionTarget));
 assert_eq!(relocate_block(&[0xe8,1,0,0,0],0x1000,0x100000000,Mode::Mode64),Err(RelocateError::OutOfRange));
 assert_eq!(relocate_block(&[0xe8,1],0x1000,0x2000,Mode::Mode64),Err(RelocateError::Truncated));
 assert_eq!(relocate_block(&[0x90],u64::MAX,0x2000,Mode::Mode64),Err(RelocateError::AddressOverflow));
 assert_eq!(relocate_block(&[0x90],0x1000,u64::MAX,Mode::Mode64),Err(RelocateError::AddressOverflow));
 assert_eq!(relocate_block(&[0xe2,0x7f],0x1000,0x2000,Mode::Mode64),Err(RelocateError::Unsupported));
}
#[test] fn internal_calls_and_external_continuation(){
 let b=relocate_block(&[0xe8,1,0,0,0,0x90,0x90],0x1000,0x2000,Mode::Mode64).unwrap();assert_eq!(target(&b.bytes,0x2000),0x2006);
 let b=relocate_block(&[0xeb,0],0x1000,0x2000,Mode::Mode64).unwrap();assert_eq!(target(&b.bytes,0x2000),0x1002);
}
#[test] fn wrapped_internal_boundaries_and_call_next(){
 for (mode,old,mask) in [(Mode::Mode16,0xffff,0xffff),(Mode::Mode32,0xffffffff,0xffffffff)]{
  for new in [0x1000,old]{
   let b=relocate_block(&[0xeb,0,0x90],old,new,mode).unwrap();assert_eq!(b.bytes,[0xeb,0,0x90]);assert_eq!(decode(&b.bytes,mode).unwrap().branch_target(new),Some((new+2)&mask));
  }
  assert_eq!(relocate_block(&[0xeb,0xff,0x90],old,0x1000,mode),Err(RelocateError::MidInstructionTarget));
  let b=relocate_block(&[0xeb,0],old,0x1000,mode).unwrap();assert_eq!(decode(&b.bytes,mode).unwrap().branch_target(0x1000),Some(1));
  let source=if mode==Mode::Mode16{vec![0xe8,0,0]}else{vec![0xe8,0,0,0,0]};let d=decode(&source,mode).unwrap();let mut out=[0xcc;15];assert_eq!(relocate(&d,&source,old,0x1000,&mut out),Err(RelocateError::PositionDiscovery));assert_eq!(out,[0xcc;15]);
  assert_eq!(relocate_block(&source,old,0x1000,mode),Err(RelocateError::PositionDiscovery));
 }
 let source=vec![0x90;65537];assert_eq!(relocate_block(&source,0,0x1000,Mode::Mode16),Err(RelocateError::Unsupported));
}
`
