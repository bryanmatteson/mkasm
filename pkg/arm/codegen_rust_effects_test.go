package arm

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/semantics"
	"github.com/bryanmatteson/mkasm/templates"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"text/template"
)

func TestGeneratedA64Effects(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0755); err != nil {
		t.Fatal(err)
	}
	// Fixed genuine instruction words pass through the production decoder and
	// companion generator. No test-owned effect implementation is substituted.
	c := &Catalog{Entries: []CatalogEntry{{EncodingID: "ADD", AsmMnemonic: "ADD", Mnemonic: "ADD", Mask: 0xffffffff, Value: 0x11000420}, {EncodingID: "ADDS", AsmMnemonic: "ADDS", Mnemonic: "ADDS", Mask: 0xffffffff, Value: 0x31000420}, {EncodingID: "CSEL", Mnemonic: "CSEL", Mask: 0xffffffff, Value: 0x9a820020}, {EncodingID: "LDR", Mnemonic: "LDR", Mask: 0xffffffff, Value: 0xf8408420}, {EncodingID: "SVE", Mnemonic: "SVE", Mask: 0xffffffff, Value: 0x04200020}, {EncodingID: "STRB", Mnemonic: "STRB", Mask: 0xffffffff, Value: 0x39000020}, {EncodingID: "LDAR", Mnemonic: "LDAR", Mask: 0xffffffff, Value: 0xc8dffc20}, {EncodingID: "MOVK", Mnemonic: "MOVK", Mask: 0xffffffff, Value: 0xf2a00020}}}
	for _, entry := range []struct {
		id   string
		word uint32
	}{
		{"AND_SP64", 0x92001c3f}, {"ORR_SP64", 0xb2001c3f}, {"EOR_SP64", 0xd2001c3f},
		{"AND_SP32", 0x12001c3f}, {"ORR_SP32", 0x32001c3f}, {"EOR_SP32", 0x52001c3f},
		{"AND_SP_ZR", 0x92001fff}, {"ANDS_ZR", 0xf2001c3f},
		{"STP_WB_RT", 0xa9bf0400}, {"STP_WB_RT2", 0xa9bf0420},
		{"LDP_WB_RT", 0xa9ff0400}, {"LDP_WB_RT2", 0xa9ff0420},
		{"LDP_DUPLICATE", 0xa9400020}, {"LDPSW_DUPLICATE", 0x69400020}, {"LDP_DUPLICATE_ZR", 0xa9407fff},
		{"STP_ORDINARY", 0xa9bf0440}, {"LDP_ORDINARY", 0xa9ff0440},
		{"STP_SP_ZR", 0xa9bf07ff}, {"LDP_SP_ZR", 0xa9ff07ff}, {"STP_DUPLICATE", 0xa9000020},
	} {
		c.Entries = append(c.Entries, CatalogEntry{EncodingID: entry.id, Mnemonic: entry.id, Mask: 0xffffffff, Value: entry.word})
	}
	for _, shape := range []struct{ mask, value uint32 }{{0x7f00c000, 0x74000000}, {0xff008000, 0x74008000}, {0x7f004000, 0x75000000}, {0xff000010, 0x54000010}} {
		c.Entries = append(c.Entries, CatalogEntry{EncodingID: fmt.Sprintf("compare_%08x", shape.value), Mnemonic: "compare", Mask: shape.mask, Value: shape.value})
	}
	data, err := buildRustDecoderData(c)
	if err != nil {
		t.Fatal(err)
	}
	tm, err := template.New("rust").ParseFS(templates.FS, "rust/*.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	if err := execTmplWrite(tm, "decoders.rs.tmpl", filepath.Join(src, "decoders.rs"), data); err != nil {
		t.Fatal(err)
	}
	if err := writeRustEffects(tm, src, false); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"Cargo.toml": "[package]\nname=\"a64_effects\"\nversion=\"0.1.0\"\nedition=\"2021\"\n", "src/lib.rs": `pub mod decoders;pub mod effects;pub use effects::*;
#[cfg(test)] mod tests {use super::*;fn fx(w:u32)->EffectSummary{decoders::decode(w).unwrap().effects()}
#[test] fn arithmetic_slices_flags_and_predication(){let e=fx(0x11000420);assert_eq!(e.registers_knowledge,EffectKnowledge::Complete);assert!(e.registers.iter().any(|r|r.write&&r.register.width==Some(32)&&r.write_behavior==WriteBehavior::ZeroUpper));assert!(e.flags.iter().all(|f|f.action==FlagAction::Preserve));let e=fx(0x31000420);assert!(e.flags.iter().all(|f|f.action==FlagAction::Write));let e=fx(0x9a820020);assert!(e.registers.iter().filter(|r|r.read).all(|r|r.conditional));assert!(e.flags.iter().any(|f|f.name=="Z"&&f.read));assert!(e.registers.iter().any(|r|r.write&&!r.conditional));}
#[test]fn store_slices_acquire_and_partial_values(){let e=fx(0x39000020);assert!(e.registers.iter().any(|r|r.read&&!r.address&&r.register.width==Some(8)));let e=fx(0xc8dffc20);assert_eq!(e.memory[0].ordering,MemoryOrdering::Acquire);assert_eq!(e.memory[0].atomicity,Atomicity::Atomic);let e=fx(0xf2a00020);assert!(e.registers.iter().any(|r|r.read&&r.register.offset==0&&r.register.width==Some(16)));assert!(e.registers.iter().any(|r|r.read&&r.register.offset==32&&r.register.width==Some(32)));}
#[test]fn compare_branch_effects_have_low_source_slices_and_preserve_nzcv(){
 for (base,width,immediate) in [(0x74000000,32,false),(0xf4000000,64,false),(0x74008000,8,false),(0x7400c000,16,false),(0x75000000,32,true),(0xf5000000,64,true)] {for cc in [0,1,2,3,6,7] {for rt in [1,31] {
  let e=fx(base|cc<<21|if immediate{63<<15}else{2<<16}|2<<5|rt);
  assert_eq!(e.registers_knowledge,EffectKnowledge::Complete);assert_eq!(e.flags_knowledge,EffectKnowledge::Complete);assert_eq!(e.memory_knowledge,EffectKnowledge::Complete);assert!(e.memory.is_empty());
  assert_eq!(e.registers.len(),usize::from(rt!=31)+usize::from(!immediate));
  assert!(e.registers.iter().all(|r|r.read&&!r.write&&!r.conditional&&!r.address&&r.register.width==Some(width)&&r.register.bank=="gpr"));assert!(e.flags.iter().all(|f|!f.read&&f.action==FlagAction::Preserve));
 }}}
 for condition in 0..16 {let e=fx(0x54000010|condition);assert!(e.registers.is_empty()&&e.memory.is_empty());assert_eq!(e.flags_knowledge,EffectKnowledge::Complete);assert!(e.flags.iter().all(|f|f.action==FlagAction::Preserve));assert_eq!(e.flags.iter().any(|f|f.read),condition<14);}
}
#[test]fn logical_immediate_sp_destination_and_zero_register(){
 for (width,words) in [(64,[0x92001c3f,0xb2001c3f,0xd2001c3f]),(32,[0x12001c3f,0x32001c3f,0x52001c3f])] {
  for w in words {let e=fx(w);assert_eq!(e.registers_knowledge,EffectKnowledge::Complete);let dst=e.registers.iter().find(|r|r.write).unwrap();assert_eq!(dst.register.bank,"sp");assert_eq!(dst.register.number,Some(31));assert_eq!(dst.register.width,Some(width));assert_eq!(dst.write_behavior,if width==32{WriteBehavior::ZeroUpper}else{WriteBehavior::Replace});assert!(!dst.read);assert!(e.flags.iter().all(|f|f.action==FlagAction::Preserve));}
 }
 let e=fx(0x92001fff);assert_eq!(e.registers.len(),1);assert_eq!(e.registers[0].register.bank,"sp");assert!(e.registers[0].write&&!e.registers[0].read);
 let e=fx(0xf2001c3f);assert!(!e.registers.iter().any(|r|r.write));assert!(!e.registers.iter().any(|r|r.register.bank=="sp"));assert_eq!(e.flags_knowledge,EffectKnowledge::Complete);assert!(e.flags.iter().any(|f|f.name=="Z"&&f.action==FlagAction::Write));
}
#[test]fn pair_overlap_categories_and_possible_nop(){
 for w in [0xa9bf0400,0xa9bf0420,0xa9ff0400,0xa9ff0420,0xa9400020,0x69400020,0xa9407fff] {
  let e=fx(w);assert_eq!(e.registers_knowledge,EffectKnowledge::Partial,"{w:#x}");assert_eq!(e.memory_knowledge,EffectKnowledge::Partial,"{w:#x}");assert!(e.registers.iter().all(|r|r.conditional),"{w:#x}");assert!(e.memory.iter().all(|m|m.conditional),"{w:#x}");assert_eq!(e.flags_knowledge,EffectKnowledge::Complete);assert!(e.flags.iter().all(|f|f.action==FlagAction::Preserve));
 }
 for w in [0xa9ff0400,0xa9ff0420] {assert_eq!(fx(w).memory[0].writeback,Writeback::Unknown);}
 for w in [0xa9bf0440,0xa9ff0440,0xa9bf07ff,0xa9ff07ff,0xa9000020] {
  let e=fx(w);assert_eq!(e.registers_knowledge,EffectKnowledge::Complete,"{w:#x}");assert_eq!(e.memory_knowledge,EffectKnowledge::Complete,"{w:#x}");assert!(e.registers.iter().all(|r|!r.conditional));assert!(e.memory.iter().all(|m|!m.conditional));
 }
 for w in [0xa9bf07ff,0xa9ff07ff] {let e=fx(w);assert!(e.registers.iter().any(|r|r.register.bank=="sp"&&r.read&&r.write));assert!(!e.registers.iter().any(|r|r.register.bank=="gpr"&&r.register.number==Some(31)));}
}
#[test]fn memory_writeback_and_unknown(){let e=fx(0xf8408420);assert!(e.registers.iter().any(|r|r.address&&r.read&&r.write));assert_eq!(e.memory[0].width_bits,Some(64));assert_eq!(e.memory[0].writeback,Writeback::After);assert!(e.memory[0].read);let e=fx(0x04200020);assert_eq!(e.knowledge,EffectKnowledge::Unknown);assert!(e.registers.is_empty());assert!(e.flags.is_empty());}}
`}
	for p, s := range files {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip(err)
	}
	cmd := exec.Command("cargo", "test", "--lib", "--quiet")
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("A64 effects: %v\n%s", err, b)
	}
}

func TestGeneratedARM32EffectPredication(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0755); err != nil {
		t.Fatal(err)
	}
	tm, err := template.New("arm32").ParseFS(templates.FS, "rust/*.tmpl", "arm32_rust/*.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	c := &Catalog{Entries: []CatalogEntry{{EncodingID: "LDR_NE", Mnemonic: "LDR", Mask: 0xffffffff, Value: 0x14910004}}}
	for _, bank := range []string{"a32", "t16", "t32"} {
		data, err := buildRustDecoderData(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := execTmplWrite(tm, "decoders.rs.tmpl", filepath.Join(src, bank+".rs"), data); err != nil {
			t.Fatal(err)
		}
	}
	if err := execTmplWrite(tm, "encoders.rs.tmpl", filepath.Join(src, "encoders.rs"), struct{ FixedTable, FieldsTable, ClassTable string }{emitRustFixedTable(c), emitRustFieldsTable(c), emitRustClassTable(c)}); err != nil {
		t.Fatal(err)
	}
	if err := execTmplWrite(tm, "arm32_analysis.rs.tmpl", filepath.Join(src, "analysis.rs"), struct{ Identities string }{""}); err != nil {
		t.Fatal(err)
	}
	if err := execTmplWrite(tm, "arm32_lib.rs.tmpl", filepath.Join(src, "lib.rs"), struct {
		Forms          string
		FormIndices    string
		GoldenTests    bool
		OptionalGroups int
	}{"", "static A32_FORM_INDICES:&[u16]=&[];static T16_FORM_INDICES:&[u16]=&[];static T32_FORM_INDICES:&[u16]=&[];", false, 0}); err != nil {
		t.Fatal(err)
	}
	if err := semantics.WriteRust(src); err != nil {
		t.Fatal(err)
	}
	if err := writeRustRequirements(src, c); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"recipes", "references"} {
		if err := execTmplWrite(tm, file+".rs.tmpl", filepath.Join(src, file+".rs"), nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeRustEffects(tm, src, true); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"Cargo.toml": "[package]\nname=\"arm32_effects\"\nversion=\"0.1.0\"\nedition=\"2021\"\n", "tests/effects.rs": `use arm32_effects::*;
#[test]fn a32_predicated_memory(){let d=decode(&0x14910004u32.to_le_bytes(),Mode::Arm,Endian::Little).unwrap();let e=d.effects();assert_eq!(e.knowledge,EffectKnowledge::Partial);assert!(e.flags.iter().any(|f|f.name=="Z"&&f.read));assert!(e.registers.iter().all(|r|r.conditional));assert!(e.memory[0].conditional&&e.memory[0].read);assert_eq!(e.memory[0].writeback,Writeback::After);}
`}
	for p, s := range files {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(s), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "effects", "--quiet")
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ARM32 effects: %v\n%s", err, b)
	}
}
