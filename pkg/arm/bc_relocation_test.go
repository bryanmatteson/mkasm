package arm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// A reduced upstream BC.cond page keeps this regression independent of the
// optional complete Arm archive while exercising parsing and both generators.
func TestGeneratedBCRelocation(t *testing.T) {
	const page = `<instructionsection><classes><iclass isa="A64">
 <docvars><docvar key="mnemonic" value="BC"/></docvars>
 <regdiagram form="32">
 <box hibit="31" width="8"><c colspan="8">01010100</c></box>
 <box hibit="23" width="19" name="imm19"><c colspan="19"/></box>
 <box hibit="4" name="o0"><c>1</c></box>
 <box hibit="3" width="4" name="cond"><c colspan="4"/></box>
 </regdiagram><encoding name="BC_only_condbranch">
 <asmtemplate><text>BC.</text><a hover="Is one of the standard conditions, encoded in the standard way, and " link="cond_option">&lt;cond&gt;</a><text>  </text><a hover="Is the program label to be conditionally branched to. Its offset from the address of this instruction, in the range +/-1MB, is encoded as &quot;imm19&quot; times 4." link="imm19_offset">&lt;label&gt;</a></asmtemplate>
 </encoding></iclass></classes></instructionsection>`
	p, err := parseIForm(strings.NewReader(page), "BC_only_condbranch")
	if err != nil {
		t.Fatal(err)
	}
	i := &ir.InstructionIR{EncodingID: p.EncodingName, IFormFile: "bc_cond.xml", IClass: "condbranch", Mnemonic: p.Mnemonic}
	ApplyParsedIForm(i, p)
	instructions := []*ir.InstructionIR{i}
	load := func(*ir.InstructionIR) *ParsedIForm { return p }
	dir := t.TempDir()
	cg := NewCodeGenerator(dir, ArchAArch64)
	cg.SetAsmSurface(BuildAsmSurface(instructions, load))
	cg.SetDisasmSurface(BuildDisasmSurface(instructions, load))
	if err := cg.GenerateRust(BuildCatalog(instructions)); err != nil {
		t.Fatal(err)
	}
	const consumer = `use aarch64::*;
#[test] fn bc_preserves_code_identity_and_internal_targets(){
 let words=[0x54000030u32,0x54fffff0];let bytes:Vec<u8>=words.iter().flat_map(|w|w.to_le_bytes()).collect();
 let b=relocate_block(&bytes,0x1000,0x2000).unwrap();assert_eq!(b.bytes,bytes);
 for (word,ip,target) in [(words[0],0x2000,0x2004),(words[1],0x2004,0x2000)]{let refs=address_references(word,ip).unwrap();assert_eq!(refs[0].kind,AddressReferenceKind::Branch);assert_eq!(refs[0].target,target);}
 let mut output=[0xcc;16];assert_eq!(relocate_block_into(&0x54000050u32.to_le_bytes(),0x1000,0x200000,&mut output),Err(RelocateError::OutOfRange));assert_eq!(output,[0xcc;16]);
}
`
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "bc.rs"), []byte(consumer), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("cargo", "test", "--test", "bc", "--quiet")
	command.Dir = dir
	command.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	if b, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generated BC relocation: %v\n%s", err, b)
	}
}
