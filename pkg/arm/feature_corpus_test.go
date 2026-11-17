package arm

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// Use real Arm pages when the optional source archive is installed. The ordinary
// fixture tests remain portable and exercise the same generator/runtime paths.
func TestCorpusGeneratedRequirementAPI(t *testing.T) {
	archive := os.Getenv("MKASM_ARM_FEATURE_CORPUS")
	if archive == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		archive = filepath.Join(home, "Documents/Developer/go-mkasm/architecture-expansion/ISA_A64_xml_A_profile-2026-06.tar.gz")
	}
	f, err := os.Open(archive)
	if os.IsNotExist(err) {
		t.Skip("optional Arm feature corpus archive unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	needed := map[string]bool{"fadd_float.xml": true, "bti.xml": true, "ptrue_p_s.xml": true, "add_addsub_imm.xml": true}
	pages := map[string]string{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(header.Name)
		if needed[name] {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			pages[name] = string(data)
		}
	}
	cases := []struct{ page, id string }{{"fadd_float.xml", "FADD_H_floatdp2"}, {"fadd_float.xml", "FADD_S_floatdp2"}, {"bti.xml", "BTI_HB_hints"}, {"ptrue_p_s.xml", "ptrue_p_s_"}, {"add_addsub_imm.xml", "ADD_64_addsub_imm"}}
	var instructions []*ir.InstructionIR
	parsed := map[string]*ParsedIForm{}
	for _, test := range cases {
		source, ok := pages[test.page]
		if !ok {
			t.Fatalf("archive missing %s", test.page)
		}
		p, err := parseIForm(strings.NewReader(source), test.id)
		if err != nil {
			t.Fatal(err)
		}
		i := &ir.InstructionIR{EncodingID: test.id, IFormFile: test.page, IClass: "requirements", Mnemonic: p.Mnemonic}
		ApplyParsedIForm(i, p)
		instructions = append(instructions, i)
		parsed[test.id] = p
	}
	dir := t.TempDir()
	load := func(i *ir.InstructionIR) *ParsedIForm { return parsed[i.EncodingID] }
	cg := NewCodeGenerator(dir, ArchAArch64)
	cg.SetAsmSurface(BuildAsmSurface(instructions, load))
	cg.SetDisasmSurface(BuildDisasmSurface(instructions, load))
	if err := cg.GenerateRust(BuildCatalog(instructions)); err != nil {
		t.Fatal(err)
	}
	source := `use aarch64::*;
use requirements::{Satisfaction::*,UnknownPolicy};
#[test] fn real_source_requirements() {
 let s=decode(0x1e222820).unwrap(); assert_eq!(s.encoding_id,"FADD_S_floatdp2");
 assert_eq!(s.evaluate_requirements(&["FEAT_FP"],"a64").primary,Satisfied);
 assert_eq!(s.evaluate_requirements(&[],"a64").primary,Unsatisfied);
 let h=decode(0x1ee22820).unwrap(); assert_eq!(h.encoding_id,"FADD_H_floatdp2");
 assert_eq!(h.evaluate_requirements(&["FEAT_FP"],"a64").primary,Unsatisfied);
 assert_eq!(h.evaluate_requirements(&["FEAT_FP","FEAT_FP16"],"a64").primary,Satisfied);
 let p=requirements_for("ptrue_p_s_");
 assert_eq!(p.evaluate(&["FEAT_SVE"],"a64",&|_|None).primary,Satisfied);
 assert_eq!(p.evaluate(&["FEAT_SME"],"a64",&|_|None).primary,Satisfied);
 assert_eq!(p.evaluate(&[],"a64",&|_|None).primary,Unsatisfied);
 let hint=decode(0xd503245f).unwrap(); assert_eq!(hint.encoding_id,"BTI_HB_hints");
 let absent=hint.evaluate_requirements(&[],"a64"); assert_eq!(absent.primary,Unsatisfied);
 assert!(absent.admit_fallback(UnknownPolicy::Reject)); assert_eq!(absent.fallback_behavior,"nop");
 assert_eq!(hint.evaluate_requirements(&["FEAT_BTI"],"a64").primary,Satisfied);
 assert_eq!(requirements_for("ADD_64_addsub_imm").evaluate(&[],"a64",&|_|None).primary,Unknown);
}
`
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "requirements.rs"), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	cmd := exec.Command("cargo", "test", "--test", "requirements", "--quiet")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real corpus requirement API: %v\n%s", err, out)
	}
}
