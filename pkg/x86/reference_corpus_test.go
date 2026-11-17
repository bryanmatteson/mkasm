package x86

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/internal/testreference"
)

func TestIndependentLLVMCorpus(t *testing.T) {
	source, database, llvm := os.Getenv("MKASM_LLVM_SOURCE"), os.Getenv("MKASM_X86_OPCODESDB"), os.Getenv("MKASM_LLVM_MC")
	if source == "" || database == "" || llvm == "" {
		t.Skip("set MKASM_LLVM_SOURCE, MKASM_X86_OPCODESDB and MKASM_LLVM_MC")
	}
	f, err := os.Open(database)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := ParseOpcodesDB(f)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := NewDecoder(c)
	if err != nil {
		t.Fatal(err)
	}
	var corpus strings.Builder
	count := 0
	missing := map[string]int{}
	outside := map[string]int{}
	available := map[Mode]map[string]bool{}
	for _, mode := range []Mode{Mode16, Mode32, Mode64} {
		available[mode] = map[string]bool{}
		for _, e := range c.Encodings {
			if e.Modes.supports(mode) {
				available[mode][strings.ToLower(e.Mnemonic)] = true
			}
		}
	}
	for _, suite := range []struct {
		file  string
		mode  Mode
		intel bool
	}{
		{"x86-16.s", Mode16, false}, {"x86-32.s", Mode32, false}, {"x86-64.s", Mode64, false},
		{"x86_64-encoding.s", Mode64, false}, {"avx-32-att.s", Mode32, false},
		{"avx-64-intel.s", Mode64, true}, {"avx512-intel.s", Mode64, true},
	} {
		triple := "i386-unknown-unknown"
		if suite.mode == Mode64 {
			triple = "x86_64-unknown-unknown"
		}
		if suite.mode == Mode16 {
			triple += "-code16"
		}
		args := []string{"-triple=" + triple, "-output-asm-variant=1"}
		if suite.intel {
			args = append(args, "-x86-asm-syntax=intel")
		}
		vectors, fixups, err := testreference.AssembleFile(llvm, filepath.Join(source, "llvm", "test", "MC", "X86", suite.file), args...)
		if err != nil {
			t.Fatal(err)
		}
		fragments := 0
		for _, v := range vectors {
			// MC prints authored prefix directives as separate encoding
			// fragments, not complete instructions. Track them separately.
			if len(v.Bytes) == 1 && strings.Contains(" data16 data32 addr16 addr32 lock rep repe repne repz repnz cs ds ss es fs gs xacquire xrelease rex64 ", " "+v.Text+" ") {
				fragments++
				continue
			}
			d, err := decoder.Decode(v.Bytes, suite.mode)
			if err != nil || int(d.Length) != len(v.Bytes) {
				key := strings.Fields(v.Text)[0]
				if !available[suite.mode][key] {
					outside[fmt.Sprintf("%d:%s", suite.mode, key)]++
					continue
				}
				missing[key]++
				if missing[key] == 1 {
					t.Logf("uncovered native %s %d %q %x: Go decode %+v %v", suite.file, suite.mode, v.Text, v.Bytes, d, err)
				}
				continue
			}
			fmt.Fprintf(&corpus, "%d\t%s\t%s\t%s\n", suite.mode, hex.EncodeToString(v.Bytes), suite.file, v.Text)
			count++
		}
		t.Logf("native %s: %d concrete MC vectors; %d relocation fragments and %d standalone prefix fragments", suite.file, len(vectors), fixups, fragments)
	}
	if len(missing) != 0 {
		t.Fatalf("native LLVM uncovered instructions: %v", missing)
	}
	if len(outside) > 0 {
		t.Logf("LLVM forms outside this source catalog's mnemonic/mode vocabulary (not counted as corpus coverage): %v", outside)
	}
	output := os.Getenv("MKASM_X86_REFERENCE_RUST")
	if output == "" {
		output = t.TempDir()
	}
	if cli := os.Getenv("MKASM_REFERENCE_CLI"); cli != "" {
		cmd := exec.Command(cli, "--arch", "x86_64", "--codegen", "rust", "--output", output, database)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("fresh CLI full x86 corpus: %v\n%s", err, out)
		}
	} else if err := GenerateRust(c, output); err != nil {
		t.Fatal(err)
	}
	if err := testreference.StandaloneRust(output); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(output, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "tests", "llvm.tsv"), []byte(corpus.String()), 0644); err != nil {
		t.Fatal(err)
	}
	consumer := fmt.Sprintf(`use x86_64::*;
#[test]fn native_llvm_corpus(){let mut count=0;
for line in include_str!("llvm.tsv").lines(){
 let parts:Vec<_>=line.splitn(4,'\t').collect();let mode=match parts[0]{"16"=>Mode::Mode16,"32"=>Mode::Mode32,"64"=>Mode::Mode64,_=>panic!()};
 let hex=parts[1];let bytes:Vec<u8>=(0..hex.len()).step_by(2).map(|i|u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect();
 let d=decode(&bytes,mode).unwrap_or_else(|e|panic!("{line}: {e:?}"));assert_eq!(d.length as usize,bytes.len(),"{line}");
 let editable=FormInstruction::decode(&bytes,mode).unwrap();let mut actual=[0u8;15];let n=editable.encode(&mut actual).unwrap_or_else(|e|panic!("{line}: {e:?}"));assert_eq!(&actual[..n],bytes,"{line}");
 count+=1;
}assert_eq!(count,%d);}
`, count)
	if err := os.WriteFile(filepath.Join(output, "tests", "llvm_corpus.rs"), []byte(consumer), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "llvm_corpus", "--quiet")
	cmd.Dir = output
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh full-corpus Rust native LLVM consumer: %v\n%s", err, out)
	}
	t.Logf("%d live LLVM instruction vectors through Go and a fresh %d-form Rust consumer; 16/32/64-bit, legacy, VEX and EVEX", count, len(c.Encodings))
}
