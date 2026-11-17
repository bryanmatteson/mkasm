package ptx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bryanmatteson/mkasm/internal/testreference"
)

// LLVM compiles independent upstream IR programs; NVIDIA validates complete
// modules after both public codecs read and write them. No instruction fragments
// are wrapped in invented declarations to make them appear vendor-validated.
func TestIndependentLLVMNVIDIACorpus(t *testing.T) {
	source, llc, configured := os.Getenv("MKASM_LLVM_SOURCE"), os.Getenv("MKASM_LLC"), os.Getenv("MKASM_PTX_VALIDATOR")
	if source == "" || llc == "" || configured == "" {
		t.Skip("set MKASM_LLVM_SOURCE, MKASM_LLC and MKASM_PTX_VALIDATOR")
	}
	var command []string
	if err := json.Unmarshal([]byte(configured), &command); err != nil || len(command) == 0 {
		t.Fatal("invalid native NVIDIA argv", err)
	}
	// LLVM's callable-function tests intentionally retain extern declarations.
	// NVIDIA's relocatable object mode validates those complete modules without
	// requiring unrelated external function definitions at this compile stage.
	command = append(command, "-c")
	var legacy []string
	if err := json.Unmarshal([]byte(os.Getenv("MKASM_PTX_LEGACY_VALIDATOR")), &legacy); err != nil || len(legacy) == 0 {
		t.Skip("set MKASM_PTX_LEGACY_VALIDATOR to NVIDIA ptxas supporting legacy SM60")
	}
	legacy = append(legacy, "-c")
	output := os.Getenv("MKASM_PTX_CORPUS_RUST")
	if output == "" {
		output = t.TempDir()
	}
	if err := Default().GenerateRust(output); err != nil {
		t.Fatal(err)
	}
	if err := testreference.StandaloneRust(output); err != nil {
		t.Fatal(err)
	}
	fixtureDir := filepath.Join(output, "tests", "native-corpus")
	if err := os.MkdirAll(fixtureDir, 0755); err != nil {
		t.Fatal(err)
	}
	var fixtures []string
	total := 0
	for _, file := range []string{
		"arithmetic-int.ll", "arithmetic-fp-sm20.ll", "atomics.ll", "atomics-sm60.ll", "atomics-sm70.ll", "atomics-sm90.ll", "atomics-b128.ll", "atomics-with-scope.ll",
		"barrier.ll", "bf16-instructions.ll", "bf16x2-instructions.ll", "bfe.ll", "fma.ll", "fma-assoc.ll", "fma-relu-fma-intrinsic.ll", "funnel-shift-clamp.ll",
		"ldg-invariant.ll", "load-store-scalars.ll", "load-store-vectors.ll", "load-store-sm-70.ll", "load-store-sm-90.ll",
		"match.ll", "prmt.ll", "rotate.ll", "rotate_64.ll", "shfl-p.ll", "shfl-sync-p.ll", "shfl-sync.ll", "shfl.ll",
		"vector-args.ll", "vector-call.ll", "vector-compare.ll", "vector-global.ll", "vector-loads.ll", "vector-returns.ll", "vector-select.ll", "vector-stores.ll",
	} {
		cpu, isa, validator := "sm_90", "+ptx85", command
		old := file == "shfl.ll" || file == "shfl-p.ll"
		if old {
			cpu, isa, validator = "sm_60", "+ptx60", legacy
		}
		cmd := exec.Command(llc, "-mtriple=nvptx64-nvidia-cuda", "-mcpu="+cpu, "-mattr="+isa, filepath.Join(source, "llvm", "test", "CodeGen", "NVPTX", file), "-o", "-")
		var diagnostics strings.Builder
		cmd.Stderr = &diagnostics
		body, err := cmd.Output()
		if err != nil {
			t.Fatalf("native LLVM %s: %v\n%s", file, err, diagnostics.String())
		}
		module, err := Decode(string(body))
		if err != nil {
			t.Fatalf("LLVM %s: %v", file, err)
		}
		var rewritten strings.Builder
		if err := module.Write(&rewritten); err != nil {
			t.Fatal(err)
		}
		if rewritten.String() != string(body) {
			t.Fatalf("%s: public writer did not preserve native LLVM source", file)
		}
		copy, err := Decode(rewritten.String())
		if err != nil {
			t.Fatal(err)
		}
		args := append([]string{}, validator[1:]...)
		for n := range args {
			args[n] = strings.ReplaceAll(args[n], "{target}", copy.Targets[0])
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		validation, err := Default().ValidateWith(ctx, copy, Profile{}, validator[0], args...)
		cancel()
		if err != nil || !validation.SemanticComplete {
			t.Fatalf("NVIDIA rejected LLVM %s after Go codec: %+v %v", file, validation, err)
		}
		name := strings.TrimSuffix(file, ".ll") + ".ptx"
		if err := os.WriteFile(filepath.Join(fixtureDir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, fmt.Sprintf("(%s,include_str!(%s),%d,%s,&%s[..])", rust(name), rust("native-corpus/"+name), len(copy.Instructions), rust(validator[0]), rustStrings(args)))
		total += len(copy.Instructions)
		t.Logf("LLVM -> Go -> NVIDIA: %s, %d instructions", file, len(copy.Instructions))
	}
	consumer := fmt.Sprintf(`use mkasm_ptx::*;
#[test]fn native_llvm_nvidia_corpus(){let mut count=0;
for (name,source,expected,command,args) in [%s] {
 let m=decode(source).unwrap_or_else(|e|panic!("{name}: {e:?}"));assert_eq!(m.instructions.len(),expected,"{name}");
 assert_eq!(m.encode(),source,"{name}");let rebuilt=decode(m.encode()).unwrap();
 assert!(validate_with(&rebuilt,&Profile::default(),command,args).unwrap_or_else(|e|panic!("{name}: {e:?}")).semantic_complete);
 count+=expected;
}assert_eq!(count,%d);}
`, strings.Join(fixtures, ","), total)
	if err := os.WriteFile(filepath.Join(output, "tests", "nvidia_corpus.rs"), []byte(consumer), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "nvidia_corpus", "--quiet")
	cmd.Dir = output
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh Rust -> NVIDIA corpus: %v\n%s", err, out)
	}
	t.Logf("%d independent LLVM programs, %d instructions; native NVIDIA acceptance after Go and fresh Rust codecs", len(fixtures), total)
}
