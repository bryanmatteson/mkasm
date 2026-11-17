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

type upstreamNVIDIARun struct {
	Name, Source string
	LLC, PTXAS   []string
}

// Use every positive native-assembler RUN in the primary NVPTX corpus. The
// source's own compiler features and ptxas flags select each complete program;
// neither FileCheck output nor an adapter-invented PTX wrapper is an oracle.
func TestIndependentUpstreamNVIDIARuns(t *testing.T) {
	for _, name := range []string{"MKASM_LLVM_SOURCE", "MKASM_LLC", "MKASM_PTX_VALIDATOR", "MKASM_PTX_LEGACY_VALIDATOR", "MKASM_PTX_32_VALIDATOR", "MKASM_PTX_FERMI_VALIDATOR", "MKASM_REFERENCE_CLI"} {
		if os.Getenv(name) == "" {
			t.Skip("set " + name)
		}
	}
	generated := filepath.Join(t.TempDir(), "primary-ir")
	extract := exec.Command("python3", "testdata/upstream-runs.py", os.Getenv("MKASM_LLVM_SOURCE"), generated)
	data, err := extract.Output()
	if err != nil {
		t.Fatal("extract native upstream RUN cases", err)
	}
	var runs []upstreamNVIDIARun
	if err := json.Unmarshal(data, &runs); err != nil {
		t.Fatal(err)
	}
	if len(runs) < 594 {
		t.Fatalf("truncated primary native corpus: %d RUN cases, expected at least 594", len(runs))
	}
	output := os.Getenv("MKASM_PTX_UPSTREAM_RUST")
	if output == "" {
		output = t.TempDir()
	}
	generate := exec.Command(os.Getenv("MKASM_REFERENCE_CLI"), "--arch", "ptx", "--codegen", "rust", "--output", output, "testdata/registry.json")
	if out, err := generate.CombinedOutput(); err != nil {
		t.Fatalf("fresh CLI PTX generation: %v\n%s", err, out)
	}
	if err := testreference.StandaloneRust(output); err != nil {
		t.Fatal(err)
	}
	fixtures := filepath.Join(output, "tests", "upstream")
	if err := os.MkdirAll(fixtures, 0755); err != nil {
		t.Fatal(err)
	}
	type result struct {
		Count          int
		Rust           string
		Opcodes        []string
		NativeRejected bool
	}
	results := make([]result, len(runs))
	workers := make(chan struct{}, 4)
	t.Run("native_go", func(t *testing.T) {
		for i, run := range runs {
			t.Run(run.Name, func(t *testing.T) {
				t.Parallel()
				workers <- struct{}{}
				defer func() { <-workers }()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				args := append(append([]string{}, run.LLC...), run.Source, "-o", "-")
				cmd := exec.CommandContext(ctx, os.Getenv("MKASM_LLC"), args...)
				var diagnostics strings.Builder
				cmd.Stderr = &diagnostics
				body, err := cmd.Output()
				if err != nil {
					t.Fatalf("native LLVM %v: %v\n%s", args, err, diagnostics.String())
				}
				module, err := Decode(string(body))
				if err != nil {
					t.Fatalf("decode live LLVM output: %v", err)
				}
				if module.Encode() != string(body) {
					t.Fatal("Go codec changed native source")
				}
				command := upstreamNVIDIACommand(t, run.PTXAS, module)
				validation, err := Default().ValidateWith(ctx, module, Profile{}, command[0], command[1:]...)
				// LLVM combines its ptr32 and sm_90 feature probes in one RUN,
				// although NVIDIA explicitly rejects that ABI/target pair. Keep
				// the original program and require the actual native diagnostic
				// in both consumers, rather than skipping or rewriting the RUN.
				nativeRejected := module.AddressSize == 32 && hasFlag(module.Targets, "sm_90")
				if nativeRejected {
					if err == nil || validation.SemanticComplete || !strings.Contains(err.Error(), "32-Bit ABI") || !strings.Contains(err.Error(), "not supported on sm_90") {
						t.Fatalf("native ABI boundary changed: %+v %v", validation, err)
					}
				} else if err != nil || !validation.SemanticComplete {
					t.Fatalf("NVIDIA rejected Go output: %+v %v", validation, err)
				}
				name := run.Name + ".ptx"
				if err := os.WriteFile(filepath.Join(fixtures, name), body, 0644); err != nil {
					t.Fatal(err)
				}
				results[i].Count = len(module.Instructions)
				results[i].NativeRejected = nativeRejected
				for _, inst := range module.Instructions {
					results[i].Opcodes = append(results[i].Opcodes, inst.Opcode)
				}
				results[i].Rust = fmt.Sprintf("(%s,include_str!(%s),%d,%s,&%s[..],%t)", rust(run.Name), rust("upstream/"+name), len(module.Instructions), rust(command[0]), rustStrings(command[1:]), nativeRejected)
			})
		}
	})
	if t.Failed() {
		return
	}
	var rows []string
	total := 0
	rejected := 0
	opcodes := map[string]bool{}
	for _, r := range results {
		rows = append(rows, r.Rust)
		total += r.Count
		if r.NativeRejected {
			rejected++
		}
		for _, op := range r.Opcodes {
			opcodes[op] = true
		}
	}
	consumer := fmt.Sprintf(`use mkasm_ptx::*;
#[test]fn every_native_upstream_run(){
let cases=&[%s];
std::thread::scope(|scope|{for worker in 0..4{scope.spawn(move||{
 for &(name,source,count,command,args,rejected) in cases.iter().skip(worker).step_by(4){
  let m=decode(source).unwrap_or_else(|e|panic!("{name}: {e:?}"));
  assert_eq!(m.instructions.len(),count,"{name}");assert_eq!(m.encode(),source,"{name}");
  let rebuilt=decode(m.encode()).unwrap();
  let validation=validate_with(&rebuilt,&Profile::default(),command,args);
  if rejected {let e=validation.expect_err("NVIDIA admitted unsupported SM90/32-bit ABI");assert!(e.0.contains("32-Bit ABI")&&e.0.contains("not supported on sm_90"),"{name}: {e:?}");}
  else {assert!(validation.unwrap_or_else(|e|panic!("{name}: {e:?}")).semantic_complete);}
 }
});}});
assert_eq!(cases.iter().map(|r|r.2).sum::<usize>(),%d);
}
`, strings.Join(rows, ",\n"), total)
	if err := os.WriteFile(filepath.Join(output, "tests", "upstream_nvidia.rs"), []byte(consumer), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--test", "upstream_nvidia", "--quiet")
	cmd.Dir = output
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh CLI Rust -> NVIDIA upstream programs: %v\n%s", err, out)
	}
	t.Logf("all %d primary NVIDIA RUN cases, %d instructions, %d opcode/modifier spellings passed Go and fresh CLI Rust: %d native NVIDIA acceptances and %d native ABI rejections", len(runs), total, len(opcodes), len(runs)-rejected, rejected)
}

func upstreamNVIDIACommand(t *testing.T, flags []string, module *Module) []string {
	t.Helper()
	configured := "MKASM_PTX_VALIDATOR"
	if module.AddressSize == 32 {
		configured = "MKASM_PTX_32_VALIDATOR"
	}
	for _, flag := range flags {
		if flag == "-arch=sm_20" || flag == "-arch=sm_35" {
			configured = "MKASM_PTX_FERMI_VALIDATOR"
			break
		}
		if module.AddressSize != 32 && (flag == "-arch=sm_50" || flag == "-arch=sm_52" || flag == "-arch=sm_53" || flag == "-arch=sm_60" || flag == "-arch=sm_70" || flag == "-arch=sm_72" || strings.HasPrefix(flag, "-arch=sm_101")) {
			configured = "MKASM_PTX_LEGACY_VALIDATOR"
		}
	}
	var command []string
	if err := json.Unmarshal([]byte(os.Getenv(configured)), &command); err != nil || len(command) == 0 {
		t.Fatal("invalid NVIDIA argv", configured, err)
	}
	// Match LLVM's native RUN exactly: it explicitly selects an architecture
	// only where its ptxas invocation does. The normal validator's target
	// placeholder must not silently override that primary test contract.
	var result []string
	for i := 0; i < len(command); i++ {
		if command[i] == "-arch" || command[i] == "--gpu-name" {
			i++
			continue
		}
		if strings.HasPrefix(command[i], "-arch=") || strings.HasPrefix(command[i], "--gpu-name=") {
			continue
		}
		result = append(result, command[i])
	}
	result = append(append(result, "-c"), flags...)
	if module.AddressSize == 32 && !hasFlag(flags, "-m32") {
		result = append(result, "-m32")
	}
	return result
}

func hasFlag(flags []string, flag string) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}

func TestUpstreamNVIDIACommandSelection(t *testing.T) {
	for _, name := range []string{"MKASM_PTX_VALIDATOR", "MKASM_PTX_LEGACY_VALIDATOR", "MKASM_PTX_32_VALIDATOR", "MKASM_PTX_FERMI_VALIDATOR"} {
		encoded, _ := json.Marshal([]string{name, "-arch={target}", "-", "-o", "/dev/null"})
		t.Setenv(name, string(encoded))
	}
	for _, c := range []struct {
		flags []string
		width int
		want  string
	}{
		{nil, 64, "MKASM_PTX_VALIDATOR"},
		{nil, 32, "MKASM_PTX_32_VALIDATOR"},
		{[]string{"-m32"}, 32, "MKASM_PTX_32_VALIDATOR"},
		{[]string{"-arch=sm_20"}, 64, "MKASM_PTX_FERMI_VALIDATOR"},
		{[]string{"-arch=sm_35"}, 64, "MKASM_PTX_FERMI_VALIDATOR"},
		{[]string{"-arch=sm_60"}, 64, "MKASM_PTX_LEGACY_VALIDATOR"},
		{[]string{"-arch=sm_101a"}, 64, "MKASM_PTX_LEGACY_VALIDATOR"},
		{[]string{"-arch=sm_80"}, 32, "MKASM_PTX_32_VALIDATOR"},
		{[]string{"-arch", "sm_100"}, 64, "MKASM_PTX_VALIDATOR"},
	} {
		cmd := upstreamNVIDIACommand(t, c.flags, &Module{AddressSize: c.width})
		if cmd[0] != c.want || strings.Contains(strings.Join(cmd, " "), "{target}") {
			t.Fatalf("%v/%d: %v", c.flags, c.width, cmd)
		}
		count := 0
		for _, a := range cmd {
			if a == "-m32" {
				count++
			}
		}
		if c.width == 32 && count != 1 || c.width == 64 && count != 0 {
			t.Fatalf("incorrect native address width: %v", cmd)
		}
	}
}
