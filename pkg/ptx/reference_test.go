package ptx

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The explicit argv supports native ptxas and an installed Linux container.
// No shell interpolation or CUDA driver/GPU is involved.
func TestIndependentNVIDIAAssembler(t *testing.T) {
	configured := os.Getenv("MKASM_PTX_VALIDATOR")
	if configured == "" {
		t.Skip("set MKASM_PTX_VALIDATOR to a JSON argv array invoking NVIDIA ptxas with stdin input")
	}
	var command []string
	if err := json.Unmarshal([]byte(configured), &command); err != nil || len(command) == 0 || command[0] == "" {
		t.Fatalf("MKASM_PTX_VALIDATOR must be a nonempty JSON argv array: %v", err)
	}
	var rustSource strings.Builder
	rustSource.WriteString("use mkasm_ptx::*;\n#[test]fn independent_nvidia_ptxas(){\n")
	rustOutput := os.Getenv("MKASM_PTX_REFERENCE_RUST")
	if rustOutput != "" {
		if err := Default().GenerateRust(rustOutput); err != nil {
			t.Fatal(err)
		}
	}
	for _, filename := range []string{"clang-sm80.ptx", "clang-sm90-debug.ptx", "ptx95.ptx"} {
		t.Run(filename, func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join("testdata", filename))
			if err != nil {
				t.Fatal(err)
			}
			module, err := Decode(string(source))
			if err != nil {
				t.Fatal(err)
			}
			arguments := append([]string(nil), command[1:]...)
			for n := range arguments {
				arguments[n] = strings.ReplaceAll(arguments[n], "{target}", module.Targets[0])
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			validation, err := Default().ValidateWith(ctx, module, Profile{}, command[0], arguments...)
			if err != nil || !validation.SemanticComplete {
				t.Fatalf("NVIDIA rejected original %s: %+v %v", filename, validation, err)
			}
			// Exercise the public source writer and parser before the external
			// validator, rather than only checking a retained source fixture.
			var rebuilt strings.Builder
			if err := module.Write(&rebuilt); err != nil {
				t.Fatal(err)
			}
			copy, err := Decode(rebuilt.String())
			if err != nil {
				t.Fatal(err)
			}
			validation, err = Default().ValidateWith(ctx, copy, Profile{}, command[0], arguments...)
			if err != nil || !validation.SemanticComplete {
				t.Fatalf("NVIDIA rejected rebuilt %s: %v", filename, err)
			}
			bad := strings.Replace(rebuilt.String(), "ret;", "mov.u32 %undeclared_reference_register, 1;\nret;", 1)
			if filename == "ptx95.ptx" {
				bad = strings.Replace(rebuilt.String(), "sin.approx.2pi.ftz.f32", "sin.approx.2pi.f32", 1)
			}
			if bad == rebuilt.String() {
				t.Fatal("negative fixture mutation did not apply")
			}
			invalid, err := Decode(bad)
			if err != nil {
				t.Fatalf("negative fixture must reach the primary semantic validator: %v", err)
			}
			validation, err = Default().ValidateWith(ctx, invalid, Profile{}, command[0], arguments...)
			if err == nil || validation.SemanticComplete {
				t.Fatalf("NVIDIA admitted invalid %s", filename)
			}
			fmt.Fprintf(&rustSource, "{let source=include_str!(%s);let m=decode(source).unwrap();let args=%s;assert!(validate_with(&m,&Profile::default(),%s,args).unwrap().semantic_complete);let rebuilt=decode(m.encode()).unwrap();assert!(validate_with(&rebuilt,&Profile::default(),%s,args).unwrap().semantic_complete);let bad=%s;let invalid=decode(bad).unwrap();assert!(validate_with(&invalid,&Profile::default(),%s,args).is_err());}\n", rust("fixtures/"+filename), rustStrings(arguments), rust(command[0]), rust(command[0]), rust(bad), rust(command[0]))
			t.Logf("NVIDIA ptxas: original and rebuilt module accepted, invalid module rejected; %d instructions", len(module.Instructions))
		})
	}
	rustSource.WriteString("}\n")
	if rustOutput != "" {
		if err := os.WriteFile(filepath.Join(rustOutput, "tests", "nvidia_reference.rs"), []byte(rustSource.String()), 0644); err != nil {
			t.Fatal(err)
		}
	}
}
