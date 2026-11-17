package cil

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Compile and execute the actual .NET emitter on every invocation. The retained
// oracle remains useful offline, but is not substituted for a live reference.
func TestIndependentRuntimeEmission(t *testing.T) {
	dotnet, err := exec.LookPath("dotnet")
	if err != nil {
		t.Skip(".NET SDK unavailable: ", err)
	}
	dir := t.TempDir()
	for _, name := range []string{"Program.cs", "Oracle.csproj", "global.json"} {
		body, err := os.ReadFile(filepath.Join("testdata", "oracle", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0644); err != nil {
			t.Fatal(err)
		}
	}
	output := filepath.Join(dir, "out")
	build := exec.Command(dotnet, "build", "Oracle.csproj", "-c", "Release", "-o", output, "--nologo", "-v:q")
	build.Dir = dir
	if log, err := build.CombinedOutput(); err != nil {
		t.Fatalf("compile independent .NET emitter: %v\n%s", err, log)
	}
	data, err := exec.Command(dotnet, filepath.Join(output, "Oracle.dll")).Output()
	if err != nil {
		t.Fatalf("execute independent .NET emitter: %v", err)
	}
	var live oracle
	if err := json.Unmarshal(data, &live); err != nil {
		t.Fatal(err)
	}
	if len(live.Encodings) != 218 {
		t.Fatalf(".NET emitted %d opcode cases, want 218", len(live.Encodings))
	}
	verifyRuntimeOracle(t, live)
	verifyMethodOracle(t, live)
	if output := os.Getenv("MKASM_CIL_REFERENCE_RUST"); output != "" {
		if err := Default().GenerateRust(output); err != nil {
			t.Fatal(err)
		}
		var rust strings.Builder
		rust.WriteString("use mkasm_cil::*;\nfn hex(s:&str)->Vec<u8>{s.as_bytes().chunks_exact(2).map(|p|u8::from_str_radix(std::str::from_utf8(p).unwrap(),16).unwrap()).collect()}\n#[test]fn independent_live_dotnet_opcodes(){\n")
		for _, row := range live.Encodings {
			fmt.Fprintf(&rust, "for offset in [0,65536]{let bytes=hex(%q);let d=decode(&bytes,offset).unwrap();assert_eq!(d.opcode,%d);assert_eq!(encode(&d,offset).unwrap(),bytes);assert_eq!(assemble(&format(&d).unwrap(),offset).unwrap(),bytes);}\n", row.Bytes, row.Code)
		}
		rust.WriteString("}\n#[test]fn independent_live_dotnet_method_bodies(){\n")
		for _, method := range live.Methods {
			fmt.Fprintf(&rust, "{let bytes=hex(%q);let body=decode_method_body(&bytes).unwrap();assert_eq!(encode_method_body(&body).unwrap(),bytes);}\n", method.Body)
		}
		rust.WriteString("}\n")
		if err := os.WriteFile(filepath.Join(output, "tests", "live_dotnet_reference.rs"), []byte(rust.String()), 0644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf(".NET %s: all %d opcode encodings and stack/flow descriptors, %d compiler-produced methods, live prefix execution verified", live.Runtime, len(live.Encodings), len(live.Methods))
}
