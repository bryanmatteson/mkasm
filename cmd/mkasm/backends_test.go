package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchitectureRegistryAndAliases(t *testing.T) {
	for name, want := range map[string]string{"i386": "x86_32", "rv64": "riscv64", "ebpf": "bpfel", "ppc64le": "powerpc64le", "mipsel": "mips32el", "la32": "loongarch32", "webassembly": "wasm32", "java": "jvm", "spir-v": "spirv", "sparcv9": "sparc64", "arc": "arc32", "arceb": "arc32be", "dotnet": "cil", "65c02": "mos6502", "xtensael": "xtensa", "xtensabe": "xtensaeb"} {
		if got := canonicalArchitecture(name); got != want {
			t.Fatalf("%s => %s", name, got)
		}
	}
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--list-architectures"}, nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"avr", "bpfel", "riscv64", "mips32", "mips16", "mips16el", "mips16-64", "mips16-64el", "loongarch64", "powerpc64", "x86_32", "amdgpu", "ptx", "pic12", "pic14", "pic18", "pic24", "dspic33c"} {
		if !strings.Contains(out.String(), name+"\n") {
			t.Fatalf("registry missing %s", name)
		}
	}
}

func TestMOS6502CLIProfileGeneration(t *testing.T) {
	path := filepath.Join("..", "..", "pkg", "mos6502", "testdata", "opcodes.c")
	for profile, count := range map[string]int{"6502": 151, "6502x": 256, "65sc02": 178, "65c02": 210, "w65c02": 212, "w65c02+nops": 256} {
		var out bytes.Buffer
		if err := run(context.Background(), []string{"--arch", "mos6502", "--cpu", profile, "--json", path}, nil, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		var catalog struct{ Encodings []any }
		if err := json.Unmarshal(out.Bytes(), &catalog); err != nil || len(catalog.Encodings) != count {
			t.Fatalf("%s: count %d, expected %d, err %v", profile, len(catalog.Encodings), count, err)
		}
		if err := run(context.Background(), []string{"--arch", "mos6502", "--cpu", profile, "--codegen", "rust", "--output", t.TempDir(), path}, nil, io.Discard, io.Discard); err != nil {
			t.Fatalf("%s Rust generation: %v", profile, err)
		}
	}
}

func TestXtensaCLIProfileSelectsScalarAndBundleTables(t *testing.T) {
	path := filepath.Join("..", "..", "pkg", "xtensa", "testdata", "llvm.json")
	for _, arch := range []string{"xtensa", "xtensaeb"} {
		var out bytes.Buffer
		if err := run(context.Background(), []string{"--arch", arch, "--cpu", "esp32", "--json", path}, nil, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		var catalog struct {
			Architecture string
			Instructions struct{ Encodings []any }
			Slots        struct{ Encodings []any }
		}
		if err := json.Unmarshal(out.Bytes(), &catalog); err != nil {
			t.Fatal(err)
		}
		if catalog.Architecture != arch || len(catalog.Instructions.Encodings) == 0 || len(catalog.Slots.Encodings) != 0 {
			t.Fatal("CPU selection retained unavailable FLIX slots")
		}
		if err := run(context.Background(), []string{"--arch", arch, "--cpu", "esp32", "--codegen", "rust", "--output", t.TempDir(), path}, nil, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLegacyCPUStreamCLI(t *testing.T) {
	for _, tc := range []struct {
		arch, pkg, source string
		count             int
	}{
		{"mcs51", "mcs51", "8051_main.sinc", 120},
		{"mcs80390", "mcs51", "8051_main.sinc", 120},
		{"z80", "z80", "z80.lst", 1446},
		{"z180", "z80", "z80.lst", 732},
	} {
		var out bytes.Buffer
		path := filepath.Join("..", "..", "pkg", tc.pkg, "data", tc.source)
		if err := run(context.Background(), []string{"--arch", tc.arch, "--strict-corpus", "--json", path}, nil, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		var catalog struct {
			Architecture string
			Encodings    []any
		}
		if err := json.Unmarshal(out.Bytes(), &catalog); err != nil {
			t.Fatal(err)
		}
		if catalog.Architecture != tc.arch || len(catalog.Encodings) != tc.count {
			t.Fatalf("%s CLI exported %s with %d forms", tc.arch, catalog.Architecture, len(catalog.Encodings))
		}
		dir := t.TempDir()
		if err := run(context.Background(), []string{"--arch", tc.arch, "--codegen", "rust", "--output", dir, path}, nil, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"src/lib.rs", "LICENSE", "Cargo.toml"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestModuleAndBytecodeCLI(t *testing.T) {
	for _, tc := range []struct{ arch, pkg, source string }{
		{"jvm", "jvm", "bytecodes.cpp"},
		{"dex", "dex", "dex_instruction_list.h"},
		{"wasm32", "wasm", "wasm-opcodes.json"},
		{"wasm64", "wasm", "wasm-opcodes.json"},
		{"spirv", "spirv", "spirv.core.grammar.json"},
		{"cil", "cil", "opcode.def"},
		{"ptx", "ptx", "registry.json"},
	} {
		t.Run(tc.arch, func(t *testing.T) {
			path := filepath.Join("..", "..", "pkg", tc.pkg, "testdata", tc.source)
			var out bytes.Buffer
			if err := run(context.Background(), []string{"--arch", tc.arch, "--json", path}, nil, &out, io.Discard); err != nil {
				t.Fatal(err)
			}
			var catalog struct{ Architecture, Schema string }
			if err := json.Unmarshal(out.Bytes(), &catalog); err != nil {
				t.Fatal(err)
			}
			if catalog.Architecture != tc.arch || catalog.Schema == "" {
				t.Fatalf("unexpected IR %+v", catalog)
			}
			dir := t.TempDir()
			if err := run(context.Background(), []string{"--arch", tc.arch, "--codegen", "rust", "--output", dir, path}, nil, io.Discard, io.Discard); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"Cargo.toml", "LICENSE", "src/lib.rs"} {
				if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			if err := run(context.Background(), []string{"--arch", tc.arch, "--cpu", "invalid", "--json", path}, nil, io.Discard, io.Discard); err == nil {
				t.Fatal("accepted CPU profile on bytecode backend")
			}
		})
	}
}

func TestM68kCLIProfileSelection(t *testing.T) {
	path := filepath.Join("..", "..", "pkg", "m68k", "testdata", "m68k-opc.c")
	for _, tc := range []struct{ arch, cpu string }{{"m68k", "68020+68881"}, {"coldfire", "isa-c"}} {
		var out bytes.Buffer
		if err := run(context.Background(), []string{"--arch", tc.arch, "--cpu", tc.cpu, "--json", path}, nil, &out, io.Discard); err != nil {
			t.Fatal(err)
		}
		var c struct {
			Architecture, CPU string
			Opcodes           []any
		}
		if err := json.Unmarshal(out.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		if c.Architecture != tc.arch || c.CPU != tc.cpu || len(c.Opcodes) == 0 {
			t.Fatalf("wrong profile %+v", c)
		}
	}
	if err := run(context.Background(), []string{"--arch", "m68k", "--cpu", "unknown", "--json", path}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("accepted unknown profile")
	}
}

func TestARCAndHexagonCLIConsumers(t *testing.T) {
	arcSource := filepath.Join("..", "..", "pkg", "arc", "testdata", "binutils244-arc.tar")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--arch", "arc", "--strict-corpus", "--json", arcSource}, nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"architecture":"arc32"`) || !strings.Contains(out.String(), `"pc_align_bits":2`) {
		t.Fatal("ARC CLI lost its canonical target or PCL alignment")
	}
	dir := t.TempDir()
	if err := run(context.Background(), []string{"--arch", "arc", "--codegen", "rust", "--output", dir, arcSource}, nil, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	if notice, err := os.ReadFile(filepath.Join(dir, "UPSTREAM-LICENSE")); err != nil || !bytes.Contains(notice, []byte("GNU GENERAL PUBLIC LICENSE")) {
		t.Fatalf("missing source license: %v", err)
	}
	hexagonSource := filepath.Join("..", "..", "pkg", "hexagon", "testdata", "hexagon.json")
	out.Reset()
	if err := run(context.Background(), []string{"--arch", "hexagon", "--cpu", "hexagonv5", "--json", hexagonSource}, nil, &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	var packet struct {
		Architecture string
		Words        struct{ Encodings []struct{ Features []string } }
		FeatureSets  map[string][]string `json:"feature_sets"`
	}
	if err := json.Unmarshal(out.Bytes(), &packet); err != nil {
		t.Fatal(err)
	}
	if packet.Architecture != "hexagon" || len(packet.Words.Encodings) == 0 {
		t.Fatal("missing packet catalog")
	}
	active := map[string]bool{}
	for _, feature := range packet.FeatureSets["hexagonv5"] {
		active[feature] = true
	}
	for _, e := range packet.Words.Encodings {
		for _, feature := range e.Features {
			if !active[feature] {
				t.Fatalf("CPU filter retained unavailable feature %s", feature)
			}
		}
	}
	if err := run(context.Background(), []string{"--arch", "hexagon", "--cpu", "unknown", "--json", hexagonSource}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("accepted unknown packet CPU")
	}
	if err := run(context.Background(), []string{"--arch", "hexagon", "--strict-corpus", "--json", hexagonSource}, nil, io.Discard, io.Discard); err == nil {
		t.Fatal("strict packet generation accepted unsupported records")
	}
}

func TestNativeCLIRealSourceAndCPUSelection(t *testing.T) {
	path := filepath.Join("..", "..", "pkg", "avr", "testdata", "avr.json")
	source, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	var out, diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"--arch", "avr", "--cpu", "attiny40", "--strict-corpus", "--json", "-"}, bytes.NewReader(source), &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var c struct {
		Architecture string
		Encodings    []struct{ ID string }
		Unsupported  []any
	}
	if err := json.Unmarshal(out.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if c.Architecture != "avr" || len(c.Encodings) == 0 || len(c.Unsupported) != 0 {
		t.Fatalf("catalog %+v", c)
	}
	dir := filepath.Join(t.TempDir(), "avr")
	if err := run(context.Background(), []string{"--arch", "avr", "--cpu", "atmega328p", "--codegen", "rust", "--output", dir, "-"}, bytes.NewReader(source), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Cargo.toml", "LICENSE", "src/lib.rs"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := run(context.Background(), []string{"--arch", "avr", "--cpu", "unknown", "--json", "-"}, bytes.NewReader(source), io.Discard, io.Discard); err == nil {
		t.Fatal("accepted unknown CPU")
	}
}

func TestX86_32JSONArchitecture(t *testing.T) {
	const source = `{"version":"3","arch":"x86","records":[{"id":"NOP","rectype":"ENCODING","diagram":{"fields":[{"name":"OP","value":"0x90"}]},"templates":[{"syntax":{"mnem":"NOP","text":"NOP","ast":[]}}]}]}`
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--arch", "i386", "--json", "-"}, strings.NewReader(source), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"architecture":"x86_32"`) {
		t.Fatal(out.String())
	}
	dir := t.TempDir()
	if err := run(context.Background(), []string{"--arch", "i386", "--codegen", "rust", "--output", dir, "-"}, strings.NewReader(source), io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
	if err != nil || !strings.Contains(string(manifest), `name = "x86_32"`) {
		t.Fatalf("32-bit crate identity: %s, %v", manifest, err)
	}
	lib, err := os.ReadFile(filepath.Join(dir, "src/lib.rs"))
	if err != nil || !strings.Contains(string(lib), "pub const DEFAULT_MODE: Mode = Mode::Mode32;") {
		t.Fatalf("32-bit default mode missing: %v", err)
	}
}
