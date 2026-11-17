package wasm

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func corpus(t *testing.T, arch string) *Catalog {
	t.Helper()
	f, e := os.Open("testdata/wasm-opcodes.json")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	c, e := Parse(f, arch)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Opcodes) != 626 {
		t.Fatalf("got %d upstream opcode records", len(c.Opcodes))
	}
	return c
}
func values(o Opcode) []Value { return representativeValues(o) }
func TestCorpusRoundtrip(t *testing.T) {
	for _, arch := range []string{"wasm32", "wasm64"} {
		c := corpus(t, arch)
		for _, o := range c.Opcodes {
			t.Run(arch+"/"+o.ID, func(t *testing.T) {
				b, e := c.Encode(o.ID, values(o))
				if e != nil {
					t.Fatal(e)
				}
				i, e := c.Decode(b)
				if e != nil {
					t.Fatal(e)
				}
				if i.Opcode.ID != o.ID || i.Length != len(b) {
					t.Fatalf("decoded %s/%d want %s/%d", i.Opcode.ID, i.Length, o.ID, len(b))
				}
				text := i.Format()
				again, e := c.Assemble(text)
				if e != nil {
					t.Fatalf("%s: %v", text, e)
				}
				if !bytes.Equal(b, again) {
					t.Fatalf("%s: %x != %x", text, b, again)
				}
				for n := 0; n < len(b); n++ {
					if _, e = c.Decode(b[:n]); e == nil {
						t.Fatalf("accepted truncated %s at byte %d", o.ID, n)
					}
				}
			})
		}
	}
}
func TestBinaryEdges(t *testing.T) {
	c := corpus(t, "wasm64")
	tests := []struct {
		id  string
		v   []Value
		hex string
	}{{"I32Const", []Value{S(-1)}, "417f"}, {"I32Const", []Value{S(math.MinInt32)}, "418080808078"}, {"I64Const", []Value{S(math.MinInt64)}, "428080808080808080807f"}, {"Block", []Value{T("empty")}, "0240"}, {"Block", []Value{U(0xffffffff)}, "02ffffffff0f"}, {"BrTable", []Value{L(U(1), U(128), U(0))}, "0e0201800100"}, {"I8x16RelaxedSwizzle", nil, "fd8002"}, {"MemorySize", []Value{U(128)}, "3f8001"}, {"I32Load", []Value{L(U(2), U(1<<40), U(3))}, "284203808080808020"}}
	for _, tt := range tests {
		t.Run(tt.id+tt.hex, func(t *testing.T) {
			b, e := c.Encode(tt.id, tt.v)
			if e != nil {
				t.Fatal(e)
			}
			if hex.EncodeToString(b) != tt.hex {
				t.Fatalf("got %x want %s", b, tt.hex)
			}
			if _, e := c.Decode(b); e != nil {
				t.Fatal(e)
			}
		})
	}
	// Valid overlong LEBs are accepted and normalized when encoded again.
	i, e := c.Decode([]byte{0x41, 0xff, 0x7f})
	if e != nil {
		t.Fatal(e)
	}
	b, e := c.Encode(i.Opcode.ID, i.Operands)
	if e != nil || hex.EncodeToString(b) != "417f" {
		t.Fatal(b, e)
	}
	for _, h := range []string{"418080808010", "418080808008", "4280808080808080808002", "fdffffffff10", "fe0301", "fd1510", "0effffffff0f", "286000", "d08080808010", "fb1804007070"} {
		b, _ := hex.DecodeString(h)
		if _, e := c.Decode(b); e == nil {
			t.Errorf("accepted malformed %s", h)
		}
	}
	if _, e := corpus(t, "wasm32").Encode("I32Load", []Value{L(U(2), U(1<<40), U(0))}); e == nil {
		t.Fatal("wasm32 accepted 64-bit offset")
	}
	if _, e := c.Encode("I8x16ExtractLaneS", []Value{U(16)}); e == nil {
		t.Fatal("accepted invalid lane")
	}
	if _, e := c.Encode("I32Const", []Value{S(1 << 31)}); e == nil {
		t.Fatal("accepted overflowing i32")
	}
}
func TestTemplateAndSequence(t *testing.T) {
	c := corpus(t, "wasm32")
	tmpl, e := c.Template("I32Const")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = tmpl.Encode(); e == nil {
		t.Fatal("accepted unset template")
	}
	if e = tmpl.Set("value", S(-17)); e != nil {
		t.Fatal(e)
	}
	b, e := tmpl.Encode()
	if e != nil {
		t.Fatal(e)
	}
	all, e := c.AssembleReader(strings.NewReader(";; comment\ni32.const -17\nnop\n"))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(all, append(b, 1)) {
		t.Fatalf("bad sequence %x", all)
	}
	inst, e := c.Disassemble(all)
	if e != nil || len(inst) != 2 {
		t.Fatal(inst, e)
	}
}
func TestIndependentWasmTools(t *testing.T) {
	tool := os.Getenv("WASM_ORACLE")
	if tool == "" {
		t.Skip("set WASM_ORACLE to the wasm-tools corpus oracle binary")
	}
	for _, arch := range []string{"wasm32", "wasm64"} {
		t.Run(arch, func(t *testing.T) { verifyIndependentWasmTools(t, tool, corpus(t, arch)) })
	}
}

func verifyIndependentWasmTools(t *testing.T, tool string, c *Catalog) {
	t.Helper()
	var input strings.Builder
	expected := map[string]string{}
	for _, o := range c.Opcodes {
		b, e := c.Encode(o.ID, values(o))
		if e != nil {
			t.Fatal(e)
		}
		h := hex.EncodeToString(b)
		expected[o.ID] = h
		fmt.Fprintf(&input, "%s %s\n", o.ID, h)
	}
	cmd := exec.Command(tool)
	cmd.Stdin = strings.NewReader(input.String())
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("oracle: %v\n%s", e, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != len(expected) {
		t.Fatalf("oracle returned %d lines want %d\n%s", len(lines), len(expected), out)
	}
	for _, line := range lines {
		parts := strings.SplitN(line, " ", 3)
		if len(parts) != 3 || parts[0] == "ERR" {
			t.Error(line)
			continue
		}
		if expected[parts[0]] != parts[1] {
			t.Errorf("independent %s: got %s want %s", parts[0], parts[1], expected[parts[0]])
		}
		delete(expected, parts[0])
	}
	if len(expected) != 0 {
		t.Errorf("unverified opcode count %d", len(expected))
	}
	t.Logf("%s: wasmparser + wasm-encoder independently decoded and emitted all %d opcode forms", c.Architecture, len(c.Opcodes))
}
func TestGeneratedRust(t *testing.T) {
	if _, e := exec.LookPath("cargo"); e != nil {
		t.Skip("cargo unavailable")
	}
	for _, arch := range []string{"wasm32", "wasm64"} {
		t.Run(arch, func(t *testing.T) { testGeneratedRust(t, corpus(t, arch)) })
	}
}

func testGeneratedRust(t *testing.T, c *Catalog) {
	dir := t.TempDir()
	if e := c.GenerateRust(dir); e != nil {
		t.Fatal(e)
	}
	const consumerTests = `
#[cfg(test)] mod consumer_tests { use super::*;
#[test]fn negative_boundaries(){for(id,n)in[("I32Const",i32::MIN as i64),("I64Const",i64::MIN)]{let b=encode(id,&[Value::I(n)]).unwrap();let i=decode(&b).unwrap();assert_eq!(i.operands,vec![Value::I(n)]);assert_eq!(assemble(&i.to_string()).unwrap(),b)};assert_eq!(assemble("i32.const\t0xff").unwrap(),encode("I32Const",&[Value::I(255)]).unwrap());assert!(decode(&[0xd0,0x65,0x65,0x70]).is_err());}
}
`

	path := filepath.Join(dir, "src", "lib.rs")
	f, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.WriteString(consumerTests)
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command("cargo", "test", "--manifest-path", filepath.Join(dir, "Cargo.toml"), "--lib")
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("generated Rust: %v\n%s", e, out)
	}
}

func TestIndependentWATModules(t *testing.T) {
	tool := os.Getenv("WASM_ORACLE")
	if tool == "" {
		t.Skip("set WASM_ORACLE to the wasm-tools corpus oracle")
	}
	cases := []struct{ name, arch, wat, text string }{
		{"memory", "wasm32", `(module (memory 1) (func (result i32) i32.const 0 i32.load offset=16 align=4 i32.const 1 i32.add))`, "i32.const 0\ni32.load [[2,16,0]]\ni32.const 1\ni32.add\nend"},
		{"simd", "wasm32", `(module (func (result i32) v128.const i8x16 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 i8x16.extract_lane_u 4))`, "v128.const [[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]]\ni8x16.extract_lane_u [4]\nend"},
		{"gc", "wasm32", `(module (type $s (struct (field i32))) (func (result (ref $s)) i32.const 7 struct.new $s))`, "i32.const 7\nstruct.new [0]\nend"},
		{"memory64", "wasm64", `(module (memory i64 1) (func (result i32) i64.const 0 i32.load offset=1099511627776))`, "i64.const 0\ni32.load [[2,1099511627776,0]]\nend"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := corpus(t, tt.arch)
			want, e := c.AssembleReader(strings.NewReader(tt.text))
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(tool, "--wat")
			cmd.Stdin = strings.NewReader(tt.wat)
			out, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatalf("independent WAT/module validator: %v\n%s", e, out)
			}
			got, e := hex.DecodeString(strings.TrimSpace(string(out)))
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("codec %x != independently assembled/validated module body %x", want, got)
			}
		})
	}
}
func rustBytes(b []byte) string {
	var s []string
	for _, v := range b {
		s = append(s, fmt.Sprintf("%d", v))
	}
	return "[" + strings.Join(s, ",") + "]"
}
