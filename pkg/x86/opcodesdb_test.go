package x86

import (
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const testOpcodesDB = `{
  "version":"3", "arch":"x86", "records":[
    {"id":"ADD_rm64_r64", "rectype":"ENCODING",
     "diagram":{"fields":[{"name":"MR","value":"1"},{"name":"OP","value":"0x01"},{"name":"MODE","value":"64"},{"name":"W","value":"1"}]},
     "templates":[
       {"bitdiffs":{"fields":[{"name":"MOD","value":"REG"}]},"syntax":{"mnem":"ADD","text":"ADD REG REG","ast":[{"type":"REG","encodedin":"RM"},{"type":"REG","encodedin":"REG"}]}},
       {"bitdiffs":{"fields":[{"name":"MOD","value":"MEM"}]},"syntax":{"mnem":"ADD","text":"ADD MEM REG","ast":[{"type":"MEM","encodedin":"RM"},{"type":"REG","encodedin":"REG"}]}}
     ]},
    {"id":"VPADDD", "rectype":"ENCODING",
     "diagram":{"fields":[{"name":"ENC","value":"VEX"},{"name":"MAP","value":"0f"},{"name":"MR","value":"1"},{"name":"OP","value":"0xfe"},{"name":"P66","value":"1"},{"name":"PF2","value":"0"},{"name":"PF3","value":"0"},{"name":"VL","value":"256"}]},
     "templates":[{"bitdiffs":{"fields":[{"name":"MOD","value":"REG"},{"name":"W","value":"0"}]},"syntax":{"mnem":"VPADDD","text":"VPADDD YMM YMM YMM","ast":[]}}]}
  ]
}`

func TestParseOpcodesDB(t *testing.T) {
	cat, err := ParseOpcodesDB(strings.NewReader(testOpcodesDB))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cat.Encodings); got != 3 {
		t.Fatalf("got %d forms, want 3", got)
	}
	reg, mem, vex := cat.Encodings[0], cat.Encodings[1], cat.Encodings[2]
	if reg.FormID != "ADD_rm64_r64/0" || reg.Mod != ModRegister || !reg.Modes.supports(Mode64) || reg.Modes.supports(Mode32) {
		t.Fatalf("bad register form: %+v", reg)
	}
	if mem.Mod != ModMemory {
		t.Fatalf("bad memory form: %+v", mem)
	}
	if vex.Kind != EncodingVEX || vex.Map != Map0F || vex.MandatoryPrefix != Prefix66 || vex.PrefixMask != 7 || vex.PrefixValue != 1 {
		t.Fatalf("bad VEX form: %+v", vex)
	}
}

func TestParseOpcodesDBRejectsWrongArchitecture(t *testing.T) {
	_, err := ParseOpcodesDB(strings.NewReader(`{"version":"3","arch":"aarch64"}`))
	if err == nil || !strings.Contains(err.Error(), "not x86") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOpcodesDBCorpus(t *testing.T) {
	path := os.Getenv("MKASM_X86_OPCODESDB")
	if path == "" {
		t.Skip("set MKASM_X86_OPCODESDB to an uncompressed opcodesDB v3 JSON file")
	}
	var input io.Reader = os.Stdin
	var command *exec.Cmd
	if path != "-" {
		if strings.HasSuffix(path, ".xz") {
			command = exec.Command("xz", "-dc", path)
			pipe, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			input = pipe
		} else {
			f, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			input = f
		}
	}
	cat, err := ParseOpcodesDB(input)
	if err != nil {
		t.Fatal(err)
	}
	if command != nil {
		if err := command.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	if len(cat.Encodings) < 3_000 {
		t.Fatalf("only %d forms imported", len(cat.Encodings))
	}
	decoder, err := NewDecoder(cat)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoder.candidates) < len(cat.Encodings) {
		t.Fatalf("dispatcher indexed %d candidates for %d forms", len(decoder.candidates), len(cat.Encodings))
	}
	for _, probe := range []struct {
		bytes    []byte
		mnemonic string
	}{
		{[]byte{0x90}, "NOP"},
		{[]byte{0x48, 0x01, 0xc8}, "ADD"},
		{[]byte{0xf3, 0x0f, 0x1e, 0xfa}, "ENDBR64"},
		{[]byte{0xc5, 0xed, 0xfe, 0xcb}, "VPADDD"},
		{[]byte{0x62, 0xf1, 0x7d, 0x48, 0xef, 0xc0}, "VPXORD"},
	} {
		decoded, err := decoder.Decode(probe.bytes, Mode64)
		if err != nil {
			t.Errorf("decode % x: %v", probe.bytes, err)
			continue
		}
		if got := decoded.Encoding(decoder).Mnemonic; got != probe.mnemonic {
			t.Errorf("decode % x = %s, want %s", probe.bytes, got, probe.mnemonic)
		}
	}
	t.Logf("imported and indexed %d x86 forms", len(cat.Encodings))
}
