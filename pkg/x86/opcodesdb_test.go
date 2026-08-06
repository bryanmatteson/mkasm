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
       {"bitdiffs":{"fields":[{"name":"MOD","value":"REG"}]},"syntax":{"mnem":"ADD","text":"ADD REG REG","ast":[{"type":"REG","symbol":"GPR64","encodedin":"RM","datatype":"SINT","size":64,"read":1,"write":1,"conditional_reading":1},{"type":"REG","symbol":"GPR64","encodedin":"REG","read":1,"suppressed":1,"zeroing":1,"conditional_writing":1}]}},
       {"bitdiffs":{"fields":[{"name":"MOD","value":"MEM"}]},"syntax":{"mnem":"ADD","text":"ADD MEM REG","ast":[{"type":"MEM","encodedin":"RM"},{"type":"REG","encodedin":"REG"}]}}
     ]},
    {"id":"VPADDD", "rectype":"ENCODING",
     "diagram":{"fields":[{"name":"ENC","value":"VEX"},{"name":"MAP","value":"0f"},{"name":"MR","value":"1"},{"name":"OP","value":"0xfe"},{"name":"P66","value":"1"},{"name":"PF2","value":"0"},{"name":"PF3","value":"0"},{"name":"VL","value":"256"}]},
     "templates":[{"bitdiffs":{"fields":[{"name":"MOD","value":"REG"},{"name":"W","value":"0"}]},"metadata":{"tuple":"FV"},"syntax":{"mnem":"VPADDD","text":"VPADDD YMM YMM YMM","ast":[]}}]}
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
	if got := len(reg.Operands); got != 2 {
		t.Fatalf("register form has %d operands, want 2", got)
	}
	first, second := reg.Operands[0], reg.Operands[1]
	if first.Type != "REG" || first.Symbol != "GPR64" || first.EncodedIn != "RM" ||
		first.DataType != "SINT" || first.Size != "64" || !first.Read || !first.Write || !first.ConditionalRead {
		t.Fatalf("bad first operand: %+v", first)
	}
	if !second.Read || !second.Suppressed || !second.Zeroing || !second.ConditionalWrite {
		t.Fatalf("bad second operand access: %+v", second)
	}
	if mem.Mod != ModMemory {
		t.Fatalf("bad memory form: %+v", mem)
	}
	if vex.Kind != EncodingVEX || vex.Map != Map0F || vex.MandatoryPrefix != Prefix66 || vex.PrefixMask != 7 || vex.PrefixValue != 1 || vex.Tuple != "FV" {
		t.Fatalf("bad VEX form: %+v", vex)
	}
}

func TestParseOpcodesDBRejectsWrongArchitecture(t *testing.T) {
	_, err := ParseOpcodesDB(strings.NewReader(`{"version":"3","arch":"aarch64"}`))
	if err == nil || !strings.Contains(err.Error(), "not x86") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseOpcodesDBPacksIS4AndIBIntoOneTailByte(t *testing.T) {
	input := `{"version":"3","arch":"x86","records":[{
		"id":"VPERMIL2PD","rectype":"ENCODING",
		"diagram":{"fields":[{"name":"ENC","value":"VEX"},{"name":"MAP","value":"0f3a"},{"name":"MR","value":"1"},{"name":"OP","value":"0x49"}]},
		"templates":[{"syntax":{"mnem":"VPERMIL2PD","text":"VPERMIL2PD","ast":[
			{"type":"VREG","symbol":"XMMREG","encodedin":"IS4"},
			{"type":"CTL","symbol":"CTL","encodedin":"IB","size":8}
		]}}]
	}]}`
	cat, err := ParseOpcodesDB(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Encodings) != 1 || len(cat.Encodings[0].Tail) != 1 || cat.Encodings[0].Tail[0] != Tail8 {
		t.Fatalf("packed IS4/IB tail = %+v, want one Tail8", cat.Encodings)
	}
}

func TestParseOpcodesDBKeepsExpandedOpcodeRegisterFormsExact(t *testing.T) {
	input := `{"version":"3","arch":"x86","records":[{
		"id":"MOV_ovuv_1","rectype":"ENCODING",
		"diagram":{"fields":[{"name":"OP","value":"0xb8"}]},
		"templates":[{"syntax":{"mnem":"MOV","text":"MOV","ast":[
			{"type":"REG","symbol":"GPRv","encodedin":"OPCODE"},
			{"type":"IMM","symbol":"SIMM","encodedin":"IV"}
		]}}]
	}]}`
	cat, err := ParseOpcodesDB(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if cat.Encodings[0].OpcodePlusReg {
		t.Fatal("opcodesDB's already-expanded opcode register form was treated as a +r range")
	}
}

func TestParseOpcodesDBPreservesLegacyOperandSizeSelection(t *testing.T) {
	input := `{"version":"3","arch":"x86","records":[{
		"id":"MOVNTI","rectype":"ENCODING",
		"diagram":{"fields":[{"name":"MAP","value":"0f"},{"name":"MR","value":"1"},{"name":"MOD","value":"MEM"},{"name":"OP","value":"0xc3"},{"name":"P66","value":"0"}]},
		"templates":[
			{"bitdiffs":{"fields":[{"name":"OSZ","value":"64"}]},"syntax":{"mnem":"MOVNTI","text":"MOVNTI64","ast":[]}},
			{"bitdiffs":{"fields":[{"name":"OSZ","value":"Z"}]},"syntax":{"mnem":"MOVNTI","text":"MOVNTI32","ast":[]}}
		]
	}]}`
	cat, err := ParseOpcodesDB(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	wide, ordinary := cat.Encodings[0], cat.Encodings[1]
	if wide.OperandSize != 64 || wide.PrefixMask&1 != 0 {
		t.Fatalf("64-bit form lost OSZ semantics: %+v", wide)
	}
	if ordinary.OperandSize != 0 || ordinary.W != BitZero || ordinary.PrefixMask&1 != 0 {
		t.Fatalf("Z-sized form lost OSZ semantics: %+v", ordinary)
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
