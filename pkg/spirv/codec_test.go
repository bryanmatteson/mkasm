package spirv

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func grammar(t *testing.T) *Catalog {
	t.Helper()
	f, e := os.Open("testdata/spirv.core.grammar.json")
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	c, e := Parse(f, "spirv")
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Instructions) != 879 || len(c.OperandKinds) != 72 {
		t.Fatalf("incomplete grammar: %d instructions, %d kinds", len(c.Instructions), len(c.OperandKinds))
	}
	return c
}
func sampleOperand(c *Catalog, kind string, extended bool) Operand {
	o := Operand{Kind: kind}
	k := c.kinds[kind]
	switch {
	case kind == "LiteralString":
		o.Text = "hello π \\\""
	case k.Category == "Composite":
		for _, b := range k.Bases {
			o.Parameters = append(o.Parameters, sampleOperand(c, b, extended))
		}
	case k.Category == "Id":
		o.Words = []uint32{1}
	case k.Category == "BitEnum" || k.Category == "ValueEnum":
		e := k.Enumerants[0]
		o.Words = []uint32{e.Number}
		for _, s := range e.Parameters {
			if s.Quantifier == "" || extended {
				o.Parameters = append(o.Parameters, sampleOperand(c, s.Kind, extended))
			}
		}
	case kind == "LiteralSpecConstantOpInteger":
		o.Words = []uint32{128}
		o.Parameters = []Operand{sampleOperand(c, "IdRef", false), sampleOperand(c, "IdRef", false)}
	default:
		o.Words = []uint32{0}
	}
	return o
}
func sampleInstruction(c *Catalog, d InstructionDef, extended bool) Instruction {
	i := Instruction{Opcode: d.Opcode}
	for _, s := range d.Operands {
		if s.Quantifier != "" && !extended {
			continue
		}
		i.Operands = append(i.Operands, sampleOperand(c, s.Kind, extended))
		if extended && s.Quantifier == "*" {
			i.Operands = append(i.Operands, sampleOperand(c, s.Kind, extended))
		}
	}
	return i
}
func TestCompleteGrammar(t *testing.T) {
	c := grammar(t)
	for _, def := range c.Instructions {
		for _, extended := range []bool{false, true} {
			i := sampleInstruction(c, def, extended)
			b, e := c.Encode(i, nil, nil)
			if e != nil {
				t.Fatalf("%s: %v", def.Name, e)
			}
			decoded, n, e := c.Decode(b, nil, nil)
			if e != nil || n != len(b) || !equalOperands(i.Operands, decoded.Operands) {
				t.Fatalf("%s binary: %+v %v", def.Name, decoded, e)
			}
			text := c.Format(i)
			assembled, e := c.Assemble(text, nil, nil)
			if e != nil || !equalOperands(i.Operands, assembled.Operands) {
				t.Fatalf("%s text %q: %v", def.Name, text, e)
			}
			for _, alias := range def.Aliases {
				j, err := c.Assemble(strings.Replace(text, def.Name, alias, 1), nil, nil)
				if err != nil || !equalOperands(i.Operands, j.Operands) {
					t.Fatalf("alias %s: %v", alias, err)
				}
			}
		}
	}
	t.Logf("validated %d full grammar instruction forms", len(c.Instructions)*2)
}
func TestAllEnumerants(t *testing.T) {
	c := grammar(t)
	count := 0
	for _, k := range c.OperandKinds {
		for _, e := range k.Enumerants {
			o := Operand{Kind: k.Kind, Words: []uint32{e.Number}}
			for _, s := range e.Parameters {
				o.Parameters = append(o.Parameters, sampleOperand(c, s.Kind, true))
			}
			w, err := c.operandWords(o)
			if err != nil {
				t.Fatal(err)
			}
			got, n, err := (wordDecoder{c: c, switchWords: 1}).one(k.Kind, w, 0)
			if err != nil || n != len(w) || !equalOperands([]Operand{o}, []Operand{got}) {
				t.Fatalf("%s.%s: %+v %v", k.Kind, e.Name, got, err)
			}
			count++
		}
	}
	t.Logf("validated %d enum values and dependent parameter sets", count)
}
func TestMalformed(t *testing.T) {
	c := grammar(t)
	for _, b := range [][]byte{nil, {0, 0, 0, 0}, {0, 0, 2, 0}, {255, 255, 1, 0}, {5, 0, 3, 0, 1, 0, 0, 0, 65, 65, 65, 65}, {5, 0, 3, 0, 1, 0, 0, 0, 65, 0, 1, 0}} {
		if _, _, e := c.Decode(b, nil, nil); e == nil {
			t.Errorf("accepted malformed %x", b)
		}
	}
	for _, s := range []string{"OpName %0 \"x\"", "OpName %1 \"x\\u0000y\"", "OpLoad %1", "OpNop 9", "OpCapability 4294967295"} {
		if _, e := c.Assemble(s, nil, nil); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
func TestContextAndDependentParameters(t *testing.T) {
	c := grammar(t)
	ctx := NewContext()
	for _, line := range []string{"%1 = OpTypeInt 64 0", "%2 = OpConstant %1 18446744073709551615", "OpSwitch %2 %4 0x1122334455667788 %5", "%6 = OpSpecConstantOp %1 IAdd %2 %2", "%7 = OpLoad %1 %8 Aligned 16", "OpDecorate %1 LinkageAttributes \"x\" Export"} {
		i, e := c.Assemble(line, ctx, nil)
		if e != nil {
			t.Fatal(line, e)
		}
		b, e := c.Encode(i, ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		j, _, e := c.Decode(b, ctx, nil)
		if e != nil || !equalOperands(i.Operands, j.Operands) {
			t.Fatal(line, e)
		}
		ctx.Observe(i)
	}
	env := &Environment{Version: 0x10000, Capabilities: map[string]bool{}, Extensions: map[string]bool{}}
	if _, e := c.Assemble("%1 = OpTypeMatrix %2 4", nil, env); e == nil {
		t.Fatal("missing Matrix capability admitted")
	}
	env.Capabilities["Matrix"] = true
	if _, e := c.Assemble("%1 = OpTypeMatrix %2 4", nil, env); e != nil {
		t.Fatal(e)
	}
}

const moduleText = `OpCapability Shader
OpMemoryModel Logical GLSL450
OpEntryPoint GLCompute %4 "main"
OpExecutionMode %4 LocalSize 1 1 1
%1 = OpTypeVoid
%2 = OpTypeFunction %1
%4 = OpFunction %1 None %2
%5 = OpLabel
OpReturn
OpFunctionEnd
`

const wideModuleText = `OpCapability Shader
OpCapability Int64
OpCapability Float16
OpCapability Float64
OpMemoryModel Logical GLSL450
OpEntryPoint GLCompute %4 "main"
OpExecutionMode %4 LocalSize 1 1 1
%1 = OpTypeVoid
%2 = OpTypeFunction %1
%3 = OpTypeInt 64 0
%6 = OpConstant %3 0x1122334455667788
%10 = OpTypeFloat 16
%11 = OpConstant %10 1.5
%12 = OpTypeFloat 32
%13 = OpConstant %12 2.5
%14 = OpTypeFloat 64
%15 = OpConstant %14 3.5
%4 = OpFunction %1 None %2
%5 = OpLabel
OpSelectionMerge %9 None
OpSwitch %6 %7 0x1122334455667788 %8
%7 = OpLabel
OpBranch %9
%8 = OpLabel
OpBranch %9
%9 = OpLabel
OpReturn
OpFunctionEnd
`

func TestIndependentWideModule(t *testing.T) {
	tools := os.Getenv("MKASM_SPIRV_TOOLS")
	if tools == "" {
		t.Skip("set MKASM_SPIRV_TOOLS")
	}
	c := grammar(t)
	m, err := c.AssembleModule(wideModuleText, 0x10600, 0)
	if err != nil {
		t.Fatal(err)
	}
	own, err := c.EncodeModule(m)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source, binaryPath := filepath.Join(dir, "wide.spvasm"), filepath.Join(dir, "wide.spv")
	os.WriteFile(source, []byte(wideModuleText), 0644)
	for _, command := range [][]string{{"spirv-as", "--preserve-numeric-ids", "--target-env", "spv1.6", source, "-o", binaryPath}, {"spirv-val", binaryPath}} {
		out, e := exec.Command(filepath.Join(tools, command[0]), command[1:]...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s: %v\n%s", command[0], e, out)
		}
	}
	reference, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(own[20:], reference[20:]) {
		t.Fatal("64-bit switch / 16/32/64-bit float module differs from spirv-as")
	}
	decoded, err := c.DecodeModule(reference)
	if err != nil {
		t.Fatal(err)
	}
	text := c.FormatModule(decoded)
	again, err := c.AssembleModule(text, decoded.Version, decoded.Generator)
	if err != nil {
		t.Fatal(text, err)
	}
	round, err := c.EncodeModule(again)
	if err != nil || !bytes.Equal(round, reference) {
		t.Fatal("wide module text roundtrip", err)
	}
}

func TestIndependentTools(t *testing.T) {
	toolDir := os.Getenv("MKASM_SPIRV_TOOLS")
	if toolDir == "" {
		t.Skip("set MKASM_SPIRV_TOOLS to spirv-as/dis/val directory")
	}
	c := grammar(t)
	dir := t.TempDir()
	source := filepath.Join(dir, "module.spvasm")
	binaryPath := filepath.Join(dir, "module.spv")
	os.WriteFile(source, []byte(moduleText), 0644)
	run := func(name string, args ...string) {
		t.Helper()
		out, e := exec.Command(filepath.Join(toolDir, name), args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s: %v\n%s", name, e, out)
		}
	}
	run("spirv-as", "--target-env", "spv1.6", "--preserve-numeric-ids", source, "-o", binaryPath)
	run("spirv-val", binaryPath)
	b, e := os.ReadFile(binaryPath)
	if e != nil {
		t.Fatal(e)
	}
	m, e := c.DecodeModule(b)
	if e != nil {
		t.Fatal(e)
	}
	again, e := c.EncodeModule(m)
	if e != nil || !bytes.Equal(b, again) {
		t.Fatalf("module binary roundtrip: %v", e)
	}
	ctx := NewContext()
	var reconstructed []Instruction
	for _, i := range m.Instructions {
		j, e := c.Assemble(c.Format(i), ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		reconstructed = append(reconstructed, j)
		ctx.Observe(j)
	}
	m.Instructions = reconstructed
	again, e = c.EncodeModule(m)
	if e != nil || !bytes.Equal(b, again) {
		t.Fatalf("module text roundtrip: %v", e)
	}
	big := append([]byte{}, b...)
	for n := 0; n < len(big); n += 4 {
		binary.BigEndian.PutUint32(big[n:], binary.LittleEndian.Uint32(b[n:]))
	}
	if _, e := c.DecodeModule(big); e != nil {
		t.Fatal("big endian module:", e)
	}
	m.Bound = 4
	if _, e := c.EncodeModule(m); e == nil {
		t.Fatal("invalid ID bound admitted")
	}
	t.Log("spirv-as and spirv-val validated real compute module; binary/text and big-endian import passed")
}
func TestInvalidGrammar(t *testing.T) {
	for _, s := range []string{"{}", "{} {}", "[]"} {
		if _, e := Parse(strings.NewReader(s), "spirv"); e == nil {
			t.Fatal("invalid grammar accepted")
		}
	}
}

func TestGeneratedRust(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	c := grammar(t)
	dir := os.Getenv("MKASM_SPIRV_RUST_OUTPUT")
	if dir == "" {
		dir = t.TempDir()
	}
	if err := c.GenerateRust(dir); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--lib", "--manifest-path", filepath.Join(dir, "Cargo.toml"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated Rust: %v\n%s", err, out)
	}
	t.Log(string(out))
	cmd = exec.Command("cargo", "build", "--lib", "--example", "roundtrip", "--manifest-path", filepath.Join(dir, "Cargo.toml"))
	out, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated consumer: %v\n%s", err, out)
	}
	cmd = exec.Command("cargo", "metadata", "--no-deps", "--format-version", "1", "--manifest-path", filepath.Join(dir, "Cargo.toml"))
	out, err = cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Target string `json:"target_directory"`
	}
	if err = json.Unmarshal(out, &metadata); err != nil {
		t.Fatal(err)
	}
	m, err := c.AssembleModule(moduleText, 0x10600, 0)
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.EncodeModule(m)
	if err != nil {
		t.Fatal(err)
	}
	input, output := filepath.Join(dir, "consumer-input.spv"), filepath.Join(dir, "consumer-output.spv")
	if err = os.WriteFile(input, data, 0644); err != nil {
		t.Fatal(err)
	}
	out, err = exec.Command(filepath.Join(metadata.Target, "debug", "examples", "roundtrip"), input, output).CombinedOutput()
	if err != nil {
		t.Fatalf("generated Rust real module consumer: %v\n%s", err, out)
	}
	again, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(data, again) {
		t.Fatalf("generated consumer byte mismatch: %v", err)
	}
	if tools := os.Getenv("MKASM_SPIRV_TOOLS"); tools != "" {
		out, err = exec.Command(filepath.Join(tools, "spirv-val"), output).CombinedOutput()
		if err != nil {
			t.Fatalf("Rust module spirv-val: %v\n%s", err, out)
		}
	}
	t.Log("generated standalone Rust consumer decoded/formatted/reencoded compute module")
}

func TestModuleAssemblyAndRequirements(t *testing.T) {
	c := grammar(t)
	text := strings.NewReplacer("%1", "%void", "%2", "%fn", "%4", "%main", "%5", "%entry").Replace(moduleText)
	m, err := c.AssembleModule(text, 0x10600, 0)
	if err != nil {
		t.Fatal(err)
	}
	formatted := c.FormatModule(m)
	again, err := c.AssembleModule(formatted, 0x10600, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := c.EncodeModule(m)
	b, _ := c.EncodeModule(again)
	if !bytes.Equal(a, b) {
		t.Fatal("symbolic module text roundtrip mismatch")
	}
	bad := m
	bad.Instructions = append([]Instruction{}, m.Instructions[1:]...)
	if err = c.ValidateRequirements(bad); err == nil {
		t.Fatal("module without Shader capability admitted")
	}
	if _, err = c.AssembleModule("%0 = OpTypeVoid", 0x10600, 0); err == nil {
		t.Fatal("zero numeric ID admitted as symbolic")
	}
	ctx := NewContext()
	for _, line := range []string{"%1 = OpTypeFloat 16", "%2 = OpConstant %1 1.5"} {
		i, e := c.Assemble(line, ctx, nil)
		if e != nil {
			t.Fatal(e)
		}
		ctx.Observe(i)
		if i.Opcode == 43 && i.Operands[2].Words[0] != 0x3e00 {
			t.Fatal("incorrect half float literal")
		}
	}
}

func TestCombinedBitmasks(t *testing.T) {
	c := grammar(t)
	for _, k := range c.OperandKinds {
		if k.Category != "BitEnum" {
			continue
		}
		var mask uint32
		for _, e := range k.Enumerants {
			mask |= e.Number
		}
		specs, err := enumParams(&k, mask, nil)
		if err != nil {
			t.Fatal(err)
		}
		o := Operand{Kind: k.Kind, Words: []uint32{mask}}
		for _, s := range specs {
			o.Parameters = append(o.Parameters, sampleOperand(c, s.Kind, true))
		}
		words, err := c.operandWords(o)
		if err != nil {
			t.Fatal(err)
		}
		got, n, err := (wordDecoder{c: c, switchWords: 1}).one(k.Kind, words, 0)
		if err != nil || n != len(words) || !equalOperands([]Operand{o}, []Operand{got}) {
			t.Fatalf("%s combined mask: %v", k.Kind, err)
		}
	}
}

// These streams exercise binary grammar parity, not semantic module validity:
// each case receives scalar type/import scaffolding, and IDs are deliberately
// reused. TestIndependentTools separately validates an actual compute module.
func TestIndependentFullGrammar(t *testing.T) {
	toolDir := os.Getenv("MKASM_SPIRV_TOOLS")
	if toolDir == "" {
		t.Skip("set MKASM_SPIRV_TOOLS")
	}
	c := grammar(t)
	var source strings.Builder
	var expected []byte
	ctx := NewContext()
	currentBase := uint32(1)
	seed := []string{"%1 = OpTypeInt 32 0", "%2 = OpConstant %1 0", "%100 = OpExtInstImport \"NonSemantic.Mkasm\""}
	appendInstruction := func(i Instruction) {
		text := c.Format(i)
		b, e := c.Encode(i, ctx, nil)
		if e != nil {
			t.Fatal(text, e)
		}
		source.WriteString(text + "\n")
		expected = append(expected, b...)
		ctx.Observe(i)
	}
	var fixIDs func([]Operand)
	fixIDs = func(operands []Operand) {
		for n := range operands {
			o := &operands[n]
			if c.kinds[o.Kind].Category == "Id" {
				switch o.Kind {
				case "IdResultType":
					o.Words[0] = currentBase
				case "IdResult":
					o.Words[0] = currentBase + 3
				default:
					o.Words[0] = currentBase + 1
				}
			}
			fixIDs(o.Parameters)
		}
	}
	count := 0
	for _, d := range c.Instructions {
		for _, extended := range []bool{false, true} {
			currentBase = uint32(count*4 + 1)
			seed = []string{fmt.Sprintf("%%%d = OpTypeInt 32 0", currentBase), fmt.Sprintf("%%%d = OpConstant %%%d 0", currentBase+1, currentBase), fmt.Sprintf("%%%d = OpExtInstImport \"NonSemantic.Mkasm\"", currentBase+2)}
			for _, s := range seed {
				i, e := c.Assemble(s, ctx, nil)
				if e != nil {
					t.Fatal(e)
				}
				appendInstruction(i)
			}
			i := sampleInstruction(c, d, extended)
			fixIDs(i.Operands)
			if d.Name == "OpTypeInt" {
				i.Operands[1].Words[0] = 32
			}
			if d.Name == "OpTypeFloat" {
				i.Operands[1].Words[0] = 32
				if extended {
					i.Operands[1].Words[0] = 16
				}
			}
			if d.Name == "OpExtInstImport" {
				i.Operands[1].Text = "NonSemantic.Mkasm"
			}
			if strings.HasPrefix(d.Name, "OpExtInst") && d.Name != "OpExtInstImport" && len(i.Operands) > 2 {
				i.Operands[2].Words[0] = currentBase + 2
			}
			appendInstruction(i)
			count++
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "all.spvasm")
	outpath := filepath.Join(dir, "all.spv")
	os.WriteFile(path, []byte(source.String()), 0644)
	out, e := exec.Command(filepath.Join(toolDir, "spirv-as"), "--target-env", "spv1.6", "--preserve-numeric-ids", path, "-o", outpath).CombinedOutput()
	if e != nil {
		t.Fatalf("full grammar spirv-as: %v\n%s", e, out)
	}
	b, e := os.ReadFile(outpath)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b[20:], expected) {
		for n := 0; n < len(b)-20 && n < len(expected); n++ {
			if b[20+n] != expected[n] {
				t.Fatalf("independent parity mismatch byte %d (%x vs %x)", n, b[20+n:20+n+4], expected[n:n+4])
			}
		}
		t.Fatal("independent parity length mismatch")
	}
	t.Logf("spirv-as verified %d machine forms across every %d core grammar instructions", count, len(c.Instructions))
}
