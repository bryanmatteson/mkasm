package hexagon

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func sample(e *codec.Encoding, seed int) Instruction {
	v := map[string]int64{}
	for n, o := range e.Operands {
		value := int64(0)
		if len(o.Names) == 0 && seed > 0 {
			var represented uint64
			for _, b := range o.Bits {
				for k := 0; k < b.Width; k++ {
					represented |= 1 << uint(b.ValueBit+k)
				}
			}
			raw := represented & 0x55555555
			if seed == 2 {
				raw = represented
			}
			w := o.Width()
			if o.Signed && raw&(1<<uint(w-1)) != 0 {
				value = int64(raw | (^uint64(0) << uint(w)))
			} else {
				value = int64(raw)
			}
		}
		if len(o.Names) > 0 {
			var legal []int
			for k, name := range o.Names {
				if name != "" {
					legal = append(legal, k)
				}
			}
			if len(legal) > 0 {
				index := seed + n
				if o.Class == "IntRegs" || o.Class == "DoubleRegs" {
					index = seed + n*4
				}
				value = int64(legal[index%len(legal)])
			}
		}
		v[o.Name] = value
	}
	for _, constraint := range e.Constraints {
		if constraint.Right != "" {
			continue
		}
		if constraint.Kind == "sum_le" && v[constraint.Left] > constraint.Limit || constraint.Kind == "diff_ge" && v[constraint.Left] < constraint.Limit {
			v[constraint.Left] = constraint.Limit
		}
	}
	return Instruction{ID: e.ID, Values: v}
}
func samplePacket(c *Catalog, e *codec.Encoding, trial int) Packet {
	i := sample(e, trial)
	m := c.Metadata[e.ID]
	p := Packet{}
	if strings.Contains(e.Syntax, ".new") {
		if strings.Contains(e.Syntax, "p0.new") {
			producer, _ := c.entry("C2_cmpeq")
			a := sample(producer, 0)
			a.Values["Pd4"] = 0
			p.Words = append(p.Words, Word{[]Instruction{a}})
		}
		for _, o := range e.Operands {
			if o.Class == "PredRegs" && strings.Contains(e.Syntax, "{"+o.Name+"}.new") {
				producer, _ := c.entry("C2_cmpeq")
				a := sample(producer, 0)
				a.Values["Pd4"] = i.Values[o.Name]
				p.Words = append(p.Words, Word{[]Instruction{a}})
			}
		}
	}
	if m.NewValueUse != "" {
		name := "A2_tfrsi"
		if m.Vector {
			name = "V6_vaddb"
		}
		producer, err := c.entry(name)
		if err == nil {
			a := sample(producer, 0)
			for _, name := range c.Metadata[producer.ID].Producers {
				a.Values[name] = 24
			}
			if value, ok := c.producerValue(a, 0); ok {
				i.Values[m.NewValueUse] = value
			}
			p.Words = append(p.Words, Word{[]Instruction{a}})
		}
	}
	if m.Type == "TypeSUBINSN" {
		var partner *codec.Encoding
		slot := 0
		for _, g := range duplexGroups {
			if g[0] == m.SubGroup {
				for n := range c.Subinstructions.Encodings {
					q := &c.Subinstructions.Encodings[n]
					if c.Metadata[q.ID].SubGroup == g[1] {
						partner = q
						slot = 0
						break
					}
				}
			}
			if partner != nil {
				break
			}
			if g[1] == m.SubGroup {
				for n := range c.Subinstructions.Encodings {
					q := &c.Subinstructions.Encodings[n]
					if c.Metadata[q.ID].SubGroup == g[0] {
						partner = q
						slot = 1
						break
					}
				}
			}
			if partner != nil {
				break
			}
		}
		if partner != nil {
			// The instruction under test uses the low register bank. Use the
			// high bank for the companion so duplex packets do not write the
			// same register twice (including either half of a register pair).
			a := sample(partner, 8)
			if slot == 0 {
				p.Words = append(p.Words, Word{[]Instruction{i, a}})
			} else {
				p.Words = append(p.Words, Word{[]Instruction{a, i}})
			}
		}
	} else {
		p.Words = append(p.Words, Word{[]Instruction{i}})
	}
	return p
}

// LLVM's assembler takes signed PC-relative displacements. The public formatter
// correctly prints wrapped 32-bit targets; adapt only those relative operands,
// keeping the negative boundary samples rather than replacing them with zero.
func llvmPacketText(c *Catalog, p Packet) string {
	text := c.FormatPacket(p, 0)
	for _, word := range p.Words {
		for _, instruction := range word.Instructions {
			e, err := c.entry(instruction.ID)
			if err != nil {
				continue
			}
			for _, operand := range e.Operands {
				value := instruction.Values[operand.Name]
				if operand.Relative && value < 0 {
					text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", uint32(value)), strconv.FormatInt(value, 10))
				}
			}
		}
	}
	return text
}

// Run explicitly to regenerate independent LLVM corpus evidence. The source
// fixture is complete; ordinary unit checks do not launch thousands of tools.
func TestCompleteLLVMCorpus(t *testing.T) {
	if os.Getenv("HEXAGON_FULL_CORPUS") == "" {
		t.Skip("set HEXAGON_FULL_CORPUS=1")
	}
	c := fixture(t)
	artifact := os.Getenv("HEXAGON_ARTIFACTS")
	if artifact == "" {
		artifact = t.TempDir()
	}
	if err := os.MkdirAll(artifact, 0755); err != nil {
		t.Fatal(err)
	}
	type Case struct{ ID, Text, Expected, Actual, Diagnostic string }
	var cases []Case
	var input strings.Builder
	for _, table := range []*codec.Catalog{c.Words, c.Subinstructions} {
		for n := range table.Encodings {
			e := &table.Encodings[n]
			if e.ID == "A4_ext" {
				continue
			}
			for trial := 0; trial < 3; trial++ {
				p := samplePacket(c, e, trial)
				b, err := c.EncodePacket(p, 0, nil)
				item := Case{ID: e.ID, Text: llvmPacketText(c, p)}
				if err != nil {
					item.Diagnostic = "encoder: " + err.Error()
				} else {
					item.Expected = hex.EncodeToString(b)
					fmt.Fprintf(&input, "case_%d:\n%s\n", len(cases), item.Text)
				}
				cases = append(cases, item)
			}
		}
	}
	path := filepath.Join(artifact, "corpus.s")
	os.WriteFile(path, []byte(input.String()), 0644)
	llvm := os.Getenv("MKASM_LLVM_MC")
	if llvm == "" {
		llvm = "/opt/homebrew/opt/llvm/bin/llvm-mc"
	}
	cmd := exec.Command(llvm, "-triple", "hexagon", "-mcpu=hexagonv81", "-mattr=+hvxv81,+hvx-length128b,+hvx-ieee-fp,+hvx-qfloat,+audio", "-show-encoding", path)
	var out, diagnostics bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &diagnostics
	cmd.Run()
	os.WriteFile(filepath.Join(artifact, "llvm.out"), out.Bytes(), 0644)
	os.WriteFile(filepath.Join(artifact, "llvm.err"), diagnostics.Bytes(), 0644)
	encRE := regexp.MustCompile(`encoding: \[([^]]+)\]`)
	index := -1
	var actual []byte
	flush := func() {
		if index >= 0 {
			cases[index].Actual = hex.EncodeToString(actual)
		}
		actual = nil
	}
	for _, line := range strings.Split(out.String(), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "case_") {
			flush()
			n, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(trim, "case_"), ":"))
			index = n
		}
		m := encRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		for _, s := range strings.Split(m[1], ",") {
			v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 8)
			if err != nil {
				if index >= 0 {
					cases[index].Diagnostic = "LLVM unresolved fixup"
				}
				continue
			}
			actual = append(actual, byte(v))
		}
	}
	flush()
	// Validate actual object emission as well as llvm-mc's diagnostic encoding
	// display. Labels delimit each independent packet in the retained ELF.
	var valid strings.Builder
	for n, x := range cases {
		if x.Actual != "" && x.Diagnostic == "" {
			fmt.Fprintf(&valid, "case_%d:\n%s\n", n, x.Text)
		}
	}
	objectPath := filepath.Join(artifact, "corpus.o")
	object := exec.Command(llvm, "-triple", "hexagon", "-mcpu=hexagonv81", "-mattr=+hvxv81,+hvx-length128b,+hvx-ieee-fp,+hvx-qfloat,+audio", "-filetype=obj", "-o", objectPath)
	object.Stdin = strings.NewReader(valid.String())
	if diagnostics, err := object.CombinedOutput(); err != nil {
		t.Fatalf("object corpus: %v\n%s", err, diagnostics)
	}
	f, err := elf.Open(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	textBytes, err := f.Section(".text").Data()
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	objectCount := 0
	for _, s := range symbols {
		if !strings.HasPrefix(s.Name, "case_") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(s.Name, "case_"))
		if err != nil {
			t.Fatal(err)
		}
		want, _ := hex.DecodeString(cases[n].Actual)
		if int(s.Value)+len(want) > len(textBytes) || !bytes.Equal(want, textBytes[int(s.Value):int(s.Value)+len(want)]) {
			t.Fatalf("%s object and encoding-display bytes differ", cases[n].ID)
		}
		objectCount++
	}
	// CABAC is available on older cores but removed from the v81 assembler
	// feature set. Validate that source form with its actual legacy target.
	for n, x := range cases {
		if x.ID != "S2_cabacdecbin" {
			continue
		}
		legacyPath := filepath.Join(artifact, "legacy.o")
		cmd := exec.Command(llvm, "-triple", "hexagon", "-mcpu=hexagonv60", "-mattr=+cabac", "-filetype=obj", "-o", legacyPath)
		cmd.Stdin = strings.NewReader(x.Text)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("legacy CABAC: %v %s", err, out)
		}
		legacy, err := elf.Open(legacyPath)
		if err != nil {
			t.Fatal(err)
		}
		data, err := legacy.Section(".text").Data()
		legacy.Close()
		if err != nil {
			t.Fatal(err)
		}
		cases[n].Actual = hex.EncodeToString(data)
		objectCount++
	}
	// LLVM's V81 disassembler and code emitter implement this physical form,
	// but its assembly parser rejects the spelling from its own printer. Check
	// both the native decoded operands and bytes re-emitted by MCCodeEmitter.
	parserFallbacks := 0
	for n, x := range cases {
		if x.ID != "V6_vconv_h_hf_rnd" {
			continue
		}
		data, err := hex.DecodeString(x.Expected)
		if err != nil {
			t.Fatal(err)
		}
		var input strings.Builder
		for _, b := range data {
			fmt.Fprintf(&input, "0x%02x ", b)
		}
		cmd := exec.Command(llvm, "-triple=hexagon", "-mcpu=hexagonv81", "-mattr=+hvxv81,+hvx-length128b", "-disassemble", "-show-encoding")
		cmd.Stdin = strings.NewReader(input.String() + "\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("native V81 decoder/emitter: %v\n%s", err, out)
		}
		matches := encRE.FindSubmatch(out)
		var actual []byte
		if len(matches) == 2 {
			for _, value := range strings.Split(string(matches[1]), ",") {
				n, err := strconv.ParseUint(strings.TrimSpace(value), 0, 8)
				if err != nil {
					t.Fatal(err)
				}
				actual = append(actual, byte(n))
			}
		}
		nativeText := strings.SplitN(string(out), "//", 2)[0]
		if !bytes.Equal(actual, data) || strings.Join(strings.Fields(nativeText), "") != strings.Join(strings.Fields(x.Text), "") {
			t.Fatalf("native decoder/emitter disagrees for %s: %s", x.Text, out)
		}
		cases[n].Actual = hex.EncodeToString(actual)
		cases[n].Diagnostic = ""
		parserFallbacks++
	}
	pass, reordered, failed, fixups, decodeErrors := 0, 0, 0, 0, 0
	for n := range cases {
		x := &cases[n]
		if x.Diagnostic != "" {
			failed++
			continue
		}
		if x.Actual == "" {
			x.Diagnostic = "LLVM rejected representative; see llvm.err"
			failed++
			continue
		}
		if x.Actual != x.Expected {
			x.Diagnostic = "LLVM selected alternative encoding or packet order"
			reordered++
		} else {
			pass++
		}
		b, _ := hex.DecodeString(x.Actual)
		if len(b)%4 != 0 {
			fixups++
			continue
		}
		p, length, err := c.DecodePacket(b, 0, nil)
		if err != nil || length != len(b) {
			x.Diagnostic += "; packet decode: " + fmt.Sprint(err)
			decodeErrors++
			continue
		}
		got, err := c.EncodePacket(p, 0, nil)
		if err != nil || !bytes.Equal(got, b) {
			x.Diagnostic += "; packet re-encode failed"
			decodeErrors++
		}
	}
	data, _ := json.MarshalIndent(cases, "", "  ")
	os.WriteFile(filepath.Join(artifact, "cases.json"), data, 0644)
	t.Logf("attempted %d exact parity %d alternative %d rejected %d object packets %d fixup fragments %d packet failures %d", len(cases), pass, reordered, failed, objectCount, fixups, decodeErrors)
	t.Logf("native decoder/code-emitter parser fallbacks: %d", parserFallbacks)
	if failed != 0 {
		t.Errorf("%d samples lack independent reference coverage; see cases.json", failed)
	}
	if decodeErrors != 0 {
		t.Fatalf("%d independent LLVM packets fail decode/re-encode", decodeErrors)
	}
}
