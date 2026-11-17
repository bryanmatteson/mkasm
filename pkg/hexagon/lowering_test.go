package hexagon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/object"
)

func TestAssemblerOnlyCombineDiagnostics(t *testing.T) {
	c := fixture(t)
	for id, target := range map[string]string{"TFRI64_V2_ext": "A2_combineii", "TFRI64_V4": "A4_combineii"} {
		if _, err := c.entry(id); err == nil {
			t.Fatalf("invented physical opcode for %s", id)
		}
		if _, err := c.entry(target); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, u := range c.Unsupported {
			if u.ID == id {
				found = strings.Contains(u.Reason, "assembler-only rewrite") && strings.Contains(u.Reason, target) && strings.Contains(u.Reason, "not a distinct opcode")
			}
		}
		if !found {
			t.Fatalf("missing precise lowering diagnostic for %s", id)
		}
	}
}

func TestCombineRewriteDoesNotHidePhysicalFields(t *testing.T) {
	for _, id := range []string{"TFRI64_V2_ext", "TFRI64_V4"} {
		data, err := json.Marshal(map[string]any{
			"!instanceof": map[string]any{"Instruction": []string{id}},
			id: map[string]any{
				"Namespace": "Hexagon", "isPseudo": 0, "isAsmParserOnly": 1,
				"Inst": []any{map[string]any{"var": "dst", "index": 0}},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(bytes.NewReader(data), "hexagon"); err == nil || !strings.Contains(err.Error(), "unexpected physical operand encoding") {
			t.Fatalf("silently excluded new physical encoding for %s: %v", id, err)
		}
	}
}

func loweringAssembler(t *testing.T) string {
	t.Helper()
	tool := os.Getenv("MKASM_LLVM_MC")
	if tool == "" {
		tool = "/opt/homebrew/opt/llvm/bin/llvm-mc"
	}
	if _, err := os.Stat(tool); err != nil {
		t.Skip("LLVM Hexagon assembler unavailable: ", err)
	}
	return tool
}

// Use the complete-program consumer, including labels and unresolved external
// operands. LLVM's two parser records do not define independent machine words:
// their emitted bytes must be the already imported combine/extender forms.
func TestLLVMCombineParserLowering(t *testing.T) {
	tool := loweringAssembler(t)
	c := fixture(t)
	cases := []struct {
		text, target   string
		reg, high, low int64
		extended       bool
	}{
		{"r1:0 = combine(##305419896,#-7)", "A2_combineii", 0, 305419896, -7, true},
		{"r3:2 = combine(##-2147483648,#-128)", "A2_combineii", 2, -2147483648, -128, true},
		{"r5:4 = combine(##2147483647,#127)", "A2_combineii", 4, 2147483647, 127, true},
		{"r7:6 = #4294967297", "A4_combineii", 6, 1, 1, false},
		{"r9:8 = ##305419896", "A4_combineii", 8, 0, 305419896, true},
		{"r11:10 = ##549755813887", "A4_combineii", 10, 127, 4294967295, true},
		{"r13:12 = ##-549755813888", "A4_combineii", 12, -128, 0, true},
		{"r15:14 = ##-4294967295", "A4_combineii", 14, -1, 1, true},
		{"r17:16 = ##-1", "A4_combineii", 16, -1, 4294967295, true},
		{"r19:18 = #4294967359", "A4_combineii", 18, 1, 63, false},
		{"r21:20 = #4294967360", "A4_combineii", 20, 1, 64, false},
	}
	var source strings.Builder
	source.WriteString(".text\n.globl combine_lowering\ncombine_lowering:\n")
	for n, tc := range cases {
		fmt.Fprintf(&source, "case_%d:\n{\n%s\n}\n", n, tc.text)
	}
	source.WriteString("cases_end:\n{\nr23:22 = ##external_low\n}\n{\nr25:24 = combine(##external_high,#7)\n}\n")
	o, err := object.Assemble(context.Background(), source.String(), object.Options{Executable: tool, Triple: "hexagon", CPU: "hexagonv60"})
	if err != nil {
		t.Fatal(err)
	}
	if dir := os.Getenv("HEXAGON_LOWERING_ARTIFACTS"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{"combine-lowering.s": []byte(source.String()), "combine-lowering.o": o.Data} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	var text []byte
	for _, s := range o.Sections {
		if s.Name == ".text" {
			text = s.Data
		}
	}
	if o.Machine != 164 || len(text) == 0 {
		t.Fatalf("missing Hexagon ELF text: machine %d", o.Machine)
	}
	labels := map[string]uint64{}
	for _, s := range o.Symbols {
		labels[s.Name] = s.Value
	}
	for n, tc := range cases {
		t.Run(tc.text, func(t *testing.T) {
			start, ok := labels[fmt.Sprintf("case_%d", n)]
			end, last := labels[fmt.Sprintf("case_%d", n+1)]
			if n+1 == len(cases) {
				end, last = labels["cases_end"]
			}
			if !ok || !last || end <= start || end > uint64(len(text)) {
				t.Fatalf("missing packet labels: %v", labels)
			}
			want := text[start:end]
			i := Instruction{ID: tc.target, Values: map[string]int64{"Rdd32": tc.reg, "Ii": tc.high, "II": tc.low}, Extended: tc.extended}
			got, err := c.EncodePacket(Packet{Words: []Word{{Instructions: []Instruction{i}}}}, start, nil)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("physical lowering %x != native %x: %v", got, want, err)
			}
			p, used, err := c.DecodePacket(want, start, nil)
			if err != nil || used != len(want) {
				t.Fatalf("native packet decode %x: length %d: %v", want, used, err)
			}
			if got, err := c.EncodePacket(p, start, nil); err != nil || !bytes.Equal(got, want) {
				t.Fatalf("native packet reencode %x: %v", got, err)
			}
			canonical := c.FormatPacket(p, start)
			// V2_ext's source spelling is already exactly the physical syntax.
			for _, syntax := range []string{canonical, fmt.Sprintf("{\n%s\n}", tc.text)} {
				if tc.target != "A2_combineii" && syntax != canonical {
					continue // V4's constant decomposition belongs to LLVM's parser.
				}
				options, err := c.AssemblePacket(syntax, start, nil)
				found := false
				for _, b := range options {
					found = found || bytes.Equal(b, want)
				}
				if err != nil || !found {
					t.Fatalf("physical assembly %s: %v; %x lacks %x", syntax, err, options, want)
				}
			}
			if tc.high == 1 && tc.low >= 63 {
				wantLen := 4
				if tc.low == 64 {
					wantLen = 8
				}
				if len(want) != wantLen {
					t.Fatalf("low32 extender boundary: got %d bytes, want %d", len(want), wantLen)
				}
			}
		})
	}
	// Both symbolic parser rewrites retain their two ABI relocation records.
	if len(o.Relocations) != 4 {
		t.Fatalf("lost symbolic lowering relocations: %+v", o.Relocations)
	}
	for n, r := range o.Relocations {
		name := "external_low"
		if n >= 2 {
			name = "external_high"
		}
		kind := uint32(17) // R_HEX_32_6_X on immext
		if n%2 == 1 {
			kind = 30 // R_HEX_6_X on the combine consumer
			if n >= 2 {
				kind = 28 // R_HEX_8_X on A2_combineii's wider consumer
			}
		}
		if int(r.Symbol) >= len(o.Symbols) || o.Symbols[r.Symbol].Name != name || r.Type != kind || r.Offset != labels["cases_end"]+uint64(4*n) || !r.HasAddend || r.Addend != 0 || r.Section != ".text" {
			t.Fatalf("wrong symbolic combine relocation %d: %+v", n, r)
		}
	}
	for _, invalid := range []struct {
		text, target string
		high, low    int64
	}{
		{"r1:0 = ##549755813888", "A4_combineii", 128, 0},
		{"r1:0 = ##-549755813889", "A4_combineii", -129, 4294967295},
		{"r1:0 = combine(##305419896,#128)", "A2_combineii", 305419896, 128},
		{"r1:0 = combine(##305419896,#-129)", "A2_combineii", 305419896, -129},
	} {
		if _, err := object.Assemble(context.Background(), ".text\n{\n"+invalid.text+"\n}\n", object.Options{Executable: tool, Triple: "hexagon", CPU: "hexagonv60"}); err == nil {
			t.Fatalf("LLVM accepted out-of-domain parser rewrite: %s", invalid.text)
		}
		i := Instruction{ID: invalid.target, Values: map[string]int64{"Rdd32": 0, "Ii": invalid.high, "II": invalid.low}, Extended: true}
		if _, err := c.EncodePacket(Packet{Words: []Word{{Instructions: []Instruction{i}}}}, 0, nil); err == nil {
			t.Fatalf("physical codec accepted out-of-domain parser rewrite: %s", invalid.text)
		}
	}
}
