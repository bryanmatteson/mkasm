package mips

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMIPS16ExecutionContext(t *testing.T) {
	for _, arch := range []string{"mips16", "mips16el", "mips16-64", "mips16-64el"} {
		t.Run(arch, func(t *testing.T) {
			c := &Catalog{compressedCatalog(t, arch)}
			physical := func(words ...uint16) []byte {
				var b []byte
				for _, w := range words {
					if strings.HasSuffix(arch, "el") {
						b = append(b, byte(w), byte(w>>8))
					} else {
						b = append(b, byte(w>>8), byte(w))
					}
				}
				return b
			}
			addressMask := uint64(0xffffffff)
			if strings.Contains(arch, "64") {
				addressMask = ^uint64(0)
			}
			fixtures := []struct {
				name              string
				transfer          []uint16
				start, pc, target uint64
			}{
				{"jal", []uint16{0x1800, 0x0000}, 0x1002, 0x1006, 0x1004},
				{"jalx", []uint16{0x1c00, 0x0000}, 0x1002, 0x1006, 0x1004},
				{"jr", []uint16{0xe820}, 0x1002, 0x1004, 0x1004},
				{"jalr", []uint16{0xe840}, 0x1002, 0x1004, 0x1004},
				{"wrap", []uint16{0x1800, 0x0000}, 0xfffffffc, 0, 0},
			}
			if strings.Contains(arch, "64") {
				fixtures[len(fixtures)-1].pc = 0x100000000
				fixtures[len(fixtures)-1].target = 0x100000000
				fixtures = append(fixtures,
					struct {
						name              string
						transfer          []uint16
						start, pc, target uint64
					}{"high-jal", []uint16{0x1800, 0}, 0x123456781002, 0x123456781006, 0x123456781004},
					struct {
						name              string
						transfer          []uint16
						start, pc, target uint64
					}{"wrap64", []uint16{0x1800, 0}, 0xfffffffffffffffc, 0, 0})
			}
			for _, fixture := range fixtures {
				t.Run(fixture.name, func(t *testing.T) {
					for _, word := range []uint16{0x0801, 0xb201} {
						b := physical(word)
						d, err := c.Decode(b)
						if err != nil {
							t.Fatal(err)
						}
						context := ExecutionContext{InstructionAddress: fixture.pc, PCBase: fixture.start}
						text := c.FormatWithContext(d, context)
						if !strings.Contains(text, fmt.Sprintf("0x%x", fixture.target)) {
							t.Fatalf("context %s: %q", fixture.name, text)
						}
						normal := d.Format(fixture.pc)
						if normal == text {
							t.Fatalf("fixture does not distinguish contextual base: %q", text)
						}
						assembled, err := c.AssembleWithContext(text, context, nil)
						if err != nil || !containsBytes(assembled, b) {
							t.Fatalf("context assembly %q: %x %v", text, assembled, err)
						}
						described := c.DescribeWithContext(d, context)
						if described.Text != text {
							t.Fatalf("describe %q != %q", described.Text, text)
						}
						refs := c.AddressReferencesWithContext(d, context)
						if len(refs) != 1 || refs[0].Target != fixture.target {
							t.Fatalf("references: %+v", refs)
						}
						for _, span := range described.Operands {
							if span.Position.Relative {
								if target, ok := span.Position.Target(fixture.pc, span.Value); !ok || target != fixture.target {
									t.Fatalf("span position: %+v", span)
								}
							}
						}
						index := refs[0].OperandIndex
						value := d.Values[d.Encoding.Operands[index].Name]
						if target, ok := refs[0].Position.Target(fixture.pc, value); !ok || target != fixture.target {
							t.Fatalf("reference position: %+v", refs[0])
						}
						output := make([]byte, 4)
						n, err := c.RewriteReferenceWithContext(d, context, index, (fixture.target+4)&addressMask, output)
						if err != nil || !bytes.Equal(output[:n], physical(word+1)) {
							t.Fatalf("rewrite: %x %v", output, err)
						}
						if d.Format(fixture.pc) != normal {
							t.Fatal("context mutated the shared encoding")
						}
						if oracle := os.Getenv("MKASM_MIPS16_DISASSEMBLER"); oracle != "" && !strings.HasPrefix(fixture.name, "wrap") {
							sequence := append(append([]uint16(nil), fixture.transfer...), word)
							order := "be"
							if strings.HasSuffix(arch, "el") {
								order = "le"
							}
							query := fmt.Sprintf("%s %x %x %d\n", order, fixture.start, physical(sequence...), len(fixture.transfer)*2)
							cmd := exec.Command(oracle)
							cmd.Stdin = strings.NewReader(query)
							out, err := cmd.CombinedOutput()
							if err != nil {
								t.Fatalf("GNU: %v %s", err, out)
							}
							tab := strings.LastIndexByte(strings.TrimSpace(string(out)), '\t')
							if tab < 0 {
								t.Fatal(string(out))
							}
							oracleText := strings.Join(strings.Fields(string(out[:tab])), " ")
							encoded, err := c.AssembleWithContext(oracleText, context, nil)
							if err != nil || !containsBytes(encoded, b) {
								t.Fatalf("GNU history %s -> %q, ours %q: %x %v", query, oracleText, text, encoded, err)
							}
						}
					}
				})
			}
			// A transfer's code target uses its own PC region, independently of
			// the data-PC base supplied for a delay-slot instruction.
			jump := physical(0x1800, 0)
			d, err := c.Decode(jump)
			if err != nil {
				t.Fatal(err)
			}
			ctx := ExecutionContext{InstructionAddress: 0x0ffffffc, PCBase: 0x01000000}
			if got := c.FormatWithContext(d, ctx); got != d.Format(ctx.InstructionAddress) || !strings.Contains(got, "0x10000000") {
				t.Fatalf("JAL context changed region: %q", got)
			}
		})
	}
}

func TestMIPS16GeneratedExecutionContext(t *testing.T) {
	for _, arch := range []string{"mips16", "mips16el", "mips16-64", "mips16-64el"} {
		c := &Catalog{compressedCatalog(t, arch)}
		out := t.TempDir()
		if err := c.GenerateRust(out); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"src/execution_context.rs", "tests/execution_context.rs"} {
			data, err := os.ReadFile(filepath.Join(out, path))
			if err != nil {
				t.Fatal(err)
			}
			if len(data) == 0 || strings.Contains(string(data), "__CRATE__") {
				t.Fatalf("unexpanded context output %s", path)
			}
		}
	}
}

func TestMIPS16AddressWidths(t *testing.T) {
	for _, arch := range []string{"mips16", "mips16el", "mips16-64", "mips16-64el"} {
		c := &Catalog{compressedCatalog(t, arch)}
		for _, fixture := range []struct {
			words                      []uint16
			pc, expected32, expected64 uint64
		}{
			{[]uint16{0x1001}, 0xfffffffc, 0, 0x100000000},
			{[]uint16{0x1800, 0}, 0x123456780ffffffc, 0x10000000, 0x1234567810000000},
			{[]uint16{0x1800, 0}, 0xfffffffffffffffc, 0, 0},
		} {
			var b []byte
			for _, word := range fixture.words {
				if strings.HasSuffix(arch, "el") {
					b = append(b, byte(word), byte(word>>8))
				} else {
					b = append(b, byte(word>>8), byte(word))
				}
			}
			d, err := c.Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			expected := fixture.expected32
			if strings.Contains(arch, "64") {
				expected = fixture.expected64
			}
			target, ok := d.BranchTarget(fixture.pc)
			if !ok || target != expected {
				t.Fatalf("%s %x at %x: target %x, want %x", arch, b, fixture.pc, target, expected)
			}
			assembled, err := c.Assemble(d.Format(fixture.pc), fixture.pc)
			if err != nil || !containsBytes(assembled, b) {
				t.Fatalf("width text: %x %v", assembled, err)
			}
			if oracle := os.Getenv("MKASM_MIPS16_DISASSEMBLER"); oracle != "" && strings.Contains(arch, "64") && fixture.pc != 0xfffffffffffffffc {
				order := "be"
				if strings.HasSuffix(arch, "el") {
					order = "le"
				}
				cmd := exec.Command(oracle)
				cmd.Stdin = strings.NewReader(fmt.Sprintf("%s %x %x\n", order, fixture.pc, b))
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("GNU64: %v %s", err, out)
				}
				// GNU prints the code target with the MIPS16 ISA marker bit set.
				if !strings.Contains(string(out), fmt.Sprintf("0x%x", expected|1)) {
					t.Fatalf("GNU64 %s at %x: %s, want %x", arch, fixture.pc, out, expected|1)
				}
			}
		}
	}
}
