package conformance_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
	"github.com/bryanmatteson/mkasm/pkg/loongarch"
	"github.com/bryanmatteson/mkasm/pkg/mips"
	"github.com/bryanmatteson/mkasm/pkg/powerpc"
	"github.com/bryanmatteson/mkasm/pkg/riscv"
	"github.com/bryanmatteson/mkasm/pkg/sparc"
)

func addressCatalog(t *testing.T, arch string) *codec.Catalog {
	t.Helper()
	var input io.Reader
	var parse func(io.Reader, string) (*codec.Catalog, error)
	switch {
	case strings.HasPrefix(arch, "riscv"):
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		for name, data := range map[string]string{
			"arg_lut.csv":     "\"rs1\",19,15\n\"rs2\",24,20\n\"bimm12hi\",31,25\n\"bimm12lo\",11,7\n",
			"extensions/rv_i": "beq bimm12hi rs1 rs2 bimm12lo 14..12=0 6..2=0x18 1..0=3\n",
		} {
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(data)); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		input, parse = &b, riscv.Parse
	default:
		var path string
		switch {
		case strings.HasPrefix(arch, "mips"):
			path = "mips/testdata/llvm22-mips.json"
			parse = func(r io.Reader, architecture string) (*codec.Catalog, error) {
				c, err := mips.Parse(r, architecture)
				if err != nil {
					return nil, err
				}
				return c.Catalog, nil
			}
		case strings.HasPrefix(arch, "powerpc"):
			path, parse = "powerpc/testdata/llvm-22.1.8-powerpc.json.gz", powerpc.Parse
		case strings.HasPrefix(arch, "sparc"):
			path, parse = "sparc/testdata/llvm22-sparc.json", sparc.Parse
		case strings.HasPrefix(arch, "loongarch"):
			path, parse = "loongarch/testdata/llvm-loongarch.json", loongarch.Parse
		}
		f, err := os.Open(filepath.Join("..", "..", "pkg", path))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		input = f
		if strings.HasSuffix(path, ".gz") {
			z, err := gzip.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { z.Close() })
			input = z
		}
	}
	c, err := parse(input, arch)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type addressWrapCase struct {
	catalog          *codec.Catalog
	decoded          *codec.Decoded
	code             []byte
	pc, target       uint64
	assembly, signed string
}

type addressWrapGroup struct {
	name  string
	cases []addressWrapCase
}

// Construct every consumer's inputs before running subtests. In particular,
// selecting generated_rust with -run must not depend on sibling tests running.
func addressWrapGroups(t *testing.T) []addressWrapGroup {
	t.Helper()
	var groups []addressWrapGroup
	for _, arch := range []string{"riscv32", "riscv64", "mips32", "mips32el", "mips64", "mips64el", "powerpc32", "powerpc32le", "powerpc64", "powerpc64le", "sparc32", "sparc32le", "sparc64", "loongarch32", "loongarch64"} {
		c := addressCatalog(t, arch)
		group := addressWrapGroup{name: arch}
		add := func(code []byte, pc, target uint64, assembly, signed string) {
			d, err := c.Decode(code)
			if err != nil {
				t.Fatalf("%s decode: %v", arch, err)
			}
			group.cases = append(group.cases, addressWrapCase{c, d, code, pc, target, assembly, signed})
		}
		var syntax string
		switch {
		case strings.HasPrefix(arch, "riscv"):
			syntax = "beq x1, x2, 0x%x"
		case strings.HasPrefix(arch, "mips"):
			syntax = "beq $1, $2, 0x%x"
		case strings.HasPrefix(arch, "sparc"):
			syntax = "call 0x%x"
		default:
			syntax = "b 0x%x"
		}
		wide := strings.Contains(arch, "64")
		for _, input := range []struct{ target, pc, want uint64 }{{0xffc, 0, 0xfffffffc}, {0x1004, 0xfffffffc, 0}} {
			want := input.want
			if wide {
				if input.pc == 0 {
					want = ^uint64(3)
				} else {
					want = 0x100000000
				}
			}
			all, err := c.Assemble(fmt.Sprintf(syntax, input.target), 0x1000)
			if err != nil || len(all) == 0 {
				t.Fatalf("%s assemble: %v", arch, err)
			}
			assembly, signed := fmt.Sprintf(syntax, want), ""
			if !wide && input.pc == 0 {
				signed = strings.Replace(assembly, "0xfffffffc", "-4", 1)
			}
			for _, code := range all {
				add(code, input.pc, want, assembly, signed)
			}
		}
		if strings.HasPrefix(arch, "mips") {
			code, err := c.Encode("J", map[string]int64{"target": 0x120})
			if err != nil {
				t.Fatal(err)
			}
			want := uint64(0x120)
			if wide {
				want = 0x100000120
			}
			add(code, 0xfffffffc, want, fmt.Sprintf("j 0x%x", want), "")
		}
		if strings.HasPrefix(arch, "powerpc") {
			all, err := c.Assemble("ba -4", 0)
			if err != nil || len(all) == 0 {
				t.Fatalf("%s absolute branch: %v", arch, err)
			}
			want := uint64(0xfffffffc)
			if wide {
				want = ^uint64(3)
			}
			for _, code := range all {
				add(code, 0, want, fmt.Sprintf("ba 0x%x", want), "ba -4")
			}
		}
		groups = append(groups, group)
	}
	c, err := codec.NewCatalog("alignment", "", []codec.Encoding{{
		ID: "CALL", Mnemonic: "call", Syntax: "call {target}", FlowControl: "call", TargetMask: 0xfffe,
		Mask: []byte{255, 0, 0}, Value: []byte{0xf0, 0, 0},
		Operands: []codec.Operand{{Name: "target", Kind: "address", Bits: []codec.BitSlice{{InstructionBit: 8, Width: 16}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	code := []byte{0xf0, 0xff, 0xff}
	d, err := c.Decode(code)
	if err != nil {
		t.Fatal(err)
	}
	groups = append(groups, addressWrapGroup{"encoded_alignment_bits", []addressWrapCase{{c, d, code, 0, 0xfffe, "call 0xffff", ""}}})
	return groups
}

func TestArchitecturalAddressWrap(t *testing.T) {
	groups := addressWrapGroups(t)
	for _, group := range groups {
		t.Run(group.name, func(t *testing.T) {
			for _, tc := range group.cases {
				if target, ok := tc.decoded.BranchTarget(tc.pc); !ok || target != tc.target {
					t.Errorf("%x at %#x: target %#x (%v), want %#x", tc.code, tc.pc, target, ok, tc.target)
				}
				formatted := tc.decoded.Format(tc.pc)
				// Compare whole spellings: substring matching can hide an
				// incorrect target such as 0x04 when expecting 0x0.
				if formatted != tc.assembly {
					t.Errorf("format %q, want %q", formatted, tc.assembly)
				}
				for _, text := range []string{tc.assembly, tc.signed} {
					if text == "" {
						continue
					}
					all, err := tc.catalog.Assemble(text, tc.pc)
					found := false
					for _, b := range all {
						found = found || bytes.Equal(b, tc.code)
					}
					if err != nil || !found {
						t.Errorf("assemble %q: %x (%v), want %x", text, all, err, tc.code)
					}
				}
				moved, err := tc.decoded.Relocated(tc.pc, tc.pc+4)
				if err != nil {
					t.Fatal(err)
				}
				if target, ok := moved.BranchTarget(tc.pc + 4); !ok || target != tc.target {
					t.Errorf("relocation lost target: %#x (%v), want %#x", target, ok, tc.target)
				}
			}
		})
	}
	t.Run("generated_rust", func(t *testing.T) {
		if testing.Short() {
			t.Skip("generated Rust consumer")
		}
		if _, err := exec.LookPath("cargo"); err != nil {
			t.Skip("cargo unavailable")
		}
		generated := &codec.Catalog{Architecture: "address_wrap"}
		var consumer strings.Builder
		consumer.WriteString("use address_wrap::*;\n#[test] fn architectural_boundaries() {\n")
		seen := map[string]bool{}
		for _, group := range groups {
			for _, tc := range group.cases {
				id := group.name + "_" + tc.decoded.Encoding.ID
				if !seen[id] {
					e := *tc.decoded.Encoding
					e.ID, e.Features = id, []string{group.name}
					generated.Encodings = append(generated.Encodings, e)
					seen[id] = true
				}
				fmt.Fprintf(&consumer, "{ let bytes: &[u8] = &%s; let pc = %d; let active = Some(&[%q][..]); let d = decode_with_features(bytes,active).unwrap(); assert_eq!(d.branch_target(pc),Some(%d),%q); assert_eq!(d.format(pc),%q); assert!(assemble_with_features(&d.format(pc),pc,active).unwrap().contains(&bytes.to_vec())); assert_eq!(d.relocated(pc,pc+4).unwrap().branch_target(pc+4),Some(%d));\n", strings.ReplaceAll(fmt.Sprint(tc.code), " ", ","), tc.pc, group.name, tc.target, id, tc.assembly, tc.target)
				if tc.signed != "" {
					fmt.Fprintf(&consumer, "assert!(assemble_with_features(%q,pc,active).unwrap().contains(&bytes.to_vec()));\n", tc.signed)
				}
				consumer.WriteString("}\n")
			}
		}
		consumer.WriteString("}\n")
		dir := t.TempDir()
		if err := generated.GenerateRust(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "tests", "boundaries.rs"), []byte(consumer.String()), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("cargo", "test", "--test", "boundaries", "--quiet")
		cmd.Dir = dir
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("generated Rust: %v\n%s", err, output)
		}
	})
}
