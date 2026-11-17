package ebpf

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestRealLLVMCorpus(t *testing.T) {
	p := os.Getenv("MKASM_BPF_TABLEGEN_JSON")

	for _, arch := range []string{"bpfel", "bpfeb"} {
		t.Run(arch, func(t *testing.T) {
			var input io.ReadCloser
			var err error
			if p != "" {
				input, err = os.Open(p)
			} else {
				f, e := os.Open("testdata/llvm-22.1.8-bpf.json.gz")
				if e != nil {
					t.Fatal(e)
				}
				defer f.Close()
				input, err = gzip.NewReader(f)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			c, err := Parse(input, arch)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("%d encodings, %d nonmachine CO-RE operations", len(c.Encodings), len(c.Unsupported))
			tests := []struct {
				id     string
				v      map[string]int64
				le, be []byte
			}{
				{"ADD_ri", map[string]int64{"dst": 1, "imm": -1}, []byte{7, 1, 0, 0, 255, 255, 255, 255}, []byte{7, 16, 0, 0, 255, 255, 255, 255}},
				{"MOV_rr", map[string]int64{"dst": 2, "src": 3}, []byte{191, 50, 0, 0, 0, 0, 0, 0}, []byte{191, 35, 0, 0, 0, 0, 0, 0}},
				{"LDD", map[string]int64{"dst": 4, "addr_base": 10, "addr_offset": -8}, []byte{121, 164, 248, 255, 0, 0, 0, 0}, []byte{121, 74, 255, 248, 0, 0, 0, 0}},
				{"STW", map[string]int64{"src": 2, "addr_base": 10, "addr_offset": -4}, []byte{99, 42, 252, 255, 0, 0, 0, 0}, []byte{99, 162, 255, 252, 0, 0, 0, 0}},
				{"LD_imm64", map[string]int64{"dst": 1, "imm": 0x1122334455667788}, []byte{24, 1, 0, 0, 136, 119, 102, 85, 0, 0, 0, 0, 68, 51, 34, 17}, []byte{24, 16, 0, 0, 85, 102, 119, 136, 0, 0, 0, 0, 17, 34, 51, 68}},
				{"JEQ_rr", map[string]int64{"dst": 1, "src": 2, "BrDst": 24}, []byte{29, 33, 3, 0, 0, 0, 0, 0}, []byte{29, 18, 0, 3, 0, 0, 0, 0}},
				{"JAL", map[string]int64{"BrDst": 7}, []byte{133, 0, 0, 0, 7, 0, 0, 0}, []byte{133, 0, 0, 0, 0, 0, 0, 7}},
				{"RET", map[string]int64{}, []byte{149, 0, 0, 0, 0, 0, 0, 0}, []byte{149, 0, 0, 0, 0, 0, 0, 0}},
			}
			for _, tt := range tests {
				t.Run(tt.id, func(t *testing.T) {
					want := tt.le
					if arch == "bpfeb" {
						want = tt.be
					}
					got, err := c.Encode(tt.id, tt.v)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, want) {
						t.Fatalf("got %x want LLVM bytes %x", got, want)
					}
					d, err := c.Decode(got)
					if err != nil {
						t.Fatal(err)
					}
					if d.Length != len(want) {
						t.Fatalf("length %d", d.Length)
					}
					forms, err := c.Assemble(d.Format(0), 0)
					if err != nil {
						t.Fatal(err)
					}
					found := false
					for _, b := range forms {
						if bytes.Equal(b, got) {
							found = true
						}
					}
					if !found {
						t.Fatalf("round trip %q", d.Format(0))
					}
				})
			}
		})
	}
}

func loadCatalog(t *testing.T, arch string) *codec.Catalog {
	t.Helper()
	f, err := os.Open("testdata/llvm-22.1.8-bpf.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	c, err := Parse(z, arch)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func sampleValues(e *codec.Encoding) map[string]int64 {
	v := map[string]int64{}
	for _, o := range e.Operands {
		n := int64(1)
		if o.Signed && !strings.HasPrefix(e.ID, "LD_pseudo_") {
			n = -3
		}
		if o.Kind == "register" {
			n = 1
		}
		if o.Relative {
			n = 24
		}
		if len(o.Names) > 0 {
			n = 1
		}
		v[o.Name] = n
	}
	return v
}
func TestEveryEncodingRoundTrip(t *testing.T) {
	for _, arch := range []string{"bpfel", "bpfeb"} {
		c := loadCatalog(t, arch)
		for i := range c.Encodings {
			e := &c.Encodings[i]
			t.Run(arch+"/"+e.ID, func(t *testing.T) {
				values := sampleValues(e)
				b, err := c.Encode(e.ID, values)
				if err != nil {
					t.Fatal(err)
				}
				d, err := c.Decode(b)
				if err != nil {
					t.Fatal(err)
				}
				forms, err := c.Assemble(d.Format(0x100), 0x100)
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range forms {
					if bytes.Equal(f, b) {
						return
					}
				}
				t.Fatalf("failed roundtrip %x %q", b, d.Format(0x100))
			})
		}
	}
}
func TestLLVMParity(t *testing.T) {
	tool, err := exec.LookPath("llvm-mc")
	if err != nil {
		tool = "/opt/homebrew/opt/llvm/bin/llvm-mc"
		if _, err = os.Stat(tool); err != nil {
			t.Skip("LLVM MC unavailable")
		}
	}
	for _, arch := range []string{"bpfel", "bpfeb"} {
		c := loadCatalog(t, arch)
		var texts []string
		var expected [][]byte
		var ids []string
		for i := range c.Encodings {
			e := &c.Encodings[i]
			if e.ID == "JAL_REL" || e.ID == "JAL_KFUNC" {
				continue
			}
			v := sampleValues(e)
			b, err := c.Encode(e.ID, v)
			if err != nil {
				t.Fatal(err)
			}
			d := codec.Decoded{Encoding: e, Values: v, Length: len(b)}
			text := d.Format(0)
			for _, o := range e.Operands {
				if o.Relative {
					text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", uint64(o.PCBias)+uint64(v[o.Name])), fmt.Sprintf("%+d", v[o.Name]/8))
				}
			}
			text = strings.ReplaceAll(text, "+ -", "- ")
			if e.ID == "NOP" {
				text = "r0 = r0"
			}
			texts = append(texts, text)
			expected = append(expected, b)
			ids = append(ids, e.ID)
		}
		cmd := exec.Command(tool, "-triple", arch, "-mcpu=v4", "-show-encoding")
		cmd.Stdin = strings.NewReader(strings.Join(texts, "\n") + "\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("LLVM %s rejected corpus: %v\n%s", arch, err, out)
		}
		matches := regexp.MustCompile(`encoding: \[([^\]]+)\]`).FindAllStringSubmatch(string(out), -1)
		if len(matches) != len(expected) {
			t.Fatalf("LLVM returned %d rows for %d encodings", len(matches), len(expected))
		}
		for i, m := range matches {
			var b []byte
			for _, x := range strings.Split(m[1], ",") {
				n, err := strconv.ParseUint(strings.TrimSpace(x), 0, 8)
				if err != nil {
					t.Fatal(err)
				}
				b = append(b, byte(n))
			}
			if !bytes.Equal(b, expected[i]) {
				t.Errorf("%s %s %q got %x LLVM %x", arch, ids[i], texts[i], expected[i], b)
			}
		}
	}
}

func TestReservedFieldsAndWideFraming(t *testing.T) {
	for _, arch := range []string{"bpfel", "bpfeb"} {
		t.Run(arch, func(t *testing.T) {
			c := loadCatalog(t, arch)
			b, err := c.Encode("LD_imm64", map[string]int64{"dst": 10, "imm": -0x112233445566778})
			if err != nil {
				t.Fatal(err)
			}
			for n := 0; n < len(b); n++ {
				if _, err := c.Decode(b[:n]); !errors.Is(err, codec.ErrTruncated) {
					t.Fatalf("%d byte lddw: %v", n, err)
				}
			}
			for _, i := range []int{8, 9, 10, 11} {
				bad := append([]byte(nil), b...)
				bad[i] = 1
				if _, err := c.Decode(bad); !errors.Is(err, codec.ErrUnknown) {
					t.Fatalf("reserved continuation byte %d accepted: %v", i, err)
				}
			}
			bad := append([]byte(nil), b...)
			if arch == "bpfel" {
				bad[1] = 15
			} else {
				bad[1] = 240
			}
			if _, err := c.Decode(bad); !errors.Is(err, codec.ErrUnknown) {
				t.Fatalf("reserved register accepted: %v", err)
			}
			for _, id := range []string{"LD_pseudo_1", "LD_pseudo_3", "LD_pseudo_4", "LD_pseudo_5"} {
				v := map[string]int64{"dst": 1, "imm": 3}
				p, err := c.Encode(id, v)
				if err != nil {
					t.Fatal(err)
				}
				p[12] = 1
				if _, err := c.Decode(p); !errors.Is(err, codec.ErrUnknown) {
					t.Fatalf("%s reserved upper word accepted: %v", id, err)
				}
			}
			if _, err := c.Encode("JEQ_rr", map[string]int64{"dst": 1, "src": 2, "BrDst": 1}); err == nil {
				t.Fatal("unaligned branch accepted")
			}
			if _, err := c.Assemble("r1 = be16 r2", 0); err == nil {
				t.Fatal("unequal tied registers accepted")
			}
			for _, tag := range []int{1, 2} {
				id := "JAL_REL"
				value := int64(-16)
				if tag == 2 {
					id = "JAL_KFUNC"
					value = 77
				}
				p, err := c.Encode(id, map[string]int64{"BrDst": value})
				if err != nil {
					t.Fatal(err)
				}
				want := byte(tag << 4)
				if arch == "bpfeb" {
					want = byte(tag)
				}
				if p[1] != want {
					t.Fatalf("call source tag: %x", p)
				}
				d, err := c.Decode(p)
				if err != nil || d.Encoding.ID != id {
					t.Fatalf("call decode %#v %v", d, err)
				}
			}
		})
	}
}
func TestRejectUnrelatedInput(t *testing.T) {
	if _, err := Parse(strings.NewReader(`{"encodings":[]}`), "bpfel"); err == nil {
		t.Fatal("accepted custom JSON as TableGen")
	}
}

func TestFeatureProfiles(t *testing.T) {
	c := loadCatalog(t, "bpfel")
	b, err := c.Encode("LDW32", map[string]int64{"dst": 1, "addr_base": 2, "addr_offset": 0})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ feature, want string }{{"BPFHasALU32", "LDW32"}, {"BPFNoALU32", "LDW"}} {
		d, err := c.DecodeWithFeatures(b, []string{tt.feature})
		if err != nil {
			t.Fatal(err)
		}
		if d.Encoding.ID != tt.want {
			t.Fatalf("%s selected %s", tt.feature, d.Encoding.ID)
		}
	}
	b, err = c.Encode("LDWSX", map[string]int64{"dst": 1, "addr_base": 2, "addr_offset": 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DecodeWithFeatures(b, []string{}); !errors.Is(err, codec.ErrUnknown) {
		t.Fatalf("missing feature accepted %v", err)
	}
	if _, err := c.DecodeWithFeatures(b, []string{"BPFHasLdsx"}); err != nil {
		t.Fatal(err)
	}
}
