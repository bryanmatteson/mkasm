package v850

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type boundaryVector struct {
	ID       string           `json:"id"`
	CPU      string           `json:"cpu"`
	Assembly string           `json:"assembly"`
	Bytes    string           `json:"bytes"`
	Values   map[string]int64 `json:"values"`
}

func TestGNUBoundaryOracle(t *testing.T) {
	as := os.Getenv("MKASM_V850_AS")
	if as == "" {
		t.Skip("set MKASM_V850_AS to run independent boundary assembly")
	}
	c := load(t)
	rows := []boundaryVector{}
	add := func(e *codec.Encoding, v map[string]int64) {
		t.Helper()
		b, err := c.Encode(e.ID, v)
		if err != nil {
			t.Fatal(e.ID, v, err)
		}
		cpu := "v850e3v5"
		// The source's per-form predicates determine the assembler profile too.
		for _, n := range []string{"v850e3v5", "v850e2v3", "v850e2", "v850e1", "v850e", "v850"} {
			active := c.FeatureSets[n+"+extension"]
			found := false
			for _, f := range active {
				if f == e.Features[0] {
					found = true
				}
			}
			if found {
				cpu = n
				break
			}
		}
		rows = append(rows, boundaryVector{e.ID, cpu, oracleText(e, v), hex.EncodeToString(b), v})
	}
	seen := map[string]bool{}
	for j := range c.Encodings {
		e := &c.Encodings[j]
		for _, o := range e.Operands {
			if seen[o.Class] {
				continue
			}
			seen[o.Class] = true
			var ns []int64
			switch o.Class {
			case "D9", "D9_RELAX":
				ns = []int64{-256, -2, 0, 254}
			case "D16_15":
				ns = []int64{-32768, -2, 0, 32766}
			case "D16", "D16_16", "I16", "IMM16LO":
				ns = []int64{-32768, -1, 0, 32767}
			case "D16_LOOP":
				ns = []int64{-65534, -2, 0}
			case "D17_16":
				ns = []int64{-65536, -2, 0, 65534}
			case "D22":
				ns = []int64{-2097152, -2, 0, 2097150}
			case "D23":
				ns = []int64{-4194304, -1, 0, 4194303}
			case "D23_ALIGN1":
				ns = []int64{-4194304, -2, 0, 4194302}
			case "D32_31", "D32_31_PCREL":
				ns = []int64{-2147483648, -2, 0, 2147483646}
			case "IMM32":
				ns = []int64{0, 0x80000000, 0xffffffff}
			case "IMM16HI":
				ns = []int64{0, 0x80000000, 0xffff0000}
			case "I5DIV1":
				ns = []int64{2, 30}
			case "I5DIV2":
				ns = []int64{4, 30}
			case "I5DIV3":
				ns = []int64{2, 32}
			}
			for _, n := range ns {
				v := sample(e)
				v[o.Name] = n
				add(e, v)
			}
		}
		if e.Mnemonic == "prepare" && len(e.Operands) == 2 && e.Operands[0].Class == "LIST12" {
			for _, mask := range []int64{0, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4095} {
				v := sample(e)
				v["op0"] = mask
				add(e, v)
			}
		}
		if e.Mnemonic == "bins" {
			for pos := int64(0); pos < 32; pos++ {
				for width := int64(1); width <= 32-pos; width++ {
					v := sample(e)
					v["op1"] = pos
					v["op2"] = width
					if _, err := c.Encode(e.ID, v); err == nil {
						add(e, v)
					}
				}
			}
		}
	}
	dir := t.TempDir()
	if p := os.Getenv("MKASM_V850_ARTIFACT_DIR"); p != "" {
		dir = p
	}
	for _, cpu := range []string{"v850", "v850e", "v850e1", "v850e2", "v850e2v3", "v850e3v5"} {
		var source strings.Builder
		source.WriteString(".text\n")
		var want []byte
		for _, r := range rows {
			if r.CPU == cpu {
				source.WriteString(r.Assembly + "\n")
				b, _ := hex.DecodeString(r.Bytes)
				want = append(want, b...)
			}
		}
		if len(want) == 0 {
			continue
		}
		object := filepath.Join(dir, "boundary-"+cpu+".o")
		cmd := exec.Command(as, "-m"+cpu, "-mextension", "-o", object)
		cmd.Stdin = strings.NewReader(source.String())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v %s", cpu, err, out)
		}
		f, err := elf.Open(object)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := f.Section(".text").Data()
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(actual) < len(want) || !bytes.Equal(actual[:len(want)], want) {
			offset := 0
			for _, r := range rows {
				if r.CPU == cpu {
					b, _ := hex.DecodeString(r.Bytes)
					if offset+len(b) > len(actual) || !bytes.Equal(actual[offset:offset+len(b)], b) {
						t.Fatalf("boundary GNU mismatch at %d %s: actual %x expected %x", offset, r.Assembly, actual[offset:], b)
					}
					offset += len(b)
				}
			}
			t.Fatal("boundary length mismatch")
		}
		if !bytes.Equal(actual[len(want):], make([]byte, len(actual)-len(want))) {
			t.Fatal("nonzero assembler padding")
		}
		os.WriteFile(filepath.Join(dir, "boundary-"+cpu+".s"), []byte(source.String()), 0644)
	}
	data, _ := json.MarshalIndent(rows, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "gnu-boundaries.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d independent GNU boundary cases, including all 528 legal bit insertion ranges", len(rows))
}

func TestRetainedGNUBoundaries(t *testing.T) {
	c := load(t)
	data, err := os.ReadFile("testdata/gnu-boundaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []boundaryVector
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) < 600 {
		t.Fatal("incomplete boundary corpus", len(rows))
	}
	for _, r := range rows {
		b, err := c.Encode(r.ID, r.Values)
		want, _ := hex.DecodeString(r.Bytes)
		if err != nil || !bytes.Equal(b, want) {
			t.Fatal(r.ID, r.Values, err)
		}
	}
}
