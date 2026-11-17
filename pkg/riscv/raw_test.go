package riscv

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

const msetmtypeID = "unratified/rv_zvtbase::msetmtypei"

func zvtbaseFixture(t *testing.T, architecture string) *codec.Catalog {
	t.Helper()
	files := map[string][]byte{}
	for name, target := range map[string]string{"arg_lut.csv": "arg_lut.csv", "rv_zvtbase": "extensions/unratified/rv_zvtbase"} {
		data, err := os.ReadFile(filepath.Join("testdata", "zvtbase", name))
		if err != nil {
			t.Fatal(err)
		}
		files[target] = data
	}
	c, err := parseFiles(files, architecture)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Unsupported) != 0 {
		t.Fatalf("source definitions lost: %v", c.Unsupported)
	}
	return c
}

func msetmtypeEncoding(t *testing.T, c *codec.Catalog) *codec.Encoding {
	t.Helper()
	for i := range c.Encodings {
		if c.Encodings[i].ID == msetmtypeID {
			return &c.Encodings[i]
		}
	}
	t.Fatal("msetmtypei source record missing")
	return nil
}

func TestUnassignedSourceBitsRemainExact(t *testing.T) {
	for _, architecture := range []string{"riscv32", "riscv64"} {
		t.Run(architecture, func(t *testing.T) {
			c := zvtbaseFixture(t, architecture)
			e := msetmtypeEncoding(t, c)
			if got := binary.LittleEndian.Uint32(e.Mask); got != 0xee7e707f {
				t.Fatalf("source mask %#x; want upstream parser's 0xee7e707f", got)
			}
			if got := binary.LittleEndian.Uint32(e.Value); got != 0x88407057 {
				t.Fatalf("source match %#x; want upstream parser's 0x88407057", got)
			}
			if e.Syntax != "msetmtypei {rd}, {raw_28}, {raw_24_23}, {raw_16_15}" {
				t.Fatal("physical fields are not explicit:", e.Syntax)
			}
			for _, o := range e.Operands[1:] {
				if o.Class != "RawEncodingBits" || o.Implicit || o.Optional || o.Signed {
					t.Fatal("raw field has invented semantics or a default:", o)
				}
			}
			// Exhaust all ten variable bits: five named rd bits and the five
			// bits omitted from upstream's operand list. No value is discarded.
			for rd := int64(0); rd < 32; rd++ {
				for raw := int64(0); raw < 32; raw++ {
					values := map[string]int64{"rd": rd, "raw_28": raw >> 4, "raw_24_23": (raw >> 2) & 3, "raw_16_15": raw & 3}
					word := uint32(0x88407057 | rd<<7 | (raw>>4)<<28 | ((raw>>2)&3)<<23 | (raw&3)<<15)
					want := make([]byte, 4)
					binary.LittleEndian.PutUint32(want, word)
					b, err := c.Encode(e.ID, values)
					if err != nil || !bytes.Equal(b, want) {
						t.Fatalf("%v: %x, %v; want %x", values, b, err, want)
					}
					d, err := c.Decode(append(append([]byte{}, b...), 0x13, 0, 0, 0))
					if err != nil || d.Length != 4 || d.Encoding.ID != e.ID || !reflect.DeepEqual(d.Values, values) {
						t.Fatalf("exact decode %x: %+v, %v", b, d, err)
					}
					text := d.Format(0)
					assembled, err := c.Assemble(text, 0)
					found := false
					for _, candidate := range assembled {
						found = found || bytes.Equal(candidate, b)
					}
					if err != nil || !found {
						t.Fatalf("text %q: %x, %v; want %x", text, assembled, err, b)
					}
				}
			}
			for name, invalid := range map[string][]int64{"rd": {-1, 32}, "raw_28": {-1, 2}, "raw_24_23": {-1, 4}, "raw_16_15": {-1, 4}} {
				for _, value := range invalid {
					values := map[string]int64{"rd": 0, "raw_28": 0, "raw_24_23": 0, "raw_16_15": 0}
					values[name] = value
					if _, err := c.Encode(e.ID, values); err == nil {
						t.Fatalf("accepted %s=%d", name, value)
					}
				}
				values := map[string]int64{"rd": 0, "raw_28": 0, "raw_24_23": 0, "raw_16_15": 0}
				delete(values, name)
				if _, err := c.Encode(e.ID, values); err == nil {
					t.Fatalf("silently defaulted missing field %s", name)
				}
			}
			if _, err := c.Assemble("msetmtypei a0", 0); err == nil {
				t.Fatal("silently defaulted raw fields in text assembly")
			}
			single := &codec.Catalog{Encodings: []codec.Encoding{*e}}
			for bit := uint(0); bit < 32; bit++ {
				if uint32(0xee7e707f)&(1<<bit) == 0 {
					continue
				}
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, 0x88407057^(1<<bit))
				if _, err := single.Decode(b); err == nil {
					t.Fatalf("ignored fixed opcode bit %d", bit)
				}
			}
			for n := 0; n < 4; n++ {
				if _, err := single.Decode(e.Value[:n]); err == nil {
					t.Fatalf("accepted instruction truncated at %d bytes", n)
				}
			}
		})
	}
}

func TestUpstreamUnassignedBitsOracle(t *testing.T) {
	dir := os.Getenv("RISCV_OPCODES_DIR")
	if dir == "" {
		t.Skip("set RISCV_OPCODES_DIR to compare the actual upstream Python parser")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("upstream parser oracle requires python3:", err)
	}
	cmd := exec.Command(python, "-c", `import json, pathlib, sys
from riscv_opcodes.shared_utils import process_enc_line
p = pathlib.Path(sys.argv[1]) / "extensions/unratified/rv_zvtbase"
line = next(s for s in p.read_text().splitlines() if s.split() and s.split()[0] == "msetmtypei")
name, instruction = process_enc_line(line, str(p))
print(json.dumps(instruction))`, dir)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(dir, "src"), "PYTHONDONTWRITEBYTECODE=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("upstream parser: %v\n%s", err, output)
	}
	var oracle struct {
		Encoding       string   `json:"encoding"`
		VariableFields []string `json:"variable_fields"`
		Match          string   `json:"match"`
		Mask           string   `json:"mask"`
	}
	if err := json.Unmarshal(output, &oracle); err != nil {
		t.Fatal(err)
	}
	if oracle.Match != "0x88407057" || oracle.Mask != "0xee7e707f" || oracle.Encoding != "100-100--100000--111-----1010111" || !reflect.DeepEqual(oracle.VariableFields, []string{"rd"}) {
		t.Fatalf("upstream definition changed; review its raw-field semantics: %+v", oracle)
	}
	for _, architecture := range []string{"riscv32", "riscv64"} {
		c := upstream(t, architecture)
		e := msetmtypeEncoding(t, c)
		for bit, ch := range oracle.Encoding {
			p := uint(31 - bit)
			fixed := ch != '-'
			if got := binary.LittleEndian.Uint32(e.Mask)&(1<<p) != 0; got != fixed {
				t.Fatalf("%s mask differs from upstream at bit %d", architecture, p)
			}
		}
		if !strings.Contains(e.Syntax, "raw_28") {
			t.Fatal("upstream source lost its explicit raw fields")
		}
	}
}
