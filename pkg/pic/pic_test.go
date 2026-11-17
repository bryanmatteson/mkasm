package pic

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

var architectures = []string{"pic12", "pic14", "pic17", "pic18", "pic24", "dspic"}

func sample(e *codec.Encoding) map[string]int64 {
	v := map[string]int64{}
	for _, o := range e.Operands {
		raw := int64(0)
		if len(o.Names) > 0 {
			for i, n := range o.Names {
				if n != "" {
					raw = int64(i)
					break
				}
			}
		}
		if len(o.Lookup) > 0 {
			raw = o.Lookup[raw]
		}
		s := o.Scale
		if s == 0 {
			s = 1
		}
		v[o.Name] = raw*s + o.Bias
	}
	for _, o := range e.Operands {
		if o.BiasOperand != "" {
			s := o.BiasScale
			if s == 0 {
				s = 1
			}
			v[o.Name] += v[o.BiasOperand] * s
		}
	}
	return v
}
func TestCorpus(t *testing.T) {
	want := map[string]int{"pic12": 222, "pic14": 290, "pic17": 559, "pic18": 2918, "pic24": 7545, "dspic": 12073}
	for _, arch := range architectures {
		c, err := Parse(nil, arch)
		if err != nil {
			t.Fatal(arch, err)
		}
		if len(c.Encodings) != want[arch] {
			t.Fatalf("%s coverage %d", arch, len(c.Encodings))
		}
		for _, e := range c.Encodings {
			values := sample(&e)
			b, err := codec.Encode(&e, values)
			if err != nil {
				t.Fatal(e.ID, err)
			}
			one := &codec.Catalog{Encodings: []codec.Encoding{e}}
			d, err := one.Decode(b)
			if err != nil {
				t.Fatal(e.ID, err)
			}
			round, err := codec.Encode(d.Encoding, d.Values)
			if err != nil || !bytes.Equal(round, b) {
				t.Fatal(e.ID, err)
			}
			forms, err := one.Assemble(d.Format(0x1000), 0x1000)
			found := false
			for _, x := range forms {
				found = found || bytes.Equal(x, b)
			}
			if err != nil || !found {
				t.Fatalf("%s text %q: %v", e.ID, d.Format(0x1000), err)
			}
		}
	}
}

type oracleRow struct {
	ID, Language, Bytes, Assembly, Address string
	Context                                map[string]string `json:"context,omitempty"`
}

func TestExportOracle(t *testing.T) {
	dir := os.Getenv("MKASM_PIC_ORACLE")
	if dir == "" {
		t.Skip("set MKASM_PIC_ORACLE to export full independent oracle input")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "requests.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	var src corpus
	json.Unmarshal(Source, &src)
	languages := map[string]string{}
	for i, p := range profileNames {
		languages[p] = src.Profiles[i].Language
	}
	for _, arch := range architectures {
		c, err := Parse(nil, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range c.Encodings {
			v := sample(&e)
			b, err := codec.Encode(&e, v)
			if err != nil {
				t.Fatal(err)
			}
			profile := strings.Split(e.ID, "_L")[0]
			hardwareProfile := profile
			if len(e.Features) > 0 {
				hardwareProfile = strings.TrimPrefix(e.Features[0], "pic-")
			}
			r := map[string]any{"profile": hardwareProfile, "id": e.ID, "language": languages[profile], "bytes": hex.EncodeToString(b), "address": "0x800"}
			if strings.HasPrefix(profile, "pic24") || strings.HasPrefix(profile, "dspic") {
				r["context"] = map[string]string{"phase": "2"}
			}
			if contains(e.Features, "ghidra-macros") {
				r["context"] = map[string]string{"doPseudo": "1"}
			}
			if err := enc.Encode(r); err != nil {
				t.Fatal(err)
			}
		}
	}
}
func TestGenerate(t *testing.T) {
	dir := os.Getenv("MKASM_PIC_GENERATE")
	if dir == "" {
		t.Skip("set MKASM_PIC_GENERATE for all generated standalone crates")
	}
	for _, arch := range architectures {
		c, err := Parse(nil, arch)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.GenerateRust(filepath.Join(dir, arch)); err != nil {
			t.Fatal(err)
		}
	}
}
func FuzzBytes(f *testing.F) {
	c, err := Parse(nil, "pic18")
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range []string{"0000", "12c034f0", "01d0", "ffff"} {
		b, _ := hex.DecodeString(s)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		d, err := c.DecodeWithFeatures(b, c.FeatureSets["default"])
		if err != nil {
			return
		}
		round, err := codec.Encode(d.Encoding, d.Values)
		if err != nil || !bytes.Equal(round, b[:d.Length]) {
			t.Fatalf("%x %s %v", b, fmt.Sprint(d), err)
		}
	})
}
