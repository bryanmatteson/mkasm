package pic

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"os"
	"strings"
	"testing"
)

type reference struct {
	ID, Bytes, Encoded, Error string
	SourceBytes               string `json:"source_bytes"`
	Length                    int
	Instruction               bool
}

func references(t *testing.T, path string) []reference {
	t.Helper()
	f, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	z, e := gzip.NewReader(f)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	var rows []reference
	if e := json.NewDecoder(z).Decode(&rows); e != nil {
		t.Fatal(e)
	}
	return rows
}
func TestRetainedOracles(t *testing.T) {
	all := map[string]codec.Encoding{}
	for _, arch := range architectures {
		c, err := Parse(nil, arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range c.Encodings {
			all[e.ID] = e
		}
	}
	for _, v := range []struct {
		path                 string
		count, exact, errors int
	}{{"testdata/ghidra-vectors.json.gz", 23607, 23180, 6}, {"testdata/gputils-vectors.json.gz", 3989, 3988, 0}} {
		rows := references(t, v.path)
		if len(rows) != v.count {
			t.Fatal(v.path, len(rows))
		}
		exact, errors := 0, 0
		seen := map[string]bool{}
		for _, r := range rows {
			e, ok := all[r.ID]
			if !ok || seen[r.ID] {
				t.Fatal(r.ID)
			}
			seen[r.ID] = true
			b, err := codec.Encode(&e, sample(&e))
			if err != nil || hex.EncodeToString(b) != r.Bytes {
				t.Fatal(r.ID, hex.EncodeToString(b), r.Bytes, err)
			}
			if r.Length > 0 && r.Length != len(b) {
				t.Fatal(r.ID, r.Length)
			}
			expected := r.Bytes
			if r.SourceBytes != "" {
				if r.ID != "pic18_L1831_1" || r.SourceBytes != "00fa" || r.Bytes != "00ea" {
					t.Fatal(r)
				}
				expected = r.SourceBytes
			}
			if r.Encoded == expected {
				exact++
			}
			if r.Error != "" {
				errors++
			}
			if r.Encoded != "" && !strings.Contains(v.path, "ghidra") {
				raw, err := hex.DecodeString(r.Encoded)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(raw, b) && r.ID != "pic14-enhanced_L845_2" {
					t.Fatal("unexpected assembler normalization", r.ID)
				}
			}
		}
		if exact != v.exact || errors != v.errors {
			t.Fatal(v.path, exact, errors)
		}
	}
}
