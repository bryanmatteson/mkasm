package xtensa

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func fixture(t *testing.T, arch string) *Catalog {
	t.Helper()
	f, err := os.Open("testdata/llvm.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := Parse(f, arch)
	if err != nil {
		t.Fatal(err)
	}
	return b.(*Catalog)
}
func TestParse(t *testing.T) {
	for _, arch := range []string{"xtensa", "xtensaeb"} {
		c := fixture(t, arch)
		t.Log(arch, len(c.Core.Encodings), len(c.Slots.Encodings), c.Core.Unsupported)
		if len(c.Core.Encodings) != 611 {
			t.Fatal("incomplete source corpus")
		}
		if arch == "xtensa" && len(c.Slots.Encodings) != 184 {
			t.Fatal("missing FLIX slots")
		}
	}
}

func TestCompletePhysicalSourceAccounting(t *testing.T) {
	c := fixture(t, "xtensa")
	data, err := os.ReadFile("testdata/llvm.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	var instances map[string][]string
	_ = json.Unmarshal(raw["!instanceof"], &instances)
	ids := map[string]bool{}
	names := map[string]bool{}
	for _, table := range []*codec.Catalog{c.Core, c.Slots} {
		for _, e := range table.Encodings {
			ids[e.ID] = true
			names[e.Mnemonic] = true
		}
	}
	physical := 0
	for _, id := range instances["Instruction"] {
		var r record
		_ = json.Unmarshal(raw[id], &r)
		if s(r["Namespace"]) == "Xtensa" && n(r["isPseudo"]) == 0 && s(r["AsmString"]) != "" {
			physical++
			if !ids[id] {
				t.Errorf("physical LLVM record missing %s", id)
			}
		}
	}
	if physical != 284 {
		t.Fatal("LLVM physical count", physical)
	}
	for _, id := range instances["InstAlias"] {
		if !ids[id] {
			t.Error("LLVM alias missing", id)
		}
	}
	var source gnuCorpus
	if err := json.Unmarshal(gnuData, &source); err != nil {
		t.Fatal(err)
	}
	if len(source.Forms) != 690 {
		t.Fatal("GNU slot corpus count", len(source.Forms))
	}
	unique := map[string]bool{}
	for _, f := range source.Forms {
		unique[f.Name] = true
		if !names[f.Name] {
			t.Error("GNU opcode missing", f.Name)
		}
		if f.Format >= 3 {
			id := fmt.Sprintf("GNU_%d_%s", f.Slot, f.Name)
			if !ids[id] {
				t.Error("GNU FLIX slot form missing", id)
			}
		}
	}
	if len(unique) != 530 {
		t.Fatal("GNU opcode names", len(unique))
	}
}
