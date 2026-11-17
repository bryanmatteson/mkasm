package v850

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"os"
	"strings"
	"testing"
)

func TestRetainedGNU(t *testing.T) {
	c := load(t)
	data, err := os.ReadFile("testdata/gnu-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []vector
	if err = json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 403 {
		t.Fatal(len(rows))
	}
	for j, row := range rows {
		e := &c.Encodings[j]
		if row.ID != e.ID {
			t.Fatal("source order differs")
		}
		want, err := hex.DecodeString(row.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.Encode(e.ID, sample(e))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("GNU %s %x != %x %v", row.ID, got, want, err)
		}
		if !e.AssemblyOnly {
			d, err := c.DecodeWithFeatures(want, c.FeatureSets[row.CPU+"+extension"])
			if err != nil {
				t.Fatal(row.ID, err)
			}
			back, err := c.Encode(d.Encoding.ID, d.Values)
			if err != nil || !bytes.Equal(back, want) {
				t.Fatal(row.ID, err)
			}
			for n := 0; n < len(want); n++ {
				if _, err := c.DecodeWithFeatures(want[:n], c.FeatureSets[row.CPU+"+extension"]); !errors.Is(err, codec.ErrTruncated) {
					t.Fatalf("%s prefix%d: %v", row.ID, n, err)
				}
			}
		}
	}
}

func TestMalformed(t *testing.T) {
	c := load(t)
	// GNU binutils 2.44 v850e3v5 objdump prints .long for this
	// unallocated encoding, rather than an instruction.
	reserved := []byte{0xe0, 0x07, 0x02, 0x00}
	if _, err := c.Decode(reserved); !errors.Is(err, codec.ErrUnknown) {
		t.Fatal("reserved encoding", err)
	}
	// bins r1,4,0,r2: the bit fields imply a zero semantic width.
	if _, err := c.Decode([]byte{0xe1, 0x17, 0xd8, 0x30}); !errors.Is(err, codec.ErrUnknown) {
		t.Fatal("zero-width bins", err)
	}
	for _, text := range []string{"prepare {r20", "dispose 4,{r20},[lp", "ld.w 8[gp", "ld.w 8[gp],r32", "jarl 0x1001,lp"} {
		if _, err := c.Assemble(text, 0x1000); err == nil {
			t.Fatal("malformed text", text)
		}
	}
	if _, err := Parse(strings.NewReader("const struct v850_opcode v850_opcodes[] = {};"), "v850"); err == nil {
		t.Fatal("partial source accepted")
	}
}

func FuzzDecode(f *testing.F) {
	source, err := os.Open("testdata/v850-opc.c")
	if err != nil {
		f.Fatal(err)
	}
	c, err := Parse(source, "v850")
	source.Close()
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add([]byte{0xe0, 0x07, 0x02, 0x00})
	for j := range c.Encodings {
		e := &c.Encodings[j]
		b, err := c.Encode(e.ID, sample(e))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := c.Decode(data)
		if err != nil {
			return
		}
		if d.Length <= 0 || d.Length > len(data) {
			t.Fatal("invalid decoded frame", d.Length, len(data))
		}
		b, err := c.Encode(d.Encoding.ID, d.Values)
		if err != nil || !bytes.Equal(b, data[:d.Length]) {
			t.Fatalf("accepted instruction cannot reencode %x %v", data, err)
		}
	})
}
func TestListsProfilesAndTemplates(t *testing.T) {
	c := load(t)
	a, err := c.Assemble("prepare {r22,r20,r21},4,sp", 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Assemble("prepare {r20-r22},4,sp", 0)
	if err != nil || !bytes.Equal(a[0], b[0]) {
		t.Fatal(err)
	}
	for _, bad := range []string{"prepare {r19},4,sp", "prepare {r20,r20},4,sp", "prepare {r22-r20},4,sp", "divh r0,r2", "mov r1,r0", "ld.dw 4[r4],r3", "fetrap 0", "adf sa,r1,r2,r3", "bins r1,31,2,r2", "bins r1,0,0,r2", "jr 0x1001", "loop r1,0x1002"} {
		if _, err := c.Assemble(bad, 0x1000); err == nil {
			t.Fatalf("invalid text accepted %q", bad)
		}
	}
	if _, err := c.AssembleWithFeatures("prepare {r20},4,sp", 0, c.FeatureSets["v850"]); err == nil {
		t.Fatal("base CPU admitted prepare")
	}
	if _, err := c.AssembleWithFeatures("prepare {r20},4,sp", 0, c.FeatureSets["v850e"]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AssembleWithFeatures("divn 8,r1,r2,r3", 0, c.FeatureSets["v850e"]); err == nil {
		t.Fatal("extension admitted by plain profile")
	}
	if _, err := c.AssembleWithFeatures("divn 8,r1,r2,r3", 0, c.FeatureSets["v850e+extension"]); err != nil {
		t.Fatal(err)
	}
	template, err := c.Template("add_000")
	if err != nil {
		t.Fatal(err)
	}
	template.Set("op0", 1)
	template.Set("op1", 2)
	encoded, err := template.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if values, err := template.Match(encoded); err != nil || values["op0"] != 1 || values["op1"] != 2 {
		t.Fatal(values, err)
	}
}
