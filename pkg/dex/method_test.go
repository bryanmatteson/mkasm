package dex

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"os"
	"testing"
)

func TestMethodConstraints(t *testing.T) {
	c := load(t)
	for _, b := range [][]byte{
		{0x28, 2, 0x14, 0, 0, 0, 0, 0, 0x0e, 0}, // branch into constant data
		{0x28, 0x7f},                            // outside method
		{0, 0},                                  // reachable fallthrough
		{0x2b, 0, 4, 0, 0, 0, 0x0e, 0, 0, 2, 0, 0}, // wrong payload kind
		{0x28, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0},    // executable branch targets payload
		{0x26, 0, 3, 0, 0, 0, 0x0e, 0},             // data target not payload
	} {
		if _, e := c.DecodeMethod(b, 39); e == nil {
			t.Fatalf("bad method accepted %x", b)
		}
	}
	// An unreachable nop may align the payload following a return instruction.
	b := []byte{0x0e, 0, 0, 0, 0, 3, 1, 0, 1, 0, 0, 0, 8, 0}
	if _, e := c.DecodeMethod(b, 39); e != nil {
		t.Fatal(e)
	}
	data := make([]byte, 8)
	binary.LittleEndian.PutUint16(data, 0x100)
	binary.LittleEndian.PutUint16(data[2:], 1)
	binary.LittleEndian.PutUint32(data[4:], 0x7fffffff)
	data = append(data, 0, 0, 0, 0)
	if _, e := c.Decode(data, 1); e == nil {
		t.Fatal("unaligned payload")
	}
	binary.LittleEndian.PutUint16(data[2:], 2)
	data = append(data, 0, 0, 0, 0)
	if _, e := c.Decode(data, 0); e == nil {
		t.Fatal("key overflow")
	}
	sparse := []byte{0, 2, 2, 0, 5, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0}
	if _, e := c.Decode(sparse, 0); e == nil {
		t.Fatal("duplicate sparse keys")
	}
	wide := sample(*c.definition(0x18))
	if e := c.ValidateRegisters([]*Instruction{wide}, 4, 0, nil); e == nil {
		t.Fatal("wide register pair exceeds frame")
	}
	wide.Values["a"] = 2
	if e := c.ValidateRegisters([]*Instruction{wide}, 4, 0, nil); e != nil {
		t.Fatal(e)
	}
	inv := sample(*c.definition(0x6e))
	if e := c.ValidateRegisters([]*Instruction{inv}, 16, 4, nil); e == nil {
		t.Fatal("insufficient outs")
	}
	if e := c.ValidateRegisters([]*Instruction{inv}, 16, 5, PoolSizes{"Method": 5}); e == nil {
		t.Fatal("pool bounds")
	}
}
func TestCodeItemConstraints(t *testing.T) {
	c := load(t)
	b := make([]byte, 18)
	binary.LittleEndian.PutUint32(b[12:], 1)
	b[16] = 0x0e
	ci, e := c.DecodeCodeItem(b, 39)
	if e != nil {
		t.Fatal(e)
	}
	back, e := c.EncodeCodeItem(ci, 39)
	if e != nil || !bytes.Equal(back, b) {
		t.Fatal(e)
	}
	for n := 0; n < len(b); n++ {
		if _, e := c.DecodeCodeItem(b[:n], 39); !errors.Is(e, ErrTruncated) {
			t.Fatalf("prefix%d %v", n, e)
		}
	}
	ci.InsSize = 1
	if _, e := c.EncodeCodeItem(ci, 39); e == nil {
		t.Fatal("ins > registers")
	}
	ci.InsSize = 0
	ci.Tries = []Try{{0, 1, 0}}
	ci.Handlers = []CatchHandler{{CatchAll: new(uint32)}}
	back, e = c.EncodeCodeItem(ci, 39)
	if e != nil {
		t.Fatal(e)
	}
	ci, e = c.DecodeCodeItem(back, 39)
	if e != nil {
		t.Fatal(e)
	}
	ci.Tries[0].Count = 0
	if _, e := c.EncodeCodeItem(ci, 39); e == nil {
		t.Fatal("empty try")
	}
	ci.Tries[0].Count = 1
	*ci.Handlers[0].CatchAll = 1
	if _, e := c.EncodeCodeItem(ci, 39); e == nil {
		t.Fatal("catch outside code")
	}
}
func TestBoundaryValues(t *testing.T) {
	c := load(t)
	for _, d := range c.Instructions {
		if d.Reserved || d.Opcode >= 256 {
			continue
		}
		for _, f := range d.Fields {
			values := []int64{0}
			if f.Signed {
				if f.Width == 64 {
					values = append(values, -1, -9223372036854775808, 9223372036854775807)
				} else {
					values = append(values, -(int64(1) << uint(f.Width-1)), (int64(1)<<uint(f.Width-1))-1)
				}
			} else {
				values = append(values, (int64(1)<<uint(f.Width))-1)
			}
			for _, v := range values {
				in := sample(d)
				in.Values[f.Name] = int64(uint64(v) << uint(f.Shift))
				if f.Kind == "target" && v == 0 {
					continue
				}
				b, e := c.Encode(in, 100)
				if e != nil {
					t.Fatalf("%s %s=%d: %v", d.Mnemonic, f.Name, v, e)
				}
				got, e := c.Decode(b, 100)
				if e != nil || got.Values[f.Name] != in.Values[f.Name] {
					t.Fatalf("%s %s=%d got%v %v", d.Mnemonic, f.Name, v, got, e)
				}
			}
		}
	}
	for count := 0; count <= 5; count++ {
		in := sample(*c.definition(0x71))
		in.Registers = make([]uint16, count)
		b, e := c.Encode(in, 0)
		if e != nil {
			t.Fatal(e)
		}
		if got, e := c.Decode(b, 0); e != nil || len(got.Registers) != count {
			t.Fatal(e)
		}
	}
	for _, r := range []RegisterRange{{0, 0}, {65535, 0}, {65535, 1}, {65281, 255}} {
		in := sample(*c.definition(0x77))
		in.Range = &r
		b, e := c.Encode(in, 0)
		if e != nil {
			t.Fatal(e)
		}
		got, e := c.Decode(b, 0)
		if e != nil || *got.Range != r {
			t.Fatal(e)
		}
		if text := c.Format(got); text != "" {
			back, e := c.Assemble(text, 0)
			if e != nil || !bytes.Equal(b, back) {
				t.Fatal(text, e)
			}
		}
	}
}
func FuzzDecode(f *testing.F) {
	for _, b := range [][]byte{{0, 0}, {0x0e, 0}, {0, 3, 1, 0, 1, 0, 0, 0, 1, 0}, {0xfa, 0x10, 0, 0, 1, 0, 0, 0}} {
		f.Add(b, uint32(0))
	}
	f.Fuzz(func(t *testing.T, b []byte, offset uint32) {
		if len(b) > 4096 {
			return
		}
		c := fuzzCatalog
		in, e := c.Decode(b, offset)
		if e == nil {
			back, e := c.Encode(in, offset)
			if e != nil || !bytes.Equal(back, b[:in.Length]) {
				t.Fatalf("%x %v", back, e)
			}
			text := c.Format(in)
			round, e := c.Assemble(text, offset)
			if e != nil || !bytes.Equal(round, back) {
				t.Fatalf("%q %v", text, e)
			}
		}
		_, _ = c.DecodeCodeItem(b, 39)
		_, _ = c.DecodeDEX(b)
	})
}

var fuzzCatalog *Catalog

func TestMain(m *testing.M) {
	data, e := os.ReadFile("testdata/dex_instruction_list.h")
	if e != nil {
		panic(e)
	}
	fuzzCatalog, e = Parse(bytes.NewReader(data), "dex")
	if e != nil {
		panic(e)
	}
	os.Exit(m.Run())
}
func TestRandomDecode(t *testing.T) {
	r := rand.New(rand.NewSource(78))
	c := load(t)
	for j := 0; j < 100000; j++ {
		b := make([]byte, r.Intn(64))
		r.Read(b)
		in, e := c.Decode(b, uint32(j%6))
		if e == nil {
			back, e := c.Encode(in, in.Offset)
			if e != nil || !bytes.Equal(back, b[:in.Length]) {
				t.Fatalf("%x %v", back, e)
			}
		}
		_, _ = c.DecodeCodeItem(b, 39)
	}
}
