package tricore

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// The complete sequence is independently assembled by Ghidra. It computes a
// value, stores and loads it, compares the result, and skips a clear on success.
// This validates the instruction stream and targets; it does not execute it.
var sequenceText = []string{"mov d2,#5", "mov d3,#7", "add d2,d3", "st.w [a10],d2", "ld.w d4,[a10]", "jeq d4,d2,0x1010", "mov d4,#0", "ret"}
var sequenceBytes = []byte{0x82, 0x52, 0x82, 0x73, 0x42, 0x32, 0x74, 0xa2, 0x54, 0xa4, 0x5f, 0x24, 0x03, 0x00, 0x82, 0x04, 0x00, 0x90}

func TestInstructionSequence(t *testing.T) {
	c, err := Parse(nil, "tricore")
	if err != nil {
		t.Fatal(err)
	}
	offset := 0
	for i, text := range sequenceText {
		address := uint64(0x1000 + offset)
		d, err := c.DecodeWithFeatures(sequenceBytes[offset:], c.FeatureSets["v2"])
		if err != nil {
			t.Fatal(err)
		}
		all, err := c.AssembleWithFeatures(text, address, c.FeatureSets["v2"])
		if err != nil {
			t.Fatal(err)
		}
		if !containsBytes(all, sequenceBytes[offset:offset+d.Length]) {
			t.Fatalf("%q: %x", text, all)
		}
		all, err = c.Assemble(d.Format(address), address)
		if err != nil || !containsBytes(all, sequenceBytes[offset:offset+d.Length]) {
			t.Fatalf("formatted stream%q: %v", d.Format(address), err)
		}
		if i == 5 {
			target, ok := d.BranchTarget(address)
			if !ok || target != 0x1010 || d.Encoding.FlowControl != "conditional_branch" {
				t.Fatalf("branch %x %v %+v", target, ok, d.Encoding)
			}
		}
		if i == 7 && d.Encoding.FlowControl != "return" {
			t.Fatal(d.Encoding.FlowControl)
		}
		offset += d.Length
	}
	if offset != len(sequenceBytes) {
		t.Fatal(offset)
	}
}
func containsBytes(all [][]byte, b []byte) bool {
	for _, v := range all {
		if bytes.Equal(v, b) {
			return true
		}
	}
	return false
}

func TestBoundariesAndProfiles(t *testing.T) {
	c, err := Parse(nil, "tricore")
	if err != nil {
		t.Fatal(err)
	}
	valid := []string{"mov d2,#-32768", "mov d2,#32767", "sh d2,d3,#-256", "sh d2,d3,#255", "sh d2,#-8", "sh d2,#7", "j 0xff001000", "j 0x1000ffe", "jla 0xf01ffffe", "lea a2,0xf0003fff", "ld.d e14,[a15]0", "mov d14/d15,d0,d1", "loop a2,0xfe0", "loop a2,0xffe", "jz d2,0x1000", "jeq d15,d2,0x103e"}
	for _, text := range valid {
		if _, err = c.AssembleWithFeatures(text, 0x1000, c.FeatureSets["v2"]); err != nil {
			t.Errorf("valid%q: %v", text, err)
		}
	}
	invalid := []string{"mov d2,#-32769", "mov d2,#32768", "mov d2,#65536", "sh d2,d3,#-257", "sh d2,d3,#256", "sh d2,#-9", "sh d2,#8", "j 0x1001", "j 0x1001000", "j 0xff000ffe", "jla 0xf0200000", "jla 0x1001", "lea a2,0xf0004000", "ld.d e3,[a0]0", "mov d3/d4,d0,d1", "add d16,d0"}
	for _, text := range invalid {
		if b, err := c.AssembleWithFeatures(text, 0x1000, c.FeatureSets["v2"]); err == nil {
			t.Errorf("invalid%q encoded%x", text, b)
		}
	}
	// The source profiles describe revision predicates. Ghidra's tc172x/tc176x/
	// tc29x language variants share one SLA, so they are not ISA profiles here.
	if _, err = c.AssembleWithFeatures("wait", 0, c.FeatureSets["v2"]); err != nil {
		t.Fatal(err)
	}
	if _, err = c.AssembleWithFeatures("wait", 0, c.FeatureSets["rider-b"]); err == nil {
		t.Fatal("V2 wait admitted by rider-b")
	}
	for _, text := range []string{"jl 0x1010", "jla 0x1000", "jli a2"} {
		all, _ := c.Assemble(text, 0x1000)
		for _, b := range all {
			d, _ := c.Decode(b)
			if d.Encoding.FlowControl != "call" {
				t.Fatal(text, d.Encoding.FlowControl)
			}
		}
	}
	for _, text := range []string{"ji a11", "ret"} {
		all, _ := c.Assemble(text, 0x1000)
		for _, b := range all {
			d, _ := c.Decode(b)
			if d.Encoding.FlowControl != "return" {
				t.Fatal(text, d.Encoding.FlowControl)
			}
		}
	}
	all, _ := c.Assemble("rslcx", 0)
	if len(all) == 0 {
		t.Fatal("missing rslcx")
	}
	d, _ := c.Decode(all[0])
	if d.Encoding.FlowControl != "next" {
		t.Fatal(d.Encoding.FlowControl)
	}
	for _, b := range [][]byte{nil, {0x0b}, {0x0b, 0}, {0x0b, 0, 0}} {
		if _, err = c.Decode(b); !errors.Is(err, codec.ErrTruncated) {
			t.Fatalf("truncated%x: %v", b, err)
		}
	}
	// A signed scaled target wraps at the architectural 32-bit address boundary.
	all, err = c.Assemble("j 0x0", 0xfffffffe)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range all {
		d, _ := c.Decode(b)
		target, ok := d.BranchTarget(0xfffffffe)
		if !ok || target != 0 {
			t.Fatal(target, ok)
		}
	}
	// A 4-bit loop displacement covers only the preceding 32..2 bytes.
	found := false
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if e.Mnemonic != "loop" || len(e.Mask) != 2 {
			continue
		}
		found = true
		v := sample(e)
		for _, o := range e.Operands {
			if o.Relative {
				for _, bad := range []int64{-34, 0, 2} {
					v[o.Name] = bad
					if _, err = codec.Encode(e, v); err == nil {
						t.Errorf("short loop displacement%d accepted", bad)
					}
				}
				for _, good := range []int64{-32, -2} {
					v[o.Name] = good
					if _, err = codec.Encode(e, v); err != nil {
						t.Error(err)
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("missing short loop")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestMalformedSource(t *testing.T) {
	if _, err := Parse(nil, "tricore64"); err == nil {
		t.Fatal("unsupported architecture accepted")
	}
	if _, err := Parse(failingReader{}, "tricore"); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	for _, arch := range []string{"tricore", "tricore-pcp"} {
		if _, err := Parse(strings.NewReader(""), arch); err == nil {
			t.Fatal("empty source accepted", arch)
		}
	}
	sources := []string{
		"define token instr (16) op=(0,15);\n@endif\n:nop is PCPMode=0 & op=0 {}",
		"define token instr (16) op=(0,15);\n@if defined(TRICORE_V2)\n:nop is PCPMode=0 & op=0 {}",
		"define token instr (16) op=(4,3);\n:nop is PCPMode=0 & op=0 {}",
		"define token instr (16) op=(0,16);\n:nop is PCPMode=0 & op=0 {}",
		"define token instr (16) op=(0,15);\nattach variables [missing] [r0];\n:nop is PCPMode=0 & op=0 {}",
		"define token instr (16) op=(0,15);\n:nop is PCPMode=0 & op=65536 {}",
		"define token instr (16) op=(0,15);\n:nop is PCPMode=0 & missing=0 {}",
		"define token instr (16) op=(0,15);\n:nop is PCPMode=0 & op=0 {",
		"define token instr (16) op=(0,15);\n:nop is PCPMode=0 & recur {}\nrecur: op is recur {}",
	}
	for i, s := range sources {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, err := Parse(strings.NewReader(s), "tricore"); err == nil {
				t.Fatal("malformed source accepted")
			}
		})
	}
	// Long source lines must not silently truncate subsequent records.
	s := strings.Replace(Source, "\n", "\n#"+strings.Repeat("x", 70000)+"\n", 1)
	if _, err := Parse(strings.NewReader(s), "tricore"); err != nil {
		t.Fatal(err)
	}
}
