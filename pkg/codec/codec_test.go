package codec

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func exampleCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := NewCatalog("example", "test", []Encoding{
		{ID: "MOV", Mnemonic: "mov", Syntax: "mov {Rd}, {imm}", Mask: []byte{0xf0, 0}, Value: []byte{0x80, 0}, Operands: []Operand{
			{Name: "Rd", Kind: "register", RegisterPrefix: "r", Names: []string{"r0", "r1", "r2", "r3"}, Bits: []BitSlice{{0, 0, 4}}},
			{Name: "imm", Kind: "immediate", Signed: true, Scale: 2, Bits: []BitSlice{{8, 0, 8}}},
		}},
		{ID: "CLR", Mnemonic: "clr", Syntax: "clr {Rd}", Mask: []byte{0xf0}, Value: []byte{0x90}, Operands: []Operand{{Name: "Rd", Kind: "register", RegisterPrefix: "r", Bits: []BitSlice{{0, 0, 2}, {2, 0, 2}}}}},
		{ID: "BR", FlowControl: "branch", Mnemonic: "br", Syntax: "br {Target}", Mask: []byte{255, 0}, Value: []byte{0xa0, 0}, Operands: []Operand{{Name: "Target", Kind: "displacement", Signed: true, Scale: 2, Relative: true, PCBias: 2, Bits: []BitSlice{{8, 0, 8}}}}},
		{ID: "WRAP", FlowControl: "branch", Mnemonic: "wrap", Syntax: "wrap {Target}", Mask: []byte{255, 0}, Value: []byte{0xb0, 0}, Operands: []Operand{{Name: "Target", Kind: "displacement", Signed: true, InputSignedBits: 16, Scale: 2, Relative: true, PCBias: 2, PCWrapBits: 16, Bits: []BitSlice{{8, 0, 8}}}}},
		{ID: "REGION", FlowControl: "branch", Mnemonic: "jump", Syntax: "jump {Target}", Mask: []byte{255, 0}, Value: []byte{0xb1, 0}, Operands: []Operand{{Name: "Target", Kind: "address", Relative: true, PCBias: 2, PCRegionBits: 8, Bits: []BitSlice{{8, 0, 8}}}}},
		{ID: "WRAP_REGION", FlowControl: "branch", Mnemonic: "pagejump", Syntax: "pagejump {Target}", Mask: []byte{255, 0}, Value: []byte{0xea, 0}, Operands: []Operand{{Name: "Target", Kind: "address", Relative: true, PCBias: 2, PCRegionBits: 8, PCWrapBits: 16, Bits: []BitSlice{{8, 0, 8}}}}},
		{ID: "LOW", FlowControl: "branch", Mnemonic: "low", Syntax: "low {Target}", Mask: []byte{255, 0}, Value: []byte{0xb3, 0}, Operands: []Operand{{Name: "Target", Kind: "displacement", Signed: true, Scale: 2, Relative: true, PCBias: 2, PCWrapBits: 20, PCLowWrapBits: 16, Bits: []BitSlice{{8, 0, 8}}}}},
		{ID: "REPEAT", Mnemonic: "rpt", Syntax: "rpt #{count} {{ inc {src}", Mask: []byte{255, 0xfc, 0, 0}, Value: []byte{0xb2, 0, 0, 0}, Operands: []Operand{
			{Name: "count", Kind: "immediate", Bits: []BitSlice{{8, 0, 2}}},
			{Name: "src", Kind: "immediate", Signed: true, Bits: []BitSlice{{16, 0, 8}}},
			{Name: "dup", Kind: "immediate", Signed: true, Implicit: true, Bias: 2, BiasOperand: "src", Bits: []BitSlice{{24, 0, 8}}},
		}},
		{ID: "BLOCK", Mnemonic: "block", Syntax: "block {dst}, {count}", Mask: []byte{0xf0}, Value: []byte{0xc0}, Operands: []Operand{
			{Name: "dst", Kind: "register", RegisterPrefix: "r", Names: []string{"0", "r1", "r2", "r3"}, Bits: []BitSlice{{0, 0, 2}}},
			{Name: "count", Kind: "immediate", Bits: []BitSlice{{2, 0, 2}}},
		}, Constraints: []Constraint{{Kind: "diff_ge", Left: "dst", Right: "count", Limit: -1}}},
		{ID: "U64", Mnemonic: "u64", Syntax: "u64 {value}", Mask: []byte{0xff, 0, 0, 0, 0, 0, 0, 0, 0}, Value: []byte{0xd0, 0, 0, 0, 0, 0, 0, 0, 0}, Operands: []Operand{{Name: "value", Kind: "immediate", Bits: []BitSlice{{8, 0, 64}}}}},
		{ID: "S64", Mnemonic: "s64", Syntax: "s64 {value}", Mask: []byte{0xff, 0, 0, 0, 0, 0, 0, 0, 0}, Value: []byte{0xd1, 0, 0, 0, 0, 0, 0, 0, 0}, Operands: []Operand{{Name: "value", Kind: "immediate", Signed: true, Bits: []BitSlice{{8, 0, 64}}}}},
		{ID: "GPU", Mnemonic: "gpu", Syntax: "gpu {src}{clamp}{offset}", Mask: []byte{255, 0xf0}, Value: []byte{0xe0, 0}, Operands: []Operand{
			{Name: "src", Kind: "register", Names: []string{"r0", "r1", "r2", "r3"}, Bits: []BitSlice{{8, 0, 2}}},
			{Name: "clamp", Kind: "immediate", Names: []string{" ", " clamp"}, Bits: []BitSlice{{10, 0, 1}}},
			{Name: "offset", Kind: "immediate", Names: []string{" ", " offset:4"}, Bits: []BitSlice{{11, 0, 1}}},
		}},
		{ID: "CASE", Mnemonic: "case", Syntax: "case {Ii}, {II}", Mask: []byte{255, 0}, Value: []byte{0xe1, 0}, Operands: []Operand{{Name: "Ii", Kind: "immediate", Bits: []BitSlice{{8, 0, 4}}}, {Name: "II", Kind: "immediate", Bits: []BitSlice{{12, 0, 4}}}}},
		{ID: "MEMORY", Mnemonic: "addmem", Syntax: "addmem {src}, {dst}", Mask: []byte{255, 0, 0, 0, 0}, Value: []byte{0xe2, 0, 0, 0, 0}, Operands: []Operand{
			{Name: "src", Kind: "displacement", Signed: true, Relative: true, PCBias: 1, PCWrapBits: 20, PCLowWrapBits: 16, Bits: []BitSlice{{8, 0, 16}}},
			{Name: "dst", Kind: "displacement", Signed: true, Relative: true, PCBias: 3, PCWrapBits: 20, PCLowWrapBits: 16, Bits: []BitSlice{{24, 0, 16}}},
		}},
		{ID: "SYMBOLIC_ALIAS", Mnemonic: "twice", Syntax: "twice {src}", AssemblyOnly: true, Mask: []byte{255, 0, 0, 0, 0}, Value: []byte{0xe2, 0, 0, 0, 0}, Operands: []Operand{
			{Name: "src", Kind: "displacement", Signed: true, Relative: true, PCBias: 1, PCWrapBits: 20, PCLowWrapBits: 16, Bits: []BitSlice{{8, 0, 16}}},
			{Name: "dup", Kind: "immediate", Signed: true, Implicit: true, Bias: 2, BiasOperand: "src", BiasScale: -1, PCBias: 3, PCWrapBits: 20, PCLowWrapBits: 16, Bits: []BitSlice{{24, 0, 16}}},
		}, Constraints: []Constraint{{Kind: "encoded_targets_eq", Left: "src", Right: "dup"}}},
		{ID: "DIGIT_MNEMONIC", Mnemonic: "ld.w23", Syntax: "ld.w23 {offset}[gp],gp", Mask: []byte{255, 0}, Value: []byte{0xe3, 0}, Operands: []Operand{{Name: "offset", Kind: "displacement", Signed: true, Bits: []BitSlice{{8, 0, 8}}}}},
		{ID: "MEM_OFFSET", Mnemonic: "mem", Syntax: "mem ({base}+{offset})", Mask: []byte{255, 0xf0, 0}, Value: []byte{0xe4, 0, 0}, Operands: []Operand{{Name: "base", Kind: "register", RegisterPrefix: "r", Bits: []BitSlice{{8, 0, 4}}}, {Name: "offset", Kind: "displacement", Signed: true, Bits: []BitSlice{{16, 0, 8}}}}},
		{ID: "ALIGNED", FlowControl: "branch", Mnemonic: "aligned", Syntax: "aligned {Target}", Mask: []byte{255, 0}, Value: []byte{0xe5, 0}, Operands: []Operand{{Name: "Target", Kind: "displacement", Signed: true, Relative: true, PCAlignBits: 2, PCBias: 2, PCWrapBits: 32, Bits: []BitSlice{{8, 0, 8}}}}},
		{ID: "PRE_ALIGN", FlowControl: "branch", Mnemonic: "litbase", Syntax: "litbase {Target}", Mask: []byte{255, 0}, Value: []byte{0xe7, 0}, Operands: []Operand{{Name: "Target", Kind: "displacement", Signed: true, Relative: true, PCPreAlignBias: 3, PCAlignBits: 2, PCWrapBits: 32, Bits: []BitSlice{{8, 0, 8}}}}},
		{ID: "LOOKUP", Mnemonic: "lut", Syntax: "lut {number},{offset}", Mask: []byte{255, 0xf0}, Value: []byte{0xe6, 0}, Operands: []Operand{
			{Name: "number", Kind: "immediate", Bits: []BitSlice{{8, 0, 2}}, Lookup: []int64{-1, 1, 10, 256}, Names: []string{"minus", "one", "ten", "wide"}, Scale: 2, Bias: 1, Xor: 1},
			{Name: "offset", Kind: "immediate", Bits: []BitSlice{{10, 0, 2}}, Lookup: []int64{-32, 0, 31}},
		}},
		{ID: "SIGNED_BOUNDARY", Mnemonic: "boundary", Syntax: "boundary {value}", Mask: []byte{255, 0, 0, 0, 0}, Value: []byte{0xe8, 0, 0, 0, 0}, Operands: []Operand{
			{Name: "value", Kind: "immediate", Signed: true, Bits: []BitSlice{{8, 0, 16}}},
			{Name: "dup", Kind: "immediate", Signed: true, Implicit: true, Bias: -65534, BiasOperand: "value", BiasScale: -1, Bits: []BitSlice{{24, 0, 16}}},
		}, Constraints: []Constraint{{Kind: "eq", Left: "dup"}, {Kind: "sum_le", Left: "value", Limit: -32767}}},
		{ID: "TUPLES", Mnemonic: "tuples", Syntax: "tuples {dmask},{d16},{tfe},{dim}", Mask: []byte{255, 0}, Value: []byte{0xe9, 0}, Operands: []Operand{
			{Name: "dmask", Kind: "immediate", Bits: []BitSlice{{8, 0, 4}}},
			{Name: "d16", Kind: "immediate", Bits: []BitSlice{{12, 0, 1}}},
			{Name: "tfe", Kind: "immediate", Bits: []BitSlice{{13, 0, 1}}},
			{Name: "dim", Kind: "immediate", Bits: []BitSlice{{14, 0, 2}}},
		}, Constraints: []Constraint{
			{Kind: "tuple_in", Operands: []string{"dmask", "d16", "tfe"}, Allowed: [][]int64{{3, 1, 0}, {7, 0, 1}}},
			{Kind: "tuple_in", Operands: []string{"dim"}, Allowed: [][]int64{{1}, {2}}},
		}},
		{ID: "PADDING", Mnemonic: "padding", Syntax: "padding {value}", Mask: []byte{255, 0}, Value: []byte{0xeb, 0}, Operands: []Operand{
			{Name: "ignored", Kind: "immediate", Optional: true, Bits: []BitSlice{{12, 0, 4}}},
			{Name: "value", Kind: "immediate", Bits: []BitSlice{{8, 0, 4}}},
		}},
		{ID: "ABS_CALL", Mnemonic: "abs_call", Syntax: "abs_call {target}", FlowControl: "call", Mask: []byte{255, 0, 0}, Value: []byte{0xef, 0, 0}, Operands: []Operand{
			{Name: "target", Kind: "address", Bits: []BitSlice{{8, 0, 16}}},
		}},
		{ID: "MEM_ADDRESS", Mnemonic: "read", Syntax: "read {address}", FlowControl: "next", Mask: []byte{255, 0, 0}, Value: []byte{0xf0, 0, 0}, Operands: []Operand{
			{Name: "address", Kind: "address", Bits: []BitSlice{{8, 0, 16}}},
		}},
		{ID: "IMPLICIT_TARGET", Mnemonic: "implicit", Syntax: "implicit {target}", Mask: []byte{255, 0xf0}, Value: []byte{0xf3, 0}, Operands: []Operand{
			{Name: "target", Kind: "displacement", Implicit: true, Relative: true, PCAlignBits: 2, PCWrapBits: 32, Bits: []BitSlice{{8, 0, 4}}},
		}},
		{ID: "VISIBLE_OPTIONAL", Mnemonic: "visible", Syntax: "visible {value}", Mask: []byte{255, 0xf0}, Value: []byte{0xf4, 0}, Operands: []Operand{
			{Name: "value", Kind: "immediate", Optional: true, Bits: []BitSlice{{8, 0, 4}}},
		}},
		{ID: "DOLLAR_LITERAL", Mnemonic: "divide", Syntax: "divide $zero, {source}, {target}", Mask: []byte{255, 0}, Value: []byte{0xf5, 0}, Operands: []Operand{
			{Name: "source", Kind: "register", RegisterPrefix: "$", Names: []string{"$zero", "$at", "$v0", "$v1"}, Bits: []BitSlice{{8, 0, 4}}},
			{Name: "target", Kind: "register", RegisterPrefix: "$", Names: []string{"$zero", "$at", "$v0", "$v1"}, Bits: []BitSlice{{12, 0, 4}}},
		}},
		{ID: "DOLLAR_REGISTER", Mnemonic: "dollar", Syntax: "dollar {value}", Mask: []byte{255, 0xfc}, Value: []byte{0xf6, 0}, Operands: []Operand{
			{Name: "value", Kind: "register", RegisterPrefix: "$", Names: []string{"$zero", "$at", "$v0", "$v1"}, Bits: []BitSlice{{8, 0, 2}}},
		}},
		{ID: "BANKS", Mnemonic: "banks", Syntax: "banks {a},{b}", Mask: []byte{255, 0}, Value: []byte{0xec, 0}, Operands: []Operand{
			{Name: "a", Kind: "register", RegisterPrefix: "r", Bits: []BitSlice{{8, 0, 4}}},
			{Name: "b", Kind: "register", RegisterPrefix: "r", Bits: []BitSlice{{12, 0, 4}}},
		}, Constraints: []Constraint{{Kind: "masked_ne", Left: "a", Right: "b", Limit: 3}}},
		{ID: "GATED_BANKS", Mnemonic: "gatedbanks", Syntax: "gatedbanks {a},{b}", Mask: []byte{255, 0}, Value: []byte{0xed, 0}, Operands: []Operand{
			{Name: "a", Kind: "register", RegisterPrefix: "r", Bits: []BitSlice{{8, 0, 4}}},
			{Name: "b", Kind: "register", RegisterPrefix: "r", Bits: []BitSlice{{12, 0, 4}}},
		}, Constraints: []Constraint{{Kind: "masked_ne", Left: "a", Right: "b", Limit: 3, LeftWhenMask: 8, RightWhenMask: 8, EqualMask: 7}}},
		{ID: "SPANNED_BANKS", Mnemonic: "spanbanks", Syntax: "spanbanks {a},{b}", Mask: []byte{255, 0}, Value: []byte{0xee, 0}, Operands: []Operand{
			{Name: "a", Kind: "register", RegisterPrefix: "r", Bits: []BitSlice{{8, 0, 4}}},
			{Name: "b", Kind: "register", RegisterPrefix: "r", Bits: []BitSlice{{12, 0, 4}}},
		}, Constraints: []Constraint{{Kind: "masked_ne", Left: "a", Right: "b", Limit: 3, LeftSpan: 2, RightSpan: 2}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestModularTargetsImplicitFieldsAndLiteralBraces(t *testing.T) {
	c := exampleCatalog(t)
	for _, tc := range []struct {
		id      string
		values  map[string]int64
		address uint64
		text    string
		bytes   []byte
	}{
		{"WRAP", map[string]int64{"Target": -4}, 0, "wrap 0xfffe", []byte{0xb0, 0xfe}},
		{"WRAP", map[string]int64{"Target": 4}, 0xfffc, "wrap 0x2", []byte{0xb0, 2}},
		{"REGION", map[string]int64{"Target": 5}, 0x1ff, "jump 0x205", []byte{0xb1, 5}},
		{"WRAP_REGION", map[string]int64{"Target": 1}, 0xffff, "pagejump 0x1", []byte{0xea, 1}},
		{"LOW", map[string]int64{"Target": 4}, 0xfffc, "low 0x2", []byte{0xb3, 2}},
		{"LOW", map[string]int64{"Target": 4}, 0x1fffc, "low 0x20002", []byte{0xb3, 2}},
		{"REPEAT", map[string]int64{"count": 3, "src": 5}, 0, "rpt #3 { inc 5", []byte{0xb2, 3, 5, 0xf9}},
		{"U64", map[string]int64{"value": -1}, 0, "u64 18446744073709551615", []byte{0xd0, 255, 255, 255, 255, 255, 255, 255, 255}},
		{"S64", map[string]int64{"value": -1}, 0, "s64 -1", []byte{0xd1, 255, 255, 255, 255, 255, 255, 255, 255}},
		{"GPU", map[string]int64{"src": 1, "clamp": 1, "offset": 1}, 0, "gpu r1 clamp offset:4", []byte{0xe0, 13}},
		{"GPU", map[string]int64{"src": 1, "clamp": 0, "offset": 1}, 0, "gpu r1  offset:4", []byte{0xe0, 9}},
		{"GPU", map[string]int64{"src": 1, "clamp": 0, "offset": 0}, 0, "gpu r1  ", []byte{0xe0, 1}},
		{"CASE", map[string]int64{"Ii": 2, "II": 7}, 0, "case 2, 7", []byte{0xe1, 0x72}},
		{"DIGIT_MNEMONIC", map[string]int64{"offset": -4}, 0, "ld.w23 -4[gp],gp", []byte{0xe3, 0xfc}},
		{"ALIGNED", map[string]int64{"Target": 100}, 0x1002, "aligned 0x1066", []byte{0xe5, 100}},
		{"ALIGNED", map[string]int64{"Target": 4}, 0xfffffffe, "aligned 0x2", []byte{0xe5, 4}},
		{"LOOKUP", map[string]int64{"number": 21, "offset": -32}, 0, "lut ten,-32", []byte{0xe6, 3}},
		{"PRE_ALIGN", map[string]int64{"Target": -4}, 0x1002, "litbase 0x1000", []byte{0xe7, 0xfc}},
		{"PRE_ALIGN", map[string]int64{"Target": -4}, 0x1000, "litbase 0xffc", []byte{0xe7, 0xfc}},
		{"PRE_ALIGN", map[string]int64{"Target": -4}, 0xfffffffe, "litbase 0xfffffffc", []byte{0xe7, 0xfc}},
	} {
		t.Run(tc.id+tc.text, func(t *testing.T) {
			b, err := c.Encode(tc.id, tc.values)
			if err != nil || !bytes.Equal(b, tc.bytes) {
				t.Fatalf("encode %x: %v", b, err)
			}
			d, err := c.Decode(b)
			if err != nil || d.Format(tc.address) != tc.text {
				t.Fatalf("decode %+v: %v", d, err)
			}
			all, err := c.Assemble(tc.text, tc.address)
			if err != nil || !bytes.Equal(all[0], b) {
				t.Fatalf("assemble %x: %v", all, err)
			}
			if tc.id == "REGION" {
				if target, ok := d.BranchTarget(tc.address); !ok || target != 0x205 {
					t.Fatalf("target %x %v", target, ok)
				}
			}
		})
	}
	for _, text := range []string{"block r0, 0", "block r1, 3", "jump 0x105"} {
		if _, err := c.Assemble(text, 0x1ff); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
	for _, text := range []string{"block 0, 1", "block r1, 0b10", "block r2, 0o3"} {
		if _, err := c.Assemble(text, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Assemble("twice 0x1", 0xfffe); err == nil {
		t.Fatal("accepted symbolic alias with different physical targets")
	}
	if b, err := c.Assemble("twice 0xffff", 0xfffe); err != nil || !bytes.Equal(b[0], []byte{0xe2, 0, 0, 0xfe, 0xff}) {
		t.Fatalf("valid symbolic alias %x %v", b, err)
	}
	if _, err := c.Decode([]byte{0xb2, 3, 5, 0xf8}); err == nil {
		t.Fatal("accepted inconsistent hidden extension field")
	}
	if all, err := c.Assemble("mem (r10-8)", 0); err != nil || !bytes.Equal(all[0], []byte{0xe4, 10, 0xf8}) {
		t.Fatalf("negative address offset %x %v", all, err)
	}
	if _, err := c.Encode("LOOKUP", map[string]int64{"number": 20, "offset": -32}); err == nil {
		t.Fatal("accepted value absent from numeric lookup")
	}
	if _, err := c.Decode([]byte{0xe6, 15}); err == nil {
		t.Fatal("accepted raw index absent from numeric lookup")
	}
	e := c.Encodings[len(c.Encodings)-1]
	e.Operands = append([]Operand(nil), e.Operands...)
	e.Operands[0].Lookup = []int64{1, 1}
	if _, err := NewCatalog("ambiguous", "test", []Encoding{e}); err == nil {
		t.Fatal("accepted ambiguous numeric lookup")
	}
}

func TestCodecRejectsInvalidPatternsAndRoundTrips(t *testing.T) {
	c := exampleCatalog(t)
	b, err := c.Encode("MOV", map[string]int64{"Rd": 2, "imm": -8})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{0x82, 0xfc}) {
		t.Fatalf("bytes %x", b)
	}
	d, err := c.Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Format(0) != "mov r2, -8" {
		t.Fatal(d.Format(0))
	}
	all, err := c.Assemble(d.Format(0), 0)
	if err != nil || !bytes.Equal(all[0], b) {
		t.Fatalf("assemble %x %v", all, err)
	}
	for _, v := range []map[string]int64{{"Rd": 4, "imm": 0}, {"Rd": 2, "imm": 3}, {"Rd": 2, "imm": 512}, {"Rd": 2, "extra": 0}} {
		if _, err := c.Encode("MOV", v); err == nil {
			t.Fatalf("accepted invalid %v", v)
		}
	}
	if _, err := c.Decode([]byte{0x91}); err == nil {
		t.Fatal("accepted inconsistent tied operand")
	}
	if _, err := c.Decode([]byte{0x84, 0}); err == nil {
		t.Fatal("accepted unavailable register")
	}
	if _, err := c.Decode([]byte{0x82}); err != ErrTruncated {
		t.Fatalf("truncation: %v", err)
	}
	branch, _ := c.Encode("BR", map[string]int64{"Target": -8})
	decoded, _ := c.Decode(branch)
	text := decoded.Format(0x1000)
	if text != "br 0xffa" {
		t.Fatal(text)
	}
	all, err = c.Assemble(text, 0x1000)
	if err != nil || !bytes.Equal(all[0], branch) {
		t.Fatalf("branch %x %v", all, err)
	}
}

func TestGeneratedRustConsumer(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	c := exampleCatalog(t)
	for i := range c.Encodings {
		if c.Encodings[i].ID == "TUPLES" {
			c.Encodings[i].Features = []string{"shared_metadata"}
			shared := c.Encodings[i]
			shared.ID = "SHARED_TUPLES"
			c.Encodings = append(c.Encodings, shared)
			break
		}
	}
	c.Encodings = append(c.Encodings, Encoding{
		ID: "RAW", Mnemonic: ".raw", Syntax: ".raw {word}",
		Mask: []byte{0, 0}, Value: []byte{0, 0}, AssemblyOnly: true,
		Operands: []Operand{{Name: "word", Kind: "immediate", Bits: []BitSlice{{InstructionBit: 0, ValueBit: 0, Width: 16}}}},
	})
	// A union decoder legitimately prefers the shorter generation's fixed
	// prefix. Corpus checks must select the long form's declared CPU profile.
	c.Encodings = append(c.Encodings,
		Encoding{ID: "PROFILE_SHORT", Mnemonic: "short", Syntax: "short", Features: []string{"short"}, Mask: []byte{255, 255}, Value: []byte{0xf1, 0}},
		Encoding{ID: "PROFILE_LONG", Mnemonic: "long", Syntax: "long {word}", Features: []string{"long"}, Mask: []byte{255, 0, 0}, Value: []byte{0xf1, 0, 0}, Operands: []Operand{{Name: "word", Kind: "immediate", Bits: []BitSlice{{InstructionBit: 8, ValueBit: 0, Width: 16}}}}},
	)
	c.FeatureSets = map[string][]string{"short": {"short"}, "long": {"long"}}
	// A rejected shorter form must not overwrite a valid result; equal length
	// alternatives retain catalog precedence, and a later shorter form wins.
	c.Encodings = append(c.Encodings,
		Encoding{ID: "PICK_WIDE", Mnemonic: "pick", Syntax: "pick {value}", Mask: []byte{255, 0, 0}, Value: []byte{0xf9, 0, 0}, Operands: []Operand{{Name: "value", Kind: "immediate", Bits: []BitSlice{{8, 0, 16}}}}},
		Encoding{ID: "PICK_SHORT", Mnemonic: "pick", Syntax: "pick {value}", Mask: []byte{255, 0}, Value: []byte{0xfa, 0}, Operands: []Operand{{Name: "value", Kind: "immediate", Bits: []BitSlice{{8, 0, 8}}}}},
		Encoding{ID: "PICK_TIE", Mnemonic: "pick", Syntax: "pick {value}", Mask: []byte{255, 0}, Value: []byte{0xfb, 0}, Operands: []Operand{{Name: "value", Kind: "immediate", Bits: []BitSlice{{8, 0, 8}}}}},
	)
	// Named candidates precede dynamic candidates on ties, even when catalog
	// order is reversed. A dynamic shorter form still wins after a named match.
	c.Encodings = append(c.Encodings,
		Encoding{ID: "ORDER_DYNAMIC_TIE", Mnemonic: "order", Syntax: "{opcode} {value}", AssemblyOnly: true, Mask: []byte{255, 0x70}, Value: []byte{0xfe, 0x10}, Operands: []Operand{{Name: "opcode", Kind: "register", Names: []string{"order"}, Bits: []BitSlice{{15, 0, 1}}}, {Name: "value", Kind: "immediate", Bits: []BitSlice{{8, 0, 4}}}}, Constraints: []Constraint{{Kind: "sum_le", Left: "value", Limit: 3}}},
		Encoding{ID: "ORDER_NAMED_WIDE", Mnemonic: "order", Syntax: "order {value}", AssemblyOnly: true, Mask: []byte{255, 255, 0}, Value: []byte{0xfe, 0x40, 0}, Operands: []Operand{{Name: "value", Kind: "immediate", Bits: []BitSlice{{16, 0, 8}}}}},
		Encoding{ID: "ORDER_NAMED_SHORT", Mnemonic: "order", Syntax: "order {value}", AssemblyOnly: true, Mask: []byte{255, 0xf0}, Value: []byte{0xfe, 0}, Operands: []Operand{{Name: "value", Kind: "immediate", Bits: []BitSlice{{8, 0, 4}}}}, Constraints: []Constraint{{Kind: "sum_le", Left: "value", Limit: 3}}},
		Encoding{ID: "ORDER_DYNAMIC_FIRST", Mnemonic: "order", Syntax: "{opcode} {value}", AssemblyOnly: true, Mask: []byte{255, 0x70}, Value: []byte{0xfe, 0x20}, Operands: []Operand{{Name: "opcode", Kind: "register", Names: []string{"order"}, Bits: []BitSlice{{15, 0, 1}}}, {Name: "value", Kind: "immediate", Bits: []BitSlice{{8, 0, 4}}}}},
	)
	// Force a failed greedy split and rollback across a repeated operand. There
	// are three syntax occurrences but only two value slots.
	c.Encodings = append(c.Encodings, Encoding{ID: "BACKTRACK_REPEAT", Mnemonic: "backtrack", Syntax: "backtrack {x}{y},{x}", AssemblyOnly: true, Mask: []byte{255, 0xf8}, Value: []byte{0xfe, 0x30}, Operands: []Operand{
		{Name: "x", Kind: "register", Names: []string{"a", "ab", "b"}, Bits: []BitSlice{{8, 0, 2}}},
		{Name: "y", Kind: "register", Names: []string{" ", "b"}, Bits: []BitSlice{{10, 0, 1}}},
	}})
	c.Encodings = append(c.Encodings, Encoding{ID: "REPEATED_SLOTS", Mnemonic: "repeat_slots", Syntax: "repeat_slots " + strings.Repeat("{x},", 7) + "{x}", AssemblyOnly: true, Mask: []byte{255, 0xf0}, Value: []byte{0xfe, 0x50}, Operands: []Operand{{Name: "x", Kind: "immediate", Bits: []BitSlice{{8, 0, 4}}}}})
	c.Encodings = append(c.Encodings,
		Encoding{ID: "UNALIGNED", Mnemonic: "unaligned", Syntax: "unaligned {value}", Mask: []byte{255, 7, 0, 0, 0, 0, 0, 0, 0, 248}, Value: []byte{0xd2, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Operands: []Operand{{Name: "value", Kind: "immediate", Bits: []BitSlice{{11, 0, 64}}}}},
		Encoding{ID: "TIED_WIDE", Mnemonic: "tied", Syntax: "tied {value}", Mask: []byte{255, 0, 240, 0}, Value: []byte{0xd3, 0, 0, 0}, Operands: []Operand{{Name: "value", Kind: "immediate", Signed: true, Xor: 0x123, Bits: []BitSlice{{8, 0, 12}, {24, 4, 8}}}}},
	)
	c.Encodings = append(c.Encodings, Encoding{ID: "UNICODE", Mnemonic: "unicode", Syntax: "unicode İÄ {Value}", Mask: []byte{255, 252}, Value: []byte{0xf8, 0}, Operands: []Operand{{Name: "Value", Kind: "register", Names: []string{"Ä0", "İ1", "π2", " A\u0085B "}, Bits: []BitSlice{{8, 0, 2}}}}})

	// Exercise literal filters for both a large fixed mnemonic bucket and the
	// dynamic mnemonic path, alongside every existing consumer edge case.
	for i := 0; i < 65; i++ {
		o := []Operand{{Name: "value", Kind: "immediate", Bits: []BitSlice{{16, 0, 8}}}}
		c.Encodings = append(c.Encodings,
			Encoding{ID: fmt.Sprintf("FILTER_%d", i), Mnemonic: "filter", Syntax: fmt.Sprintf("filter {{π}} {value} suffix%d", i), Mask: []byte{255, 255, 0}, Value: []byte{0xfc, byte(i), 0}, Operands: o},
			Encoding{ID: fmt.Sprintf("DYNAMIC_%d", i), Mnemonic: "dynamic", Syntax: fmt.Sprintf("{value}=literal%d", i), Mask: []byte{255, 255, 0}, Value: []byte{0xfd, byte(i), 0}, Operands: o},
		)
	}
	dir := t.TempDir()
	if err := c.GenerateRust(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	const consumer = `use example::*;
#[test] fn real_consumer(){
for value in [0,1,u64::MAX as i128,0x123456789abcdef0]{let b=encode("UNALIGNED",&[value]).unwrap();assert_eq!(decode(&b).unwrap().operand("value"),Some(value));assert_eq!(b[1]&7,0);assert_eq!(b[9]&248,0);}
for value in [-2048,-1,0,1,2047]{let b=encode("TIED_WIDE",&[value]).unwrap();assert_eq!(decode(&b).unwrap().operand("value"),Some(value));let mut bad=b.clone();bad[3]^=1;assert_eq!(decode(&bad).unwrap_err(),Error::Unknown);}
let(index,_)=catalog_entry("TIED_WIDE").unwrap();let mut untouched=[0xa5;16];assert_eq!(encode_into(index,&[2048],&mut untouched),Err(Error::Operand));assert_eq!(untouched,[0xa5;16]);
let first=catalog_entry("TUPLES").unwrap().1;let shared=catalog_entry("SHARED_TUPLES").unwrap().1;
assert!(std::ptr::eq(first.operands,shared.operands));assert!(std::ptr::eq(first.constraints,shared.constraints));assert!(std::ptr::eq(first.features,shared.features));
let framed=[0xf1,0,0];assert_eq!(decode(&framed).unwrap().length,2);let active=Some(profile("long").unwrap());let d=decode_with_features(&framed,active).unwrap();assert_eq!(d.encoding().id,"PROFILE_LONG");assert_eq!(d.length,3);assert_eq!(assemble_with_features(&d.format(0),0,active).unwrap(),vec![framed.to_vec()]);
assert_eq!(encode("RAW",&[0]).unwrap(),[0,0]);assert_eq!(decode(&[0,0]).unwrap_err(),Error::Unknown);assert_eq!(assemble(".raw 256").unwrap(),vec![vec![0,1]]);let raw=Template::parse(".raw $word").unwrap();assert_eq!(raw.matches(&[0,1]).unwrap().1,vec![("word".into(),256)]);assert_eq!(raw.encode(&[("word",256)]).unwrap(),vec![vec![0,1]]);
let b=encode("MOV",&[2,-8]).unwrap();assert_eq!(b,[0x82,0xfc]);let d=decode(&b).unwrap();assert_eq!(d.format(0),"mov r2, -8");assert_eq!(assemble(&d.format(0)).unwrap()[0],b);
let t=Template::parse("mov $r, $n").unwrap();let(n,v)=t.matches(&b).unwrap();assert_eq!(n,2);assert_eq!(v,[("r".into(),2),("n".into(),-8)]);assert!(t.encode(&[("r",2),("n",-8)]).unwrap().contains(&b));
assert_eq!(decode(&[0x91]).unwrap_err(),Error::Unknown);assert!(encode("MOV",&[4,0]).is_err());assert_eq!(decode(&[0x82]).unwrap_err(),Error::Truncated);
let b=encode("REPEAT",&[3,5]).unwrap();assert_eq!(b,[0xb2,3,5,0xf9]);assert_eq!(decode(&b).unwrap().format(0),"rpt #3 { inc 5");assert!(assemble("rpt #3 { inc 5").unwrap().contains(&b));let t=Template::parse("rpt #$n { inc $v").unwrap();assert!(t.matches(&b).is_some());assert!(t.encode(&[("n",3),("v",5)]).unwrap().contains(&b));
let d=decode(&[0xb1,5]).unwrap();assert_eq!(d.branch_target(0x1ff),Some(0x205));assert_eq!(d.format(0x1ff),"jump 0x205");assert!(assemble_at("jump 0x105",0x1ff).is_err());
assert_eq!(decode(&[0xea,1]).unwrap().branch_target(0xffff),Some(1));assert_eq!(assemble_at("pagejump 0x1",0xffff).unwrap(),vec![vec![0xea,1]]);assert!(assemble_at("pagejump 0x10001",0xffff).is_err());assert!(Template::parse_at("pagejump 0x1",0xffff).unwrap().matches(&[0xea,1]).is_some());
assert_eq!(decode(&[0xef,0xff,0xff]).unwrap().branch_target(0x1000),Some(65535));assert_eq!(decode(&[0xf0,0xff,0xff]).unwrap().branch_target(0x1000),None);
assert!(assemble_at("wrap 0xfffe",0).unwrap().contains(&vec![0xb0,0xfe]));assert_eq!(decode(&[0xb0,2]).unwrap().branch_target(0xfffc),Some(2));
assert_eq!(decode(&[0xb3,2]).unwrap().branch_target(0xfffc),Some(2));assert_eq!(decode(&[0xb3,2]).unwrap().branch_target(0x1fffc),Some(0x20002));assert!(assemble_at("low 0x20002",0x1fffc).unwrap().contains(&vec![0xb3,2]));assert!(assemble_at("low 0x10002",0xfffc).is_err());
let b=encode("U64",&[u64::MAX as i128]).unwrap();assert_eq!(decode(&b).unwrap().operand("value"),Some(u64::MAX as i128));assert!(assemble("u64 0xffffffffffffffff").unwrap().contains(&b));assert!(encode("U64",&[-1]).is_err());let b=encode("S64",&[-1]).unwrap();assert_eq!(decode(&b).unwrap().operand("value"),Some(-1));
assert!(assemble("block r0, 0").is_err());assert!(assemble("block r1, 3").is_err());assert!(assemble("block r1, 0b10").is_ok());assert!(assemble("block r2, 0o3").is_ok());
assert!(assemble("gpu r1 offset:4").unwrap().contains(&vec![0xe0,9]));assert!(assemble("gpu r1 clamp offset:4").unwrap().contains(&vec![0xe0,13]));let t=Template::parse("gpu $r clamp $flags").unwrap();assert!(t.matches(&[0xe0,13]).is_some());assert!(t.encode(&[("r",1),("flags",1)]).unwrap().contains(&vec![0xe0,13]));
assert_eq!(assemble("CASE 2, 7").unwrap(),vec![vec![0xe1,0x72]]);let t=Template::parse("case $first, $second").unwrap();assert!(t.encode(&[("first",2),("second",7)]).unwrap().contains(&vec![0xe1,0x72]));
assert!(assemble_at("twice 0x1",0xfffe).is_err());assert!(assemble_at("twice 0xffff",0xfffe).unwrap().contains(&vec![0xe2,0,0,0xfe,0xff]));let t=Template::parse_at("twice $v",0xfffe).unwrap();assert!(t.encode(&[("v",2)]).is_err());assert!(t.matches(&[0xe2,2,0,0,0]).is_none());assert!(t.encode(&[("v",0)]).is_ok());
assert_eq!(assemble("ld.w23 -4[gp],gp").unwrap(),vec![vec![0xe3,0xfc]]);assert_eq!(assemble("mem (r10-8)").unwrap(),vec![vec![0xe4,10,0xf8]]);
assert_eq!(decode(&[0xe5,100]).unwrap().branch_target(0x1002),Some(0x1066));assert_eq!(assemble_at("aligned 0x1066",0x1002).unwrap(),vec![vec![0xe5,100]]);assert!(Template::parse_at("aligned 0x1066",0x1002).unwrap().matches(&[0xe5,100]).is_some());assert!(Template::parse_at("aligned $target",0x1002).unwrap().encode(&[("target",100)]).unwrap().contains(&vec![0xe5,100]));assert_eq!(decode(&[0xe5,4]).unwrap().branch_target(0xfffffffe),Some(2));
assert_eq!(decode(&[0xe6,3]).unwrap().operand("number"),Some(21));assert_eq!(assemble("lut ten,-32").unwrap(),vec![vec![0xe6,3]]);assert_eq!(assemble("lut 21,-32").unwrap(),vec![vec![0xe6,3]]);assert!(encode("LOOKUP",&[20,-32]).is_err());assert!(decode(&[0xe6,15]).is_err());let t=Template::parse("lut $n,$offset").unwrap();assert_eq!(t.matches(&[0xe6,3]).unwrap().1,vec![("n".into(),21),("offset".into(),-32)]);assert_eq!(t.encode(&[("n",21),("offset",-32)]).unwrap(),vec![vec![0xe6,3]]);
assert_eq!(decode(&[0xe7,0xfc]).unwrap().branch_target(0x1002),Some(0x1000));assert_eq!(decode(&[0xe7,0xfc]).unwrap().branch_target(0xfffffffe),Some(0xfffffffc));assert!(Template::parse_at("litbase 0x1000",0x1002).unwrap().matches(&[0xe7,0xfc]).is_some());assert_eq!(assemble_at("litbase 0x1000",0x1002).unwrap(),vec![vec![0xe7,0xfc]]);
let t=Template::parse("tuples $mask,$half,$status,$dimension").unwrap();for raw in 0u8..=255{let values=[(raw&15)as i128,((raw>>4)&1)as i128,((raw>>5)&1)as i128,((raw>>6)&3)as i128];let valid=matches!((values[0],values[1],values[2]),(3,1,0)|(7,0,1))&&matches!(values[3],1|2);assert_eq!(encode("TUPLES",&values).is_ok(),valid);assert_eq!(encode("TUPLES",&values),encode("SHARED_TUPLES",&values));assert_eq!(decode(&[0xe9,raw]).is_ok(),valid);assert_eq!(t.matches(&[0xe9,raw]).is_some(),valid);assert_eq!(t.encode(&[("mask",values[0]),("half",values[1]),("status",values[2]),("dimension",values[3])]).is_ok(),valid);}
assert_eq!(encode("PADDING",&[3]).unwrap(),vec![0xeb,3]);let bytes=encode("PADDING",&[15,3]).unwrap();assert_eq!(bytes,vec![0xeb,0xf3]);let d=decode(&bytes).unwrap();assert_eq!(d.operand("ignored"),Some(15));assert_eq!(encode(d.encoding().id,&d.values[..d.encoding().operands.len()]).unwrap(),bytes);assert_eq!(assemble(&d.format(0)).unwrap(),vec![vec![0xeb,3]]);let t=Template::parse("padding $value").unwrap();assert_eq!(t.encode(&[("value",3)]).unwrap(),vec![vec![0xeb,3]]);
let t=Template::parse("banks $a,$b").unwrap();for raw in 0u8..=255{let a=(raw&15)as i128;let b=(raw>>4)as i128;let valid=(a&3)!=(b&3);assert_eq!(encode("BANKS",&[a,b]).is_ok(),valid);assert_eq!(decode(&[0xec,raw]).is_ok(),valid);assert_eq!(t.matches(&[0xec,raw]).is_some(),valid);assert_eq!(t.encode(&[("a",a),("b",b)]).is_ok(),valid);}
let t=Template::parse("gatedbanks $a,$b").unwrap();for raw in 0u8..=255{let a=(raw&15)as i128;let b=(raw>>4)as i128;let valid=(a&8)==0||(b&8)==0||(a&7)==(b&7)||(a&3)!=(b&3);assert_eq!(encode("GATED_BANKS",&[a,b]).is_ok(),valid);assert_eq!(decode(&[0xed,raw]).is_ok(),valid);assert_eq!(t.matches(&[0xed,raw]).is_some(),valid);assert_eq!(t.encode(&[("a",a),("b",b)]).is_ok(),valid);}
let t=Template::parse("spanbanks $a,$b").unwrap();for raw in 0u8..=255{let a=(raw&15)as i128;let b=(raw>>4)as i128;let valid=(0..2).all(|i|(0..2).all(|j|((a+i)&3)!=((b+j)&3)));assert_eq!(encode("SPANNED_BANKS",&[a,b]).is_ok(),valid);assert_eq!(decode(&[0xee,raw]).is_ok(),valid);assert_eq!(t.matches(&[0xee,raw]).is_some(),valid);assert_eq!(t.encode(&[("a",a),("b",b)]).is_ok(),valid);}
}`
	if err := os.WriteFile(filepath.Join(dir, "tests", "consumer.rs"), []byte(consumer+rustAnalysisConsumer+rustDispatchConsumer(c)+rustZeroAllocationConsumer), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--lib", "--test", "consumer", "--test", "positions", "--quiet")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated Rust consumer: %v\n%s", err, output)
	}
}
