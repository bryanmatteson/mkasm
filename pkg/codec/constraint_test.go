package codec

import (
	"fmt"
	"testing"
)

func tupleEncoding(t *testing.T, c *Catalog) *Encoding {
	t.Helper()
	for i := range c.Encodings {
		if c.Encodings[i].ID == "TUPLES" {
			return &c.Encodings[i]
		}
	}
	t.Fatal("tuple fixture missing")
	return nil
}

func TestTupleDomainsAcrossCodecAndText(t *testing.T) {
	c := exampleCatalog(t)
	for raw := 0; raw < 256; raw++ {
		values := map[string]int64{"dmask": int64(raw & 15), "d16": int64(raw >> 4 & 1), "tfe": int64(raw >> 5 & 1), "dim": int64(raw >> 6 & 3)}
		validData := values["dmask"] == 3 && values["d16"] == 1 && values["tfe"] == 0 || values["dmask"] == 7 && values["d16"] == 0 && values["tfe"] == 1
		valid := validData && (values["dim"] == 1 || values["dim"] == 2)
		encoded, err := c.Encode("TUPLES", values)
		if (err == nil) != valid {
			t.Fatalf("encode %02x: valid=%t err=%v", raw, valid, err)
		}
		decoded, err := c.Decode([]byte{0xe9, byte(raw)})
		if (err == nil) != valid {
			t.Fatalf("decode %02x: valid=%t err=%v", raw, valid, err)
		}
		if valid {
			forms, err := c.Assemble(decoded.Format(0), 0)
			if err != nil || len(forms) != 1 || len(encoded) != 2 || forms[0][1] != byte(raw) {
				t.Fatalf("text %02x: %x, %v", raw, forms, err)
			}
		}
	}
}

func TestTupleDomainSchemaValidation(t *testing.T) {
	for _, constraint := range []Constraint{
		{Kind: "tuple_in"},
		{Kind: "tuple_in", Operands: []string{"dmask"}},
		{Kind: "tuple_in", Operands: []string{"missing"}, Allowed: [][]int64{{1}}},
		{Kind: "tuple_in", Operands: []string{"dmask", "dmask"}, Allowed: [][]int64{{1, 1}}},
		{Kind: "tuple_in", Operands: []string{"dmask", "d16"}, Allowed: [][]int64{{1}}},
		{Kind: "eq", Left: "dmask", Operands: []string{"dmask"}, Allowed: [][]int64{{1}}},
	} {
		c := exampleCatalog(t)
		last := tupleEncoding(t, c)
		last.Constraints = []Constraint{constraint}
		if err := c.Validate(); err == nil {
			t.Fatalf("accepted malformed tuple constraint %#v", constraint)
		}
	}
	c := exampleCatalog(t)
	e := tupleEncoding(t, c)
	e.Constraints = []Constraint{{Kind: "tuple_in", Operands: []string{"dmask"}, Allowed: [][]int64{{1}}, UnlessZero: "tfe"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := Encode(e, map[string]int64{"dmask": 0, "d16": 0, "tfe": 0, "dim": 0}); err != nil {
		t.Fatal("zero guard failed", err)
	}
	if _, err := Encode(e, map[string]int64{"dmask": 0, "d16": 0, "tfe": 1, "dim": 0}); err == nil {
		t.Fatal("nonzero guard bypassed tuple domain")
	}
}

func TestMaskedInequalityAcrossCodecAndText(t *testing.T) {
	c := exampleCatalog(t)
	for a := int64(0); a < 16; a++ {
		for b := int64(0); b < 16; b++ {
			valid := a&3 != b&3
			if _, err := c.Encode("BANKS", map[string]int64{"a": a, "b": b}); (err == nil) != valid {
				t.Fatalf("encode r%d,r%d: %v", a, b, err)
			}
			if _, err := c.Decode([]byte{0xec, byte(a | b<<4)}); (err == nil) != valid {
				t.Fatalf("decode r%d,r%d: %v", a, b, err)
			}
			if _, err := c.Assemble(fmt.Sprintf("banks r%d,r%d", a, b), 0); (err == nil) != valid {
				t.Fatalf("assemble r%d,r%d: %v", a, b, err)
			}
		}
	}
	for _, limit := range []int64{0, -1} {
		last := &c.Encodings[len(c.Encodings)-1]
		last.Constraints[0].Limit = limit
		if err := c.Validate(); err == nil {
			t.Fatal("accepted invalid bank mask", limit)
		}
	}
}

func TestMaskedRelationGatesAndEqualityException(t *testing.T) {
	c := exampleCatalog(t)
	for a := int64(0); a < 16; a++ {
		for b := int64(0); b < 16; b++ {
			valid := a&8 == 0 || b&8 == 0 || a&7 == b&7 || a&3 != b&3
			if _, err := c.Encode("GATED_BANKS", map[string]int64{"a": a, "b": b}); (err == nil) != valid {
				t.Fatalf("encode r%d,r%d: %v", a, b, err)
			}
			if _, err := c.Decode([]byte{0xed, byte(a | b<<4)}); (err == nil) != valid {
				t.Fatalf("decode r%d,r%d: %v", a, b, err)
			}
			if _, err := c.Assemble(fmt.Sprintf("gatedbanks r%d,r%d", a, b), 0); (err == nil) != valid {
				t.Fatalf("assemble r%d,r%d: %v", a, b, err)
			}
		}
	}
	for _, bad := range []Constraint{
		{Kind: "masked_ne", Left: "a", Right: "b", Limit: 3, LeftWhenMask: -1},
		{Kind: "masked_ne", Left: "a", Right: "b", Limit: 3, EqualMask: -1},
		{Kind: "eq", Left: "a", Right: "b", LeftWhenMask: 8},
		{Kind: "masked_ne", Left: "a", Right: "b", Limit: 3, LeftSpan: -1},
		{Kind: "masked_ne", Left: "a", Right: "b", Limit: 3, RightSpan: 17},
		{Kind: "eq", Left: "a", Right: "b", LeftSpan: 1},
	} {
		last := &c.Encodings[len(c.Encodings)-1]
		last.Constraints = []Constraint{bad}
		if err := c.Validate(); err == nil {
			t.Fatal("accepted malformed relation gates", bad)
		}
	}
}

func TestMaskedRegisterSpans(t *testing.T) {
	c := exampleCatalog(t)
	for a := int64(0); a < 16; a++ {
		for b := int64(0); b < 16; b++ {
			valid := true
			for i := int64(0); i < 2; i++ {
				for j := int64(0); j < 2; j++ {
					valid = valid && (a+i)&3 != (b+j)&3
				}
			}
			if _, err := c.Encode("SPANNED_BANKS", map[string]int64{"a": a, "b": b}); (err == nil) != valid {
				t.Fatalf("encode r%d:r%d,r%d:r%d: %v", a, a+1, b, b+1, err)
			}
			if _, err := c.Decode([]byte{0xee, byte(a | b<<4)}); (err == nil) != valid {
				t.Fatalf("decode r%d,r%d: %v", a, b, err)
			}
			if _, err := c.Assemble(fmt.Sprintf("spanbanks r%d,r%d", a, b), 0); (err == nil) != valid {
				t.Fatalf("assemble r%d,r%d: %v", a, b, err)
			}
		}
	}
	// Odd register pairs span banks 3 and 0; their overlap cannot be modeled
	// by masking off the low register bit before comparing pair bases.
	if _, err := c.Encode("SPANNED_BANKS", map[string]int64{"a": 3, "b": 4}); err == nil {
		t.Fatal("accepted overlapping wrapped bank sets")
	}
}

func TestAbsoluteControlFlowTargets(t *testing.T) {
	c := exampleCatalog(t)
	d, err := c.Decode([]byte{0xef, 0xff, 0xff})
	if err != nil {
		t.Fatal(err)
	}
	for _, flow := range []string{"call", "branch", "conditional_branch", "conditional-branch", "unconditional_branch", "unconditional-branch", "loop"} {
		d.Encoding.FlowControl = flow
		if got, ok := d.BranchTarget(0x1000); !ok || got != 65535 {
			t.Fatalf("%s target %x, %t", flow, got, ok)
		}
	}
	for _, flow := range []string{"next", "return", "indirect_branch", "indirect_call"} {
		d.Encoding.FlowControl = flow
		if got, ok := d.BranchTarget(0x1000); ok {
			t.Fatalf("%s exposed address operand as target %x", flow, got)
		}
	}
	// Relative operands also describe data references and indirect call slots.
	for _, flow := range []string{"", "next", "return", "indirect_branch", "indirect_call"} {
		d.Encoding.FlowControl = flow
		d.Encoding.Operands[0].Relative = true
		if got, ok := d.BranchTarget(0x1000); ok {
			t.Fatalf("%s exposed PC-relative memory operand as target %x", flow, got)
		}
	}
	load, err := c.Decode([]byte{0xf0, 0xff, 0xff})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := load.BranchTarget(0); ok {
		t.Fatal("ordinary memory reference exposed as control-flow target")
	}
}
