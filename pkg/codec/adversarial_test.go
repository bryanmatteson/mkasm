package codec

import (
	"bytes"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Exercise the model at its boundaries independently of the importers' usual
// representative values. In particular XOR applies before sign extension and
// a dependent field can precede the field on which it depends.
func adversarialCatalog(t *testing.T) *Catalog {
	t.Helper()
	var encodings []Encoding
	zeroTarget := uint64(0)
	for i, signed := range []bool{false, true} {
		id := []string{"SPARSE_U", "SPARSE_S"}[i]
		encodings = append(encodings, Encoding{ID: id, Mnemonic: id, Syntax: id + " {n}", Mask: []byte{255, 252}, Value: []byte{byte(i + 1), 0}, Operands: []Operand{{Name: "n", Kind: "immediate", Signed: signed, Xor: 1, Bits: []BitSlice{{8, 1, 1}, {9, 3, 1}}}}})
	}
	encodings = append(encodings,
		Encoding{ID: "DEPENDENT", Mnemonic: "dependent", Syntax: "dependent {n}, {base}", Mask: []byte{255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Value: make([]byte, 17), Operands: []Operand{
			{Name: "n", Kind: "immediate", Signed: true, BiasOperand: "base", BiasScale: 2, Bits: []BitSlice{{8, 0, 64}}},
			{Name: "base", Kind: "immediate", Signed: true, Bits: []BitSlice{{72, 0, 64}}},
		}},
		Encoding{ID: "SUM", Mnemonic: "sum", Syntax: "sum {a}, {b}", Mask: []byte{255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Value: append([]byte{4}, make([]byte, 16)...), Operands: []Operand{
			{Name: "a", Kind: "immediate", Signed: true, Bits: []BitSlice{{8, 0, 64}}},
			{Name: "b", Kind: "immediate", Signed: true, Bits: []BitSlice{{72, 0, 64}}},
		}, Constraints: []Constraint{{Kind: "sum_le", Left: "a", Right: "b", Limit: 0}}},
		Encoding{ID: "ABS64", Mnemonic: "abs64", Syntax: "abs64 {target}", Mask: []byte{255, 0, 0, 0, 0, 0, 0, 0, 0}, Value: append([]byte{5}, make([]byte, 8)...), Operands: []Operand{{Name: "target", Kind: "address", Bits: []BitSlice{{8, 0, 64}}}}},
		Encoding{ID: "REL64", Mnemonic: "rel64", Syntax: "rel64 {target}", Mask: []byte{255, 0, 0, 0, 0, 0, 0, 0, 0}, Value: append([]byte{6}, make([]byte, 8)...), Operands: []Operand{{Name: "target", Kind: "displacement", Signed: true, Relative: true, Bits: []BitSlice{{8, 0, 64}}}}},
		Encoding{ID: "WIDE_S", Mnemonic: "wide_s", Syntax: "wide_s {n}", Mask: []byte{255, 0, 0, 0, 0, 0, 0, 0, 128}, Value: append([]byte{7}, make([]byte, 8)...), Operands: []Operand{{Name: "n", Kind: "immediate", Signed: true, InputSignedBits: 63, Bits: []BitSlice{{8, 0, 63}}}}},
		Encoding{ID: "WIDE_U", Mnemonic: "wide_u", Syntax: "wide_u {n}", Mask: []byte{255, 0, 0, 0, 0, 0, 0, 0, 128}, Value: append([]byte{8}, make([]byte, 8)...), Operands: []Operand{{Name: "n", Kind: "immediate", InputSignedBits: 63, Bits: []BitSlice{{8, 0, 63}}}}},
		Encoding{ID: "FIXED_ZERO", Mnemonic: "fixed_zero", Syntax: "fixed_zero", FlowControl: "call", FixedTarget: &zeroTarget, Mask: []byte{255}, Value: []byte{9}},
		Encoding{ID: "MASKED_TARGET", Mnemonic: "masked_target", Syntax: "masked_target {target}", FlowControl: "call", TargetMask: 0xfffe, Mask: []byte{255, 0, 0}, Value: []byte{10, 0, 0}, Operands: []Operand{{Name: "target", Kind: "address", Bits: []BitSlice{{8, 0, 16}}}}},
	)
	encodings[2].Value[0] = 3
	c, err := NewCatalog("adversarial", "test", encodings)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestFixedAndMaskedTargets(t *testing.T) {
	c := adversarialCatalog(t)
	for _, tc := range []struct {
		raw  []byte
		want uint64
	}{{[]byte{9}, 0}, {[]byte{10, 255, 255}, 0xfffe}} {
		d, err := c.Decode(tc.raw)
		if err != nil {
			t.Fatal(err)
		}
		if target, ok := d.BranchTarget(0x1000); !ok || target != tc.want {
			t.Fatalf("%x target %x, %t, want %x", tc.raw, target, ok, tc.want)
		}
	}
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if e.FixedTarget != nil || e.TargetMask != 0 {
			e.FlowControl = "indirect_call"
			if err := c.Validate(); err == nil {
				t.Fatal("accepted direct target metadata for indirect control flow")
			}
			e.FlowControl = "call"
		}
	}
}

func TestWideSignedInputNormalization(t *testing.T) {
	c := adversarialCatalog(t)
	for _, tc := range []struct {
		text string
		want int64
	}{
		{"wide_s 0x7fffffffffffffff", -1},
		{"wide_s 0x4000000000000000", -(1 << 62)},
		{"wide_u -1", math.MaxInt64},
		{"wide_u -4611686018427387904", 1 << 62},
	} {
		forms, err := c.Assemble(tc.text, 0)
		if err != nil || len(forms) != 1 {
			t.Fatalf("%s: %x, %v", tc.text, forms, err)
		}
		d, err := c.Decode(forms[0])
		if err != nil || d.Values["n"] != tc.want {
			t.Fatalf("%s: %v, %v", tc.text, d, err)
		}
	}
}

func TestValidateHostileBitSlices(t *testing.T) {
	for _, bits := range []BitSlice{
		{InstructionBit: math.MaxInt, Width: 1},
		{ValueBit: math.MaxInt, Width: 1},
		{InstructionBit: 1, Width: math.MaxInt},
		{ValueBit: 1, Width: math.MaxInt},
	} {
		c := Catalog{Architecture: "test", Encodings: []Encoding{{ID: "bad", Mnemonic: "bad", Syntax: "bad {n}", Mask: []byte{0}, Value: []byte{0}, Operands: []Operand{{Name: "n", Kind: "immediate", Bits: []BitSlice{bits}}}}}}
		if err := c.Validate(); err == nil {
			t.Fatalf("accepted out-of-bounds bit slice %+v", bits)
		}
	}
}

func TestSparseXorRoundtrip(t *testing.T) {
	c := adversarialCatalog(t)
	for _, op := range []byte{1, 2} {
		for raw := byte(0); raw < 4; raw++ {
			in := []byte{op, raw}
			d, err := c.Decode(in)
			if err != nil {
				t.Fatal(err)
			}
			out, err := Encode(d.Encoding, d.Values)
			if err != nil || !bytes.Equal(in, out) {
				t.Fatalf("%x -> %v -> %x: %v", in, d.Values, out, err)
			}
		}
	}
}

func TestDependentArithmeticDoesNotWrap(t *testing.T) {
	c := adversarialCatalog(t)
	// n-base*2 is -2^64, outside this signed field. Wrapping it to zero
	// would produce an encoding whose decoded value disagrees with its input.
	if b, err := c.Encode("DEPENDENT", map[string]int64{"n": -2, "base": math.MaxInt64}); err == nil {
		t.Fatalf("accepted overflowed dependent bias: %x", b)
	}
	// A raw zero plus twice the maximum base also cannot fit the Go value model.
	b := make([]byte, 17)
	b[0] = 3
	for i := 9; i < 16; i++ {
		b[i] = 255
	}
	b[16] = 127
	if d, err := c.Decode(b); err == nil {
		t.Fatalf("decoded overflowed dependent value: %v", d.Values)
	}
	// Overflowing intermediates may cancel. The final raw and semantic values
	// of this tuple both fit and must agree with the generated Rust codec.
	values := map[string]int64{"n": math.MaxInt64, "base": math.MaxInt64}
	b, err := c.Encode("DEPENDENT", values)
	if err != nil {
		t.Fatal("rejected cancelling dependent bias", err)
	}
	d, err := c.Decode(b)
	if err != nil || d.Values["n"] != values["n"] || d.Values["base"] != values["base"] {
		t.Fatal("cancelling dependent bias roundtrip", d, err)
	}
}

func TestConstraintArithmeticUsesMathematicalBounds(t *testing.T) {
	c := adversarialCatalog(t)
	values := map[string]int64{"a": math.MinInt64, "b": math.MinInt64}
	b, err := c.Encode("SUM", values)
	if err != nil {
		t.Fatal("negative sum is below limit even beyond int64", err)
	}
	if _, err := c.Decode(b); err != nil {
		t.Fatal(err)
	}
	e := Encoding{Constraints: []Constraint{{Kind: "diff_ge", Left: "a", Right: "b", Limit: 0}}}
	if !constraintsMatch(&e, map[string]int64{"a": math.MaxInt64, "b": math.MinInt64}) {
		t.Fatal("positive difference is above limit even beyond int64")
	}
	if constraintsMatch(&e, map[string]int64{"a": math.MinInt64, "b": math.MaxInt64}) {
		t.Fatal("negative difference is below limit")
	}
}

func TestGeneratedRustAdversarialValues(t *testing.T) {
	if _, err := exec.LookPath("cargo"); err != nil {
		t.Skip("cargo unavailable")
	}
	dir := t.TempDir()
	if err := adversarialCatalog(t).GenerateRust(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "adversarial.rs"), []byte(rustAdversarialConsumer), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--lib", "--test", "adversarial", "--test", "positions", "--quiet")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "RUSTFLAGS=-D warnings")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("adversarial consumer: %v\n%s", err, out)
	}
}

const rustAdversarialConsumer = `use adversarial::*;
#[test] fn fixed_and_masked_targets(){assert_eq!(decode(&[9]).unwrap().branch_target(0x1000),Some(0));assert_eq!(decode(&[10,255,255]).unwrap().branch_target(0x1000),Some(0xfffe));}
#[test] fn wide_signed_input_normalization(){
 for(text,want)in [("wide_s 0x7fffffffffffffff",-1),("wide_s 0x4000000000000000",-(1i128<<62)),("wide_u -1",i64::MAX as i128),("wide_u -4611686018427387904",1i128<<62)]{
  let forms=assemble(text).unwrap();assert_eq!(forms.len(),1);assert_eq!(decode(&forms[0]).unwrap().operand("n"),Some(want));
 }
}
#[test] fn sparse_xor_values_and_domains(){
    for op in [1,2]{for raw in 0..4{let bytes=[op,raw];let d=decode(&bytes).unwrap();let mut out=[0xcc;2];assert_eq!(d.encode_into(&mut out).unwrap(),2);assert_eq!(out,bytes);let span=&d.describe(0).operands[0];assert!(span.domain.contains(span.value));}}
    assert_eq!(catalog_entry("SPARSE_U").unwrap().1.operands[0].domain(),Domain::new(1,11,2,false));
    assert_eq!(catalog_entry("SPARSE_S").unwrap().1.operands[0].domain(),Domain::new(-7,3,2,false));
    assert!(encode("SPARSE_U",&[0]).is_err());
}
#[test] fn invalid_extreme_values_reject_atomically(){
    for(id,values)in [("SUM",vec![i128::MAX,1]),("SUM",vec![i128::MIN,-1]),("DEPENDENT",vec![0,i128::MAX]),("DEPENDENT",vec![0,i128::MIN])]{
        let i=catalog_entry(id).unwrap().0;let mut out=[0xcc;32];assert_eq!(encode_into(i,&values,&mut out),Err(Error::Operand));assert_eq!(out,[0xcc;32]);
    }
}
#[test] fn addresses_do_not_truncate_to_u64(){
    let bytes=encode("ABS64",&[u64::MAX as i128]).unwrap();let text=decode(&bytes).unwrap().format(0);assert!(assemble(&text).unwrap().contains(&bytes));
    assert!(assemble_at("rel64 18446744073709551616",0).is_err());
    assert!(assemble_at("rel64 -18446744073709551616",0).is_err());
    assert_eq!(assemble_at("rel64 -1",0).unwrap(),vec![encode("REL64",&[-1]).unwrap()]);
}
`
