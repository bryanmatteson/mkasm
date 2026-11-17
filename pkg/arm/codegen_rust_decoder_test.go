package arm

import (
	"strings"
	"testing"
	"text/template"

	"github.com/bryanmatteson/mkasm/pkg/ir"
	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

func TestRustDecoderUsesStaticTreeAndLazyViews(t *testing.T) {
	catalog := BuildCatalog(rustDecoderWildcardFixture())
	data, err := buildRustDecoderData(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if data.Root == "None" {
		t.Fatal("decoder tree has no root")
	}
	if !strings.Contains(data.Table, `mnemonic: "A_group", asm_mnemonic: "A"`) {
		t.Fatalf("decoder table lost the assembler mnemonic:\n%s", data.Table)
	}
	if !strings.Contains(data.Nodes, "static NODES: &[Node]") ||
		!strings.Contains(data.Edges, "static EDGES: &[Edge]") ||
		!strings.Contains(data.Candidates, "static CANDIDATES: &[u16]") {
		t.Fatalf("missing compact tree tables:\n%s\n%s\n%s", data.Nodes, data.Edges, data.Candidates)
	}

	tmpl, err := template.New("rust").ParseFS(assettemplates.FS, "rust/decoders.rs.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	if err := tmpl.ExecuteTemplate(&source, "decoders.rs.tmpl", data); err != nil {
		t.Fatal(err)
	}
	generated := source.String()
	for _, forbidden := range []string{"BTreeMap", "Vec<", ".collect()"} {
		if strings.Contains(generated, forbidden) {
			t.Fatalf("generated hot path still contains %q", forbidden)
		}
	}
	for _, required := range []string{
		"binary_search_by_key", "CandidateSource::Leaf", "pub struct Fields", "pub struct Ambiguous",
		"pub asm_mnemonic: &'static str", "pub struct CatalogEntry", "pub fn catalog_entry_count()",
		"pub fn catalog_entry(index: usize) -> Option<CatalogEntry>",
	} {
		if !strings.Contains(generated, required) {
			t.Fatalf("generated decoder is missing %q", required)
		}
	}
}

func TestRustDecoderCompilesBitDiffsToMasks(t *testing.T) {
	node := &ir.BitDiffNode{
		Kind: ir.BitDiffAnd,
		Kids: []*ir.BitDiffNode{
			{Kind: ir.BitDiffAtomKind, Atom: &ir.BitDiffAtom{
				Start: 8, End: 11, Op: ir.BitDiffNe, Bits: "0011",
			}},
			{Kind: ir.BitDiffAtomKind, Atom: &ir.BitDiffAtom{
				Start: 4, End: 5, Op: ir.BitDiffIn, Alts: []string{"01", "1x"},
			}},
		},
	}
	got := emitRustBitDiff(node)
	for _, want := range []string{
		"BitDiff::And", "BitDiffOp::Ne", "mask: 0x0000000F", "value: 0x00000003",
		"BitDiffOp::In", "mask: 0x00000002", "value: 0x00000002",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("bitdiff literal missing %q:\n%s", want, got)
		}
	}
}

func TestExactEncoderTestsDoNotDecodeIllegalZeroBase(t *testing.T) {
	surface := &AsmSurface{Exact: []ExactEncoding{
		{Fn: "enc_legal", EncodingID: "LEGAL", FixedLegal: true},
		{Fn: "enc_illegal", EncodingID: "ILLEGAL", FixedLegal: false},
	}}
	generated := emitExactEncoderTests(surface)
	if !strings.Contains(generated, "\n    chk(&mut bad, \"LEGAL\"") {
		t.Fatal("legal fixed word is not decode-checked")
	}
	if strings.Contains(generated, "\n    chk(&mut bad, \"ILLEGAL\"") {
		t.Fatal("constraint-violating fixed word is decode-checked")
	}
	for _, id := range []string{"LEGAL", "ILLEGAL"} {
		if !strings.Contains(generated, `xchk(&mut bad, "`+id+`"`) {
			t.Fatalf("%s exact encoder lost its independent field-placement check", id)
		}
	}
}

func rustDecoderWildcardFixture() []*ir.InstructionIR {
	fixed := func(value uint64) *uint64 { return &value }
	field := func(name string, start, end int, value *uint64) ir.BitField {
		return ir.BitField{Name: name, Start: start, End: end, Fixed: value}
	}
	return []*ir.InstructionIR{
		{
			Mnemonic: "A_group", AsmMnemonic: "A", EncodingID: "A", IClass: "test",
			BitPattern: "11" + strings.Repeat("x", 26) + "0001",
			Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{
				field("top", 30, 31, fixed(3)),
				field("mid", 4, 29, nil),
				field("tag", 0, 3, fixed(1)),
			}},
		},
		{
			Mnemonic: "B", EncodingID: "B", IClass: "test",
			BitPattern: "10" + strings.Repeat("x", 26) + "0001",
			Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{
				field("top", 30, 31, fixed(2)),
				field("mid", 4, 29, nil),
				field("tag", 0, 3, fixed(1)),
			}},
		},
		{
			Mnemonic: "C", EncodingID: "C", IClass: "test",
			BitPattern: strings.Repeat("x", 28) + "0001",
			Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{
				field("mid", 4, 29, nil),
				field("tag", 0, 3, fixed(1)),
			}},
		},
	}
}

func TestEncoderTestWordsKeepRejectedProbesAndAddLegalFields(t *testing.T) {
	tree, err := ParseBitDiffs("bits != '0001' && bits != '0000'")
	if err != nil {
		t.Fatal(err)
	}
	instr := &ir.InstructionIR{Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{{Name: "bits", Start: 4, End: 7}}}}
	if err := ir.ResolveBitDiffFields(tree, instr.Encoding); err != nil {
		t.Fatal(err)
	}
	fields := []RawField{{Name: "bits", Start: 4, End: 7, Free: 0xf0}}
	words := encoderTestWords(0xa0000001, fields, tree)
	if len(words) != 2 || words[0] != 0xa0000011 || ir.EvalBitDiffs(tree, words[0]) || !ir.EvalBitDiffs(tree, words[1]) {
		t.Fatalf("probes: %08x", words)
	}
	for _, word := range words {
		if word & ^uint32(0xf0) != 0xa0000001 {
			t.Fatalf("pinned bits changed: %08x", word)
		}
	}
	// An impossible fixed allocation must retain a negative check.
	impossible := &ir.BitDiffNode{Kind: ir.BitDiffAtomKind, Atom: &ir.BitDiffAtom{Start: 0, End: 0, Op: ir.BitDiffEq, Bits: "0"}}
	if got := encoderTestWords(1, nil, impossible); len(got) != 1 || got[0] != 1 {
		t.Fatalf("negative fixed allocation: %x", got)
	}
	surface := &AsmSurface{Exact: []ExactEncoding{{Fn: "enc_probe", EncodingID: "PROBE", FixedWord: 0xa0000001, Fields: fields, Constraints: tree}}, Raw: []RawEncoding{{EncodingID: "PROBE", FixedWord: 0xa0000001, Fields: fields, Constraints: tree}}}
	for name, source := range map[string]string{"exact": emitExactEncoderTests(surface), "raw": emitRawEncoderTests(surface)} {
		if !strings.Contains(source, "AllocationConstraint") || !strings.Contains(source, "0xA0000011") || !strings.Contains(source, "0xA00000F1") {
			t.Fatalf("%s lost a positive or negative allocation case", name)
		}
	}
}
