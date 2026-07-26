package arm

import (
	"encoding/xml"
	"reflect"
	"strings"
	"testing"

	"mkasm/pkg/ir"
)

func TestSplitFieldList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"single", "Rd", []string{"Rd"}},
		{"compact tuple", "size:Q", []string{"size", "Q"}},
		{"ARM definition tuple", "(size :: Q)", []string{"size", "Q"}},
		{"three column definition", "(op1 :: CRm :: op2)", []string{"op1", "CRm", "op2"}},
		{"field slice", "CRm<2:1>", []string{"CRm<2:1>"}},
		{"definition slice", "cmode[2:1]", []string{"cmode[2:1]"}},
		{"tuple containing slices", "(Q :: S :: size<1>)", []string{"Q", "S", "size<1>"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitFieldList(tt.in); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("splitFieldList(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestDecodeExplanationPreservesTableSelectorSlices(t *testing.T) {
	const source = `<explanations>
		<explanation enclist="EXT">
			<symbol link="index">&lt;index&gt;</symbol>
			<definition encodedin="(Q :: imm4)">
				<table><tgroup>
					<thead><row>
						<entry>Q</entry><entry>imm4[3]</entry><entry>&lt;index&gt;</entry>
					</row></thead>
					<tbody><row>
						<entry>0</entry><entry>0</entry><entry>UInt(imm4[2:0])</entry>
					</row></tbody>
				</tgroup></table>
			</definition>
		</explanation>
	</explanations>`
	decoder := xml.NewDecoder(strings.NewReader(source))
	start, err := decoder.Token()
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeExplanations(decoder, start.(xml.StartElement))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("explanations = %d, want 1", len(got))
	}
	if want := []string{"Q", "imm4"}; !reflect.DeepEqual(got[0].Fields, want) {
		t.Fatalf("encoded fields = %#v, want %#v", got[0].Fields, want)
	}
	if want := []string{"Q", "imm4[3]"}; !reflect.DeepEqual(got[0].ValueFields, want) {
		t.Fatalf("table fields = %#v, want %#v", got[0].ValueFields, want)
	}
}

func TestDecodeExplanationIgnoresTableMetadataColumns(t *testing.T) {
	const source = `<explanations>
		<explanation enclist="PRFM">
			<symbol link="prfop">&lt;prfop&gt;</symbol>
			<definition encodedin="Rt">
				<table><tgroup>
					<thead><row>
						<entry class="bitfield">Rt</entry>
						<entry class="symbol">&lt;prfop&gt;</entry>
						<entry class="symbol">Architectural Feature</entry>
					</row></thead>
					<tbody><row>
						<entry class="bitfield">00000</entry>
						<entry class="symbol">PLDL1KEEP</entry>
						<entry class="feature"><arch_variants/></entry>
					</row></tbody>
				</tgroup></table>
			</definition>
		</explanation>
	</explanations>`
	decoder := xml.NewDecoder(strings.NewReader(source))
	start, err := decoder.Token()
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeExplanations(decoder, start.(xml.StartElement))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Values) != 1 {
		t.Fatalf("decoded explanations = %#v", got)
	}
	if want := []string{"Rt"}; !reflect.DeepEqual(got[0].ValueFields, want) {
		t.Fatalf("table fields = %#v, want %#v", got[0].ValueFields, want)
	}
	row := got[0].Values[0]
	if !reflect.DeepEqual(row.Bits, []string{"00000"}) || row.Symbol != "PLDL1KEEP" {
		t.Fatalf("value row = %#v", row)
	}
}

func TestLookupFieldSliceSyntaxes(t *testing.T) {
	fields := map[string]ir.BitField{
		"cmode": {Name: "cmode", Start: 12, End: 15},
	}
	for _, name := range []string{"cmode<2:1>", "cmode[2:1]"} {
		got, ok := lookupField(name, fields)
		if !ok {
			t.Fatalf("lookupField(%q) did not resolve", name)
		}
		if got.Start != 13 || got.End != 14 {
			t.Fatalf("lookupField(%q) = bits %d:%d, want 14:13", name, got.End, got.Start)
		}
	}
}
