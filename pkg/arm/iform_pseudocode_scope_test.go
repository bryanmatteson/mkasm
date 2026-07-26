package arm

import (
	"strings"
	"testing"
)

func TestParseIFormScopesPseudocodeToOwningIClass(t *testing.T) {
	xml := `<instructionsection>
<classes>
  <iclass>
    <regdiagram form="32"><box hibit="0" name="bit"><c>x</c></box></regdiagram>
    <encoding name="FIRST"><asmtemplate><text>FIRST</text></asmtemplate></encoding>
    <ps_section><ps><pstext>if bit == '0' then EndOfDecode(Decode_UNDEF); end;</pstext></ps></ps_section>
  </iclass>
  <iclass>
    <regdiagram form="32"><box hibit="0" name="bit"><c>x</c></box></regdiagram>
    <encoding name="SECOND"><asmtemplate><text>SECOND</text></asmtemplate></encoding>
    <ps_section><ps><pstext>if bit == '1' then EndOfDecode(Decode_UNDEF); end;</pstext></ps></ps_section>
  </iclass>
</classes>
</instructionsection>`
	parsed, err := parseIForm(strings.NewReader(xml), "SECOND")
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Pseudocode) != 1 ||
		!strings.Contains(parsed.Pseudocode[0], "bit == '1'") {
		t.Fatalf("pseudocode = %#v, want only SECOND's decode", parsed.Pseudocode)
	}
}
