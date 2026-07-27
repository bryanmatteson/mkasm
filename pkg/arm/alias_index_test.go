package arm

import (
	"strings"
	"testing"
)

func TestInspectIFormMemberBytes(t *testing.T) {
	const source = `<?xml version="1.0"?>
<!DOCTYPE instructionsection PUBLIC "a>b" "iform-p.dtd">
<!-- ignored -->
<arm:instructionsection xmlns:arm="urn:arm" type="alias">
  <docvar key="alias_mnemonic" value="PAGE"/>
  <aliasto refiform="base.xml"/>
  <encoding name="ONE_alias">
    <docvar key="alias_mnemonic" value="ONE &amp; ONLY"/>
    <![CDATA[<encoding name="NOT_AN_ELEMENT">]]>
  </encoding>
  <encoding name="TWO_alias"><docvar key="mnemonic" value="BASE"/></encoding>
</arm:instructionsection>`

	gotIDs, gotAliases, gotIForm, err := inspectIFormMember(strings.NewReader(source), "alias.xml")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !gotIForm {
		t.Fatal("instructionsection was not recognized")
	}
	if len(gotIDs) != 2 || gotIDs[0] != "ONE_alias" || gotIDs[1] != "TWO_alias" {
		t.Fatalf("encoding IDs = %#v", gotIDs)
	}
	if len(gotAliases) != 2 {
		t.Fatalf("aliases = %#v", gotAliases)
	}
	if gotAliases[0].Mnemonic != "ONE & ONLY" || gotAliases[0].RefIForm != "base.xml" {
		t.Fatalf("first alias = %#v", gotAliases[0])
	}
	if gotAliases[1].Mnemonic != "PAGE" || gotAliases[1].Canonical != "BASE" {
		t.Fatalf("second alias = %#v", gotAliases[1])
	}
}

func TestInspectIFormMemberBytesRejectsUnbalancedXML(t *testing.T) {
	_, _, _, err := inspectIFormMemberBytes(
		[]byte(`<instructionsection><encoding name="BAD"></instructionsection>`),
		"bad.xml",
	)
	if err == nil {
		t.Fatal("expected an unbalanced XML error")
	}
}
