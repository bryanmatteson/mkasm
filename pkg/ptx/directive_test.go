package ptx

import "testing"

const multilineJumpTable = `.version 6.0
.target sm_30
.address_size 64
.func f(){
table: .branchtargets
 first,
 second;
 brx.idx %r1,table;
first: bra second;
second: ret;
}`

func TestMultilineTerminatedDirectives(t *testing.T) {
	m, err := Decode(multilineJumpTable)
	if err != nil {
		t.Fatal(err)
	}
	if m.Encode() != multilineJumpTable || len(m.Instructions) != 3 {
		t.Fatal("jump table became instruction text")
	}
	f := m.ControlFlow()
	if len(f) != 3 || f[0].Kind != "branch" || f[0].Target != "table" || f[1].Target != "second" || f[2].Kind != "return" {
		t.Fatalf("jump table references: %+v", f)
	}
	for _, directive := range []string{".branchtargets a,\nb;", ".calltargets f,\ng;", ".alias f,\ng;", ".pragma \"first\",\n\"second\";"} {
		m, err := Decode(directive + "\nret;")
		if err != nil || len(m.Instructions) != 1 || m.Instructions[0].Mnemonic != "ret" {
			t.Fatalf("%s: %v", directive, err)
		}
	}
	for _, source := range []string{".branchtargets a,\nb", ".calltargets f,\ng", ".alias f,\ng"} {
		if _, err := Decode(source); err == nil {
			t.Fatalf("unterminated directive: %q", source)
		}
	}
}
