package m68k

import (
	"reflect"
	"testing"
)

func TestRustExactOpcodeIndicesPreserveMnemonicUnion(t *testing.T) {
	opcodes := []Opcode{
		{ID: "safe_z", Mnemonic: "add"},
		{ID: "add", Mnemonic: "other"},
		{ID: "alias_id", Mnemonic: "subtract"},
		{ID: "foo.bar", Mnemonic: "foobar"},
		{ID: "safe_a", Mnemonic: "other"},
		{ID: "chain_id", Mnemonic: "other"},
	}
	aliases := []Alias{{"alias_id", "add"}, {"chain_id", "alias_id"}}
	if got, want := rustExactOpcodeIndices(opcodes, aliases), []int{4, 0}; !reflect.DeepEqual(got, want) {
		t.Fatalf("exact indices %v want %v", got, want)
	}
}
