package hexagon

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestCompilerOnlyAliasesDoNotReplacePhysicalControlFlow(t *testing.T) {
	c := fixture(t)
	for _, test := range []struct {
		word uint32
		id   string
	}{
		{0x529fc000, "J2_jumpr"}, // LR return
		{0x5287c000, "J2_jumpr"}, // ordinary indirect jump
		{0x5a00c006, "J2_call"},
		{0x50a5c000, "J2_callr"},
	} {
		bytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(bytes, test.word)
		packet, _, err := c.DecodePacket(bytes, 0x1000, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := packet.Words[0].Instructions[0].ID; got != test.id {
			t.Fatalf("%08x: physical identity %s, want %s", test.word, got, test.id)
		}
	}
	for _, id := range []string{"J2_loop0iext", "J2_loop0rext", "J2_loop1iext", "J2_loop1rext"} {
		encoding, err := c.entry(id)
		if err != nil || encoding.AssemblyOnly || !c.Metadata[id].MustExtend {
			t.Fatalf("mandatory extended loop %s must remain decodable: %v", id, err)
		}
	}
}

func fixture(t *testing.T) *Catalog {
	t.Helper()
	f, err := os.Open("testdata/hexagon.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f, "hexagon")
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func TestImport(t *testing.T) {
	c := fixture(t)
	t.Logf("words %d subinstructions %d unsupported %d profiles %d", len(c.Words.Encodings), len(c.Subinstructions.Encodings), len(c.Unsupported), len(c.FeatureSets))
	if len(c.Words.Encodings) != 2882 || len(c.Subinstructions.Encodings) != 52 || len(c.Unsupported) != 8 {
		t.Fatal("complete pinned target record accounting changed")
	}
	for _, u := range c.Unsupported {
		t.Log(u.ID, u.Reason)
	}
}

func TestActualLLVMInput(t *testing.T) {
	path := os.Getenv("HEXAGON_SOURCE")
	if path == "" {
		t.Skip("set HEXAGON_SOURCE to llvm-tblgen --dump-json")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f, "hexagon")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Words.Encodings) != 2882 || len(c.Subinstructions.Encodings) != 52 || len(c.Unsupported) != 8 {
		t.Fatalf("actual source counts %d/%d/%d", len(c.Words.Encodings), len(c.Subinstructions.Encodings), len(c.Unsupported))
	}
}
