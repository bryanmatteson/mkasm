package codec

import (
	"bytes"
	"testing"
)

func TestOptionalBitsPreservedByStructuredAPIs(t *testing.T) {
	c := exampleCatalog(t)
	for ignored := int64(0); ignored < 16; ignored++ {
		encoded, err := c.Encode("PADDING", map[string]int64{"value": 3, "ignored": ignored})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := c.Decode(encoded)
		if err != nil || decoded.Values["ignored"] != ignored {
			t.Fatalf("ignored bits lost: %v, %v", decoded, err)
		}
		again, err := c.Encode(decoded.Encoding.ID, decoded.Values)
		if err != nil || !bytes.Equal(again, encoded) {
			t.Fatal("structured roundtrip changed ignored bits")
		}
		text, err := c.Assemble(decoded.Format(0), 0)
		if err != nil || len(text) != 1 || !bytes.Equal(text[0], []byte{0xeb, 3}) {
			t.Fatal("text did not select canonical ignored bits", text, err)
		}
	}
	encoded, err := c.Encode("PADDING", map[string]int64{"value": 3})
	if err != nil || !bytes.Equal(encoded, []byte{0xeb, 3}) {
		t.Fatal("omitted optional operand did not default to zero", err)
	}
}
