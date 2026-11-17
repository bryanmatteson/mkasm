package dotnet

import (
	"os"
	"strings"
	"testing"
)

func TestRealAttributeAndMarshalBlobs(t *testing.T) {
	b, e := os.ReadFile("testdata/anycpu.dll")
	if e != nil {
		t.Fatal(e)
	}
	im, e := Open(b)
	if e != nil {
		t.Fatal(e)
	}
	attrs, e := im.Metadata.Attributes(0)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, a := range attrs {
		if a.Constructor.DeclaringType != "ManagedFixture.MarkAttribute" {
			continue
		}
		v, e := im.Metadata.DecodeAttribute(a, nil)
		if e != nil {
			t.Fatal(e)
		}
		if len(v.Fixed) != 1 || v.Fixed[0].Text == nil || *v.Fixed[0].Text != "generic" || len(v.Named) != 1 || v.Named[0].Name != "Number" || v.Named[0].Field || v.Named[0].Value.Bits != 17 {
			t.Fatalf("%+v", v)
		}
		count++
		for n := 0; n < len(a.Value); n++ {
			bad := a
			bad.Value = a.Value[:n]
			if _, e := im.Metadata.DecodeAttribute(bad, nil); e == nil {
				t.Fatalf("accepted truncated attribute at %d", n)
			}
		}
	}
	if count != 1 {
		t.Fatal("real attribute missing")
	}
	for rid := uint32(1); rid <= im.Metadata.Tables[13].Count; rid++ {
		r, e := im.Metadata.Row(13, rid)
		if e != nil {
			t.Fatal(e)
		}
		b, e := im.Metadata.Blob(r[1])
		if e != nil {
			t.Fatal(e)
		}
		m, e := DecodeMarshal(b)
		if e != nil {
			t.Fatal(e)
		}
		if m.NativeType != 0x1e || m.Size == nil || *m.Size != 4 {
			t.Fatalf("actual MarshalAs ByValArray: %+v", m)
		}
	}
}

func TestSerializedBlobBoundaries(t *testing.T) {
	for _, b := range [][]byte{{}, {0x1e}, {0x1e, 4, 8, 1}, {0x2a}, {0x2c, 0, 0, 0}, {0xff}, {0x17, 0x80}} {
		if _, e := DecodeMarshal(b); e == nil {
			t.Fatalf("accepted invalid marshal %x", b)
		}
	}
	// PermissionSet: one named boolean property on a security attribute.
	b := append([]byte{'.', 1, 1, 'X', 8, 1, 0x54, 2, 1, 'A'}, 1)
	// Serialized length includes count and the complete named argument.
	b[4] = 6
	s, e := DecodeSecurity(b, nil)
	if e != nil || len(s.Attributes) != 1 || s.Attributes[0].Named[0].Value.Bits != 1 {
		t.Fatalf("%+v %v %x", s, e, b)
	}
	for n := 1; n < len(b); n++ {
		if _, e := DecodeSecurity(b[:n], nil); e == nil {
			t.Fatalf("accepted truncated security %d", n)
		}
	}
	r := cursor{b: []byte{1, 0, 0, 0, 17}}
	_, e = attributeValue(&r, SerializedType{Kind: "enum", Enum: "External.Enum"}, nil, 0)
	if e == nil || !strings.Contains(e.Error(), "resolver") {
		t.Fatal(e)
	}
}
