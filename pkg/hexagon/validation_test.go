package hexagon

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestMalformedPacketsAndFeatures(t *testing.T) {
	c := fixture(t)
	valid, err := c.AssemblePacket("{\nr0 = ##305419896\n}", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	for cut := 0; cut < len(valid[0]); cut++ {
		if _, _, err := c.DecodePacket(valid[0][:cut], 0, nil); err == nil {
			t.Fatalf("accepted truncated packet at %d", cut)
		}
	}
	for _, raw := range []uint32{0xf0002000, 0x0000c000} {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, raw)
		if _, _, err := c.DecodePacket(b, 0, nil); err == nil {
			t.Fatalf("accepted reserved/dangling packet %x", b)
		}
	}
	if _, err := c.AssemblePacket("{\nmemw(r1+#0) = r0.new\n}", 0, nil); err == nil {
		t.Fatal("accepted new-value consumer without producer")
	}
	if _, err := c.AssemblePacket("{\nr0 = #1\n}:endloop1", 0, nil); err == nil {
		t.Fatal("accepted loop marker without physical word")
	}
	if _, err := c.AssemblePacket("{\nv0.b = vadd(v1.b,v2.b)\n}", 0, c.FeatureSets["hexagonv5"]); err == nil {
		t.Fatal("accepted HVX on scalar-only profile")
	}
	text := "{\nv0.b = vadd(v1.b,v2.b)\n}"
	if _, err := c.AssemblePacket(text, 0, c.FeatureSets["hexagonv81+hvx-length128b"]); err != nil {
		t.Fatal(err)
	}
}
func TestDistinctImmediateNamesAndAddress(t *testing.T) {
	c := fixture(t)
	for _, text := range []string{"{\nr1:0 = combine(#2,#3)\n}", "{\njump 0xff0\n}"} {
		variants, err := c.AssemblePacket(text, 0x1000, nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range variants {
			p, _, err := c.DecodePacket(b, 0x1000, nil)
			if err != nil {
				t.Fatal(err)
			}
			formatted := c.FormatPacket(p, 0x1000)
			again, err := c.AssemblePacket(formatted, 0x1000, nil)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, a := range again {
				found = found || bytes.Equal(a, b)
			}
			if !found {
				t.Fatalf("lost semantic text %s", formatted)
			}
			if strings.Contains(text, "combine") && !strings.Contains(formatted, "#2,#3") {
				t.Fatalf("Ii and II confused: %s", formatted)
			}
		}
	}
}

func TestAliasImmediateDomain(t *testing.T) {
	c := fixture(t)
	e, err := c.entry("S2_tableidxb_goodsyntaxAlias")
	if err != nil {
		t.Fatal(err)
	}
	i := sample(e, 0)
	i.Values["II"] = 63
	if _, err := c.EncodePacket(Packet{Words: []Word{{[]Instruction{i}}}}, 0, nil); err == nil {
		t.Fatal("accepted six-bit value in five-bit alias domain")
	}
	i.Values["II"] = 31
	if _, err := c.EncodePacket(Packet{Words: []Word{{[]Instruction{i}}}}, 0, nil); err != nil {
		t.Fatal(err)
	}
}
