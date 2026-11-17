package hexagon

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestPacketAddressWrap(t *testing.T) {
	c := fixture(t)
	for _, mnemonic := range []string{"jump", "call", "if (p0) call", "if (!p0) call"} {
		for _, tc := range []struct{ target, pc, want uint64 }{
			{0xffc, 0, 0xfffffffc}, {0x1004, 0xfffffffc, 0},
		} {
			all, err := c.AssemblePacket(fmt.Sprintf("{\n%s 0x%x\n}", mnemonic, tc.target), 0x1000, nil)
			if err != nil || len(all) == 0 {
				t.Fatalf("assemble: %v", err)
			}
			for _, code := range all {
				p, _, err := c.DecodePacket(code, tc.pc, nil)
				if err != nil {
					t.Fatal(err)
				}
				text := c.FormatPacket(p, tc.pc)
				if !strings.Contains(strings.ReplaceAll(text, "##", ""), fmt.Sprintf("%s 0x%x", mnemonic, tc.want)) {
					t.Errorf("packet at %#x: %q, want %#x", tc.pc, text, tc.want)
				}
				again, err := c.AssemblePacket(fmt.Sprintf("{\n%s 0x%x\n}", mnemonic, tc.want), tc.pc, nil)
				found := false
				for _, b := range again {
					found = found || bytes.Equal(b, code)
				}
				if err != nil || !found {
					t.Errorf("boundary assembly: %x (%v), want %x", again, err, code)
				}
			}
		}
	}
}
