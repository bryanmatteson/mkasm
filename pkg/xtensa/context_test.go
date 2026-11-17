package xtensa

import (
	"bytes"
	"strings"
	"testing"
)

func TestExtendedLiteralContext(t *testing.T) {
	for _, arch := range []string{"xtensa", "xtensaeb"} {
		c := fixture(t, arch)
		for pc := uint32(0x1000); pc < 0x1004; pc++ {
			ctx := ExecutionContext{PC: pc, LITBASE: 0x40001}
			cases, e := c.AssembleWithContext("l32r a2,0x3fffc", ctx, nil)
			if e != nil {
				t.Fatal(e)
			}
			for _, b := range cases {
				d, e := c.Decode(b)
				if e != nil {
					t.Fatal(e)
				}
				text := c.FormatWithContext(d, ctx)
				if !strings.Contains(text, "0x3fffc") {
					t.Fatal(text)
				}
				moved, e := c.RelocateWithContext(d, ctx, ExecutionContext{PC: 0x2000, LITBASE: ctx.LITBASE})
				if e != nil {
					t.Fatal(e)
				}
				again, e := c.Encode(*moved)
				if e != nil || !bytes.Equal(again, b) {
					t.Fatalf("%x %x %v", b, again, e)
				}
				if _, e = c.RelocateWithContext(d, ctx, ExecutionContext{PC: 0x1000}); e == nil {
					t.Fatal("accepted out-of-range literal after disabling extended mode")
				}
			}
		}
	}
}
