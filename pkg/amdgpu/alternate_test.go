package amdgpu

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func TestAlternatePhysicalEncodings(t *testing.T) {
	c := sourceCatalog(t)
	seen := map[string]bool{}
	tested := map[string]bool{}
	for i := range c.Encodings {
		e := &c.Encodings[i]
		if !strings.HasPrefix(e.Syntax, "enc[") {
			continue
		}
		id := strings.Split(e.ID, "/")[0]
		seen[id] = true
		values := representative(e)
		if _, err := codec.Encode(e, values); err != nil {
			continue
		}
		for _, format := range []int64{0, 1, 127} {
			if _, ok := values["format"]; ok {
				values["format"] = format
			}
			code, err := codec.Encode(e, values)
			if err != nil {
				t.Fatalf("%s: %v", e.ID, err)
			}
			d := codec.Decoded{Encoding: e, Values: values, Length: len(code)}
			parsed, ok := codec.ParseOperands(e, d.Format(0x1000), 0x1000)
			if !ok {
				t.Fatalf("%s: cannot parse exact spelling %q", e.ID, d.Format(0x1000))
			}
			back, err := codec.Encode(e, parsed)
			if err != nil || !bytes.Equal(back, code) {
				t.Fatalf("%s: format lost physical fields: %x -> %x (%v)", e.ID, code, back, err)
			}
			tested[id] = true
		}
	}
	if len(seen) < 600 {
		t.Fatalf("only %d alternate source records imported", len(seen))
	}
	for id := range seen {
		if !tested[id] {
			t.Errorf("no legal alternative representative tested for %s", id)
		}
	}
	for _, u := range c.Unsupported {
		if strings.Contains(u.Reason, "NonParsable") {
			t.Fatalf("valid alternate source encoding still rejected: %+v", u)
		}
	}
	t.Logf("%d alternate source records imported with exact spellings", len(seen))
}
