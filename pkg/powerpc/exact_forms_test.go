package powerpc

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// These source records encode real instructions even though their LLVM printer
// uses a composite predicate, malformed syntax, or a different physical opcode.
func TestExactSourceForms(t *testing.T) {
	ids := strings.Fields("BCC BCCA BCCCTR BCCCTR8 BCCCTRL BCCCTRL8 BCCL BCCLA BCCLR BCCLRL CTRL_DEP EVFSCTUF EVFSCTUIZ EVSEL MFTB TAILBA TAILBA8 alias_anonymous_18388 alias_anonymous_18389 alias_anonymous_18390")
	for _, arch := range []string{"powerpc32", "powerpc64", "powerpc32le", "powerpc64le"} {
		t.Run(arch, func(t *testing.T) {
			c := corpus(t, arch)
			for _, id := range ids {
				if strings.HasPrefix(arch, "powerpc32") && (id == "BCCCTR8" || id == "BCCCTRL8") {
					continue
				}
				var e *codec.Encoding
				for i := range c.Encodings {
					if c.Encodings[i].ID == id {
						e = &c.Encodings[i]
					}
				}
				if e == nil || !strings.HasPrefix(e.Syntax, "enc["+id+"] ") {
					t.Fatalf("source form %s lost its exact spelling: %+v", id, e)
				}
				for _, u := range c.Unsupported {
					if u.ID == id {
						t.Fatalf("supported source form %s still rejected: %s", id, u.Reason)
					}
				}
				values := map[string]int64{}
				for _, o := range e.Operands {
					values[o.Name] = (1 << uint(o.Width())) - 1
					if o.Signed {
						values[o.Name] = -4
					}
				}
				code, err := codec.Encode(e, values)
				if err != nil {
					t.Fatalf("%s boundary values: %v", id, err)
				}
				single := &codec.Catalog{Encodings: []codec.Encoding{*e}}
				decoded, err := single.Decode(code)
				if err != nil {
					t.Fatalf("%s: %v", id, err)
				}
				for _, o := range e.Operands {
					if decoded.Values[o.Name] != values[o.Name] || !strings.Contains(e.Syntax, "{"+o.Name+"}") {
						t.Fatalf("%s lost structured field %s: %+v", id, o.Name, decoded.Values)
					}
				}
				text := decoded.Format(0x100)
				assembled, err := c.Assemble(text, 0x100)
				found := false
				for _, b := range assembled {
					found = found || bytes.Equal(b, code)
				}
				if err != nil || !found {
					t.Fatalf("%s exact text %q changes %x: %x %v", id, text, code, assembled, err)
				}
				if strings.HasPrefix(id, "BCC") || id == "CTRL_DEP" {
					if values["BIBO"] != 127 || values["CR"] != 7 || !strings.Contains(llvmInstructionText(*e, values), "31, 31") {
						t.Fatalf("%s composite predicate lost BO/BI boundaries: %s", id, llvmInstructionText(*e, values))
					}
				}
				if id == "TAILBA" || id == "TAILBA8" {
					if target, ok := decoded.BranchTarget(0x100); !ok || target != 0xfc {
						t.Fatalf("%s AA=0 branch must be relative: %#x/%v", id, target, ok)
					}
				}
			}
			// Ordinary assembly retains its preferred instruction identities.
			for text, wantHex := range map[string]string{
				"mftb 1, 268":    "7c2c42a6",
				"evfsctsf 1, 2":  "10201297",
				"evfsctsiz 1, 2": "1020129a",
				"ba 0x100":       "48000102",
			} {
				want, _ := hex.DecodeString(wantHex)
				if strings.HasSuffix(arch, "le") {
					want[0], want[3], want[1], want[2] = want[3], want[0], want[2], want[1]
				}
				assembled, err := c.Assemble(text, 0)
				found := false
				for _, b := range assembled {
					found = found || bytes.Equal(b, want)
				}
				if err != nil || !found {
					t.Fatalf("ordinary spelling %q lost preferred bytes %x: %x %v", text, want, assembled, err)
				}
			}
		})
	}
}
