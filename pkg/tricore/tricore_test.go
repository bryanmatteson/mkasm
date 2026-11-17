package tricore

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSource(t *testing.T) {
	for _, arch := range []string{"tricore", "tricore-pcp"} {
		t.Run(arch, func(t *testing.T) {
			c, err := Parse(nil, arch)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("encodings=%d", len(c.Encodings))
			for _, e := range c.Encodings {
				if strings.Contains(e.Syntax, "{{") {
					t.Fatal(e.Syntax)
				}
			}
		})
	}
}

func TestPinnedSourceCoverage(t *testing.T) {
	hashes := map[string]string{Source: "d184686bf1092ad6bb799102d6ed64b1c8ced07d8b8b4448ac54c939b5e9ccca", PCPSource: "70f47e558faf70902bde5dcb50ee2292193ff01995d0c6dc2b980ab4c4a03524"}
	for source, want := range hashes {
		if fmt.Sprintf("%x", sha256.Sum256([]byte(source))) != want {
			t.Fatal("pinned upstream source changed")
		}
	}
	for _, arch := range []string{"tricore", "tricore-pcp"} {
		c, err := Parse(nil, arch)
		if err != nil {
			t.Fatal(err)
		}
		source := Source
		profiles := []string{"v2", "rider-d", "rider-b"}
		mode := "PCPMode=0"
		if arch == "tricore-pcp" {
			source += "\n" + PCPSource
			profiles = []string{"pcp"}
			mode = "PCPMode=1"
		}
		for _, profile := range profiles {
			d, err := sourceDescription(stripComments(source), profile)
			if err != nil {
				t.Fatal(err)
			}
			constructors, forms, sourceForms := 0, 0, 0
			for _, instruction := range d.instructions {
				if !strings.Contains(instruction.pattern, mode) {
					continue
				}
				constructors++
				variants, err := d.expand(instruction, 0)
				if err != nil {
					t.Fatal(err)
				}
				for _, variant := range variants {
					_, err := d.encoding(variant)
					if err == nil {
						sourceForms++
					} else if !errors.Is(err, errConflict) {
						t.Fatal(err)
					}
				}
				prefix := fmt.Sprintf("%s_L%d_", profile, instruction.line)
				found := false
				for _, e := range c.Encodings {
					found = found || strings.HasPrefix(e.ID, prefix)
				}
				if !found {
					t.Errorf("lost source constructor %s %s", prefix, instruction.display)
				}
			}
			for _, e := range c.Encodings {
				if e.Features[0] == "tricore-"+profile {
					forms++
				}
			}
			t.Logf("%s constructors=%d expanded source forms=%d priority-partitioned forms=%d", profile, constructors, sourceForms, forms)
		}
		if len(c.Unsupported) != 0 {
			t.Fatal("unexpected unsupported records", c.Unsupported)
		}
	}
}
func TestSourcePriority(t *testing.T) {
	c, err := Parse(nil, "tricore")
	if err != nil {
		t.Fatal(err)
	}
	// COP's generic opcode overlaps PACK. The source's more-specific PACK
	// constructor reserves this region, including through assembly/templates.
	d, err := c.Decode([]byte{0x6b, 0, 0, 0})
	if err != nil || d.Encoding.Mnemonic != "pack" {
		t.Fatal(d, err)
	}
	for _, profile := range []string{"v2", "rider-d", "rider-b"} {
		if b, err := c.AssembleWithFeatures("cop 0[0],d0,d0,d0,d0", 0, c.FeatureSets[profile]); err == nil {
			t.Fatalf("reserved COP region admitted %s %x", profile, b)
		}
	}
	if _, err = c.Assemble("cop 255[3],d15,d15,d15", 0); err != nil {
		t.Fatal(err)
	}
}
