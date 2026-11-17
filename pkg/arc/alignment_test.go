package arc

import (
	"bytes"
	"testing"
)

func TestAlignedPCLTargets(t *testing.T) {
	for _, path := range []string{"testdata/binutils244-arc.tar", "testdata/llvm22-arc.json"} {
		for _, arch := range []string{"arc32", "arc32be"} {
			c := catalog(t, path, arch)
			atAligned, err := c.Assemble("bl.d 0x1064", 0x1000)
			if err != nil {
				t.Fatal(path, arch, err)
			}
			atHalfword, err := c.Assemble("bl.d 0x1064", 0x1002)
			if err != nil || len(atAligned) != len(atHalfword) {
				t.Fatalf("%s %s inconsistent address alignment: %v", path, arch, err)
			}
			for i, encoded := range atAligned {
				if !bytes.Equal(encoded, atHalfword[i]) {
					t.Fatalf("%s %s %x != %x", path, arch, encoded, atHalfword[i])
				}
				decoded, err := c.Decode(encoded)
				if err != nil {
					t.Fatal(err)
				}
				if target, ok := decoded.BranchTarget(0x1002); !ok || target != 0x1064 {
					t.Fatalf("%s %s target %x %v: %s", path, arch, target, ok, decoded.Format(0x1002))
				}
			}
		}
	}
}
