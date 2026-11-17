package mips

import (
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompressedModes(t *testing.T) {
	for _, arch := range []string{"micromips32", "micromips32el", "micromips64", "micromips64el", "mips16", "mips16el", "mips16-64", "mips16-64el"} {
		t.Run(arch, func(t *testing.T) {
			f, err := os.Open("testdata/llvm22-compressed.json.gz")
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			z, err := gzip.NewReader(f)
			if err != nil {
				t.Fatal(err)
			}
			defer z.Close()
			c, err := Parse(z, arch)
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range c.Unsupported {
				t.Errorf("unhandled source form %s: %s", u.ID, u.Reason)
			}
			min := 700
			if strings.HasPrefix(arch, "mips16") {
				min = 60
			}
			if len(c.Encodings) < min {
				t.Fatalf("incomplete source catalog: %d", len(c.Encodings))
			}
			t.Logf("%d forms", len(c.Encodings))
			if testing.Short() {
				return
			}
			out := t.TempDir()
			if err := c.GenerateRust(out); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("cargo", "test", "--manifest-path", filepath.Join(out, "Cargo.toml"), "--lib", "--test", "positions", "--quiet")
			if log, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("generated consumer: %v\n%s", err, log)
			}
		})
	}
}
