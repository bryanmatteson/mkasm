package arm

import (
	"os"
	"path/filepath"
	"testing"
)

// iformFilePath locates an optional extracted corpus for implementation-level
// regression tests. Corpus-scale proof uses the explicit compressed input in
// the top-level conformance suite.
func iformFilePath(t *testing.T, name string) string {
	t.Helper()
	for _, root := range []string{
		filepath.Join("..", "..", "spec", "ISA"),
		filepath.Join("spec", "ISA"),
	} {
		filename := filepath.Join(root, name)
		if st, err := os.Stat(filename); err == nil && st.Size() > 0 {
			return filename
		}
	}
	t.Skipf("optional extracted IForm %q is unavailable; run the top-level conformance suite for corpus-scale proof", name)
	return ""
}
