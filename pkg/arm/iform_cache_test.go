package arm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParsedIFormCacheRetainsPipelineCorpus(t *testing.T) {
	dir := t.TempDir()
	writeIFormFixture(t, filepath.Join(dir, "a.xml"), "A")
	writeIFormFixture(t, filepath.Join(dir, "b.xml"), "B")

	cache := NewParsedIFormCache(0)
	if _, err := cache.GetOrLoad(filepath.Join(dir, "a.xml"), "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.GetOrLoad(filepath.Join(dir, "b.xml"), "B"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.GetOrLoad(filepath.Join(dir, "a.xml"), "A"); err != nil {
		t.Fatal(err)
	}

	if got := len(cache.data); got != 2 {
		t.Fatalf("unbounded cache retained %d forms, want 2", got)
	}
	if got := cache.Hits(); got != 1 {
		t.Fatalf("cache hits = %d, want 1", got)
	}
	if got := cache.Misses(); got != 2 {
		t.Fatalf("cache misses = %d, want 2", got)
	}
}

func TestParsedIFormCacheHonorsPositiveBound(t *testing.T) {
	dir := t.TempDir()
	writeIFormFixture(t, filepath.Join(dir, "a.xml"), "A")
	writeIFormFixture(t, filepath.Join(dir, "b.xml"), "B")

	cache := NewParsedIFormCache(1)
	if _, err := cache.GetOrLoad(filepath.Join(dir, "a.xml"), "A"); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.GetOrLoad(filepath.Join(dir, "b.xml"), "B"); err != nil {
		t.Fatal(err)
	}
	if got := len(cache.data); got != 1 {
		t.Fatalf("bounded cache retained %d forms, want 1", got)
	}
}

func writeIFormFixture(t *testing.T, path, encoding string) {
	t.Helper()
	xml := `<instructionsection><iclass><regdiagram><box hibit="0"><c>1</c></box></regdiagram>` +
		`<encoding name="` + encoding + `"><asmtemplate><text>TEST</text></asmtemplate></encoding>` +
		`</iclass></instructionsection>`
	if err := os.WriteFile(path, []byte(xml), 0o644); err != nil {
		t.Fatal(err)
	}
}
