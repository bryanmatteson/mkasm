package codec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"

	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

func TestNumberTextWorksInConsumersForbiddingUnsafeCode(t *testing.T) {
	if _, err := exec.LookPath("rustc"); err != nil {
		t.Skip("rustc unavailable")
	}
	tmpl, err := template.New("numbers").ParseFS(assettemplates.FS, "rust/number_text.rs.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	source.WriteString("#![forbid(unsafe_code)]\n")
	if err := tmpl.ExecuteTemplate(&source, "number_text", nil); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "numbers.rs"), []byte(source.String()), 0644); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("rustc", "--edition=2021", "--test", "-Dwarnings", "numbers.rs", "-o", "number-tests")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("compile safe formatter consumer: %v\n%s", err, out)
	}
	if out, err := exec.Command(filepath.Join(dir, "number-tests")).CombinedOutput(); err != nil {
		t.Fatalf("execute number formatting boundaries: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
