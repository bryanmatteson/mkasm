package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunARM32CombinesA32AndBothThumbWidths(t *testing.T) {
	var archive bytes.Buffer
	w := tar.NewWriter(&archive)
	files := map[string]string{
		"a32_encindex.xml": `<encodingindex><instructiontable iclass="hint"><tr class="instructiontable" encname="NOP_A1" iformfile="arm.xml"><td class="iformname" iformid="NOP">NOP</td></tr><tr class="instructiontable" encname="UNALLOCATED"/></instructiontable></encodingindex>`,
		"t32_encindex.xml": `<encodingindex><instructiontable iclass="hint"><tr class="instructiontable" encname="NOP_T1" iformfile="thumb16.xml"><td class="iformname" iformid="NOP">NOP</td></tr><tr class="instructiontable" encname="NOP_T2" iformfile="thumb32.xml"><td class="iformname" iformid="NOP">NOP</td></tr></instructiontable></encodingindex>`,
	}
	for _, form := range []struct{ file, id, state, bits string }{
		{"arm.xml", "NOP_A1", "A32", "11100011001000001111000000000000"},
		{"thumb16.xml", "NOP_T1", "T32", "1011111100000000"},
		{"thumb32.xml", "NOP_T2", "T32", "11110011101011111000000000000000"},
	} {
		files[form.file] = fmt.Sprintf(`<instructionsection><classes><iclass isa="%s"><regdiagram form="%d"><box hibit="%d" width="%d"><c colspan="%d">%s</c></box></regdiagram><encoding name="%s"><asmtemplate><text>NOP</text></asmtemplate></encoding></iclass></classes></instructionsection>`, form.state, len(form.bits), len(form.bits)-1, len(form.bits), len(form.bits), form.bits, form.id)
	}
	for name, data := range files {
		if err := w.WriteHeader(&tar.Header{Name: "ISA/" + name, Size: int64(len(data)), Mode: 0644}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--arch", "thumb", "--json", "-"}, bytes.NewReader(archive.Bytes()), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var document jsonDocument
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Architecture != "arm32" || len(document.Instructions) != 3 {
		t.Fatalf("bad ARM32 document: %#v", document)
	}
	for i, item := range document.Instructions {
		wantWidth, wantState := 32, "T32"
		if i == 0 {
			wantState = "A32"
		}
		if i == 1 {
			wantWidth = 16
		}
		if item.Width != wantWidth || item.InstructionSet != wantState {
			t.Fatalf("lost instruction state: %#v", item)
		}
	}
	directory := t.TempDir()
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0644); err != nil {
			t.Fatal(err)
		}
	}
	stdout.Reset()
	if err := run(context.Background(), []string{"--arch", "arm32", "--json", directory}, nil, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil || len(document.Instructions) != 3 {
		t.Fatalf("local directory input did not resolve both states: %v", err)
	}
	output := t.TempDir()
	if err := run(context.Background(), []string{"--arch", "arm32", "--codegen", "rust", "--output", output, "-"}, bytes.NewReader(archive.Bytes()), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"lib", "a32", "t16", "t32", "encoders"} {
		data, err := os.ReadFile(filepath.Join(output, "src", module+".rs"))
		if err != nil || !strings.Contains(string(data), "pub fn ") {
			t.Fatalf("missing generated %s API: %v", module, err)
		}
	}
}
