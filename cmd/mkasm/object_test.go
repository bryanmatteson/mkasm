package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/bryanmatteson/mkasm/pkg/object"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIProgramAssembly(t *testing.T) {
	mc := os.Getenv("MKASM_LLVM_MC")
	if mc == "" {
		t.Skip("set MKASM_LLVM_MC")
	}
	source := []byte(".text\ncall external\nlea external(%rip),%rax\n.bss\n.space 32\n")
	args := []string{"--assemble-object", "--assembler", mc, "--target-triple", "x86_64-unknown-linux-gnu", "--json", "-"}
	var out bytes.Buffer
	if e := run(context.Background(), args, bytes.NewReader(source), &out, io.Discard); e != nil {
		t.Fatal(e)
	}
	var report object.Object
	if e := json.Unmarshal(out.Bytes(), &report); e != nil {
		t.Fatal(e)
	}
	if report.Machine != 62 || len(report.Relocations) != 2 {
		t.Fatalf("%+v", report)
	}
	found := false
	for _, s := range report.Symbols {
		found = found || s.Name == "external"
	}
	if !found {
		t.Fatal("external symbol lost")
	}
	path := filepath.Join(t.TempDir(), "program.o")
	args = []string{"--assemble-object", "--assembler", mc, "--target-triple", "x86_64-unknown-linux-gnu", "--output", path, "-"}
	if e := run(context.Background(), args, bytes.NewReader(source), io.Discard, io.Discard); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	obj, e := object.Parse(raw)
	if e != nil || len(obj.Relocations) != 2 {
		t.Fatal(obj, e)
	}
}
