package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunJSONKeepsStdoutMachineReadable(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(), []string{"--json", "-"},
		bytes.NewReader(testCorpus(t)), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	var document jsonDocument
	if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if document.Schema != "mkasm.ir.v1" || document.Architecture != "aarch64" {
		t.Fatalf("document header = %#v", document)
	}
	if len(document.Instructions) != 1 || document.Instructions[0].EncodingID != "EXAMPLE" {
		t.Fatalf("instructions = %#v", document.Instructions)
	}
	if strings.Contains(stdout.String(), "Pass ") || strings.Contains(stdout.String(), "Instructions:") {
		t.Fatalf("stdout contains diagnostics:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Pass 1 complete") ||
		!strings.Contains(stderr.String(), "Instructions: 1 total, 1 resolved") {
		t.Fatalf("stderr lacks progress/stats:\n%s", stderr.String())
	}
}

func TestRunCodegenWritesOnlyRequestedProject(t *testing.T) {
	output := filepath.Join(t.TempDir(), "generated")
	var stdout, stderr bytes.Buffer
	if err := run(context.Background(),
		[]string{"--codegen", "go", "--output", output, "-"},
		bytes.NewReader(testCorpus(t)), &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("codegen stdout = %q", stdout.String())
	}
	for _, name := range []string{"go.mod", "encoders", "decoders", "registry"} {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Errorf("generated project missing %s: %v", name, err)
		}
	}
	if !strings.Contains(stderr.String(), "Pass 3 (go)") {
		t.Fatalf("stderr lacks codegen progress:\n%s", stderr.String())
	}
}

func TestRunAcceptsFileAndURLInputs(t *testing.T) {
	archive := testCorpus(t)
	filename := filepath.Join(t.TempDir(), "isa.tar")
	if err := os.WriteFile(filename, archive, 0o644); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer server.Close()

	for _, input := range []string{filename, server.URL} {
		t.Run(input, func(t *testing.T) {
			var stdout bytes.Buffer
			if err := run(context.Background(), []string{"--json", input},
				bytes.NewReader(nil), &stdout, io.Discard); err != nil {
				t.Fatal(err)
			}
			var document jsonDocument
			if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
				t.Fatalf("stdout is not JSON: %v", err)
			}
			if len(document.Instructions) != 1 {
				t.Fatalf("instructions = %d", len(document.Instructions))
			}
		})
	}
}

func TestRunRejectsInvalidModeCombinations(t *testing.T) {
	tests := [][]string{
		{"input.tar"},
		{"--json", "--codegen", "rust", "input.tar"},
		{"--codegen", "rust", "input.tar"},
		{"--json", "--output", "out", "input.tar"},
		{"--codegen", "swift", "--output", "out", "input.tar"},
		{"--json"},
	}
	for _, args := range tests {
		err := run(context.Background(), args, bytes.NewReader(nil), io.Discard, io.Discard)
		var badUsage *usageError
		if !errors.As(err, &badUsage) {
			t.Errorf("run(%q) error = %v, want usage error", args, err)
		}
	}
}

func TestHelpUsesInstalledCommandName(t *testing.T) {
	var stderr bytes.Buffer
	if err := run(context.Background(), []string{"--help"},
		bytes.NewReader(nil), io.Discard, &stderr); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stderr.String(), "usage:\n  asmgen ") {
		t.Fatalf("help does not identify asmgen:\n%s", stderr.String())
	}
	if strings.Contains(stderr.String(), "parse-arm") {
		t.Fatalf("help contains retired command name:\n%s", stderr.String())
	}
}

func testCorpus(t *testing.T) []byte {
	t.Helper()
	files := []struct {
		name string
		data string
	}{
		{
			name: "ISA/encodingindex.xml",
			data: `<encodingindex>
				<instructiontable iclass="test">
					<tr class="instructiontable" encname="EXAMPLE" iformfile="example.xml">
						<td class="iformname" iformid="NOP">NOP</td>
					</tr>
				</instructiontable>
			</encodingindex>`,
		},
		{
			name: "ISA/example.xml",
			data: `<instructionsection>
				<classes><iclass>
					<regdiagram form="32">
						<box hibit="31" width="32" name="opcode"><c colspan="32">0</c></box>
					</regdiagram>
					<encoding name="EXAMPLE"><asmtemplate><text>NOP</text></asmtemplate></encoding>
				</iclass></classes>
			</instructionsection>`,
		},
	}

	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, file := range files {
		if err := writer.WriteHeader(&tar.Header{
			Name: file.name,
			Mode: 0o644,
			Size: int64(len(file.data)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(writer, file.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
