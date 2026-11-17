package v850

import (
	"bytes"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type vector struct {
	ID       string `json:"id"`
	CPU      string `json:"cpu"`
	Assembly string `json:"assembly"`
	Bytes    string `json:"bytes"`
}

func oracleText(e *codec.Encoding, values map[string]int64) string {
	d := codec.Decoded{Encoding: e, Values: values}
	text := d.Format(0x1000)
	for _, o := range e.Operands {
		if o.Relative {
			text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", uint32(0x1000+values[o.Name])), fmt.Sprintf(".%+d", values[o.Name]))
		}
	}
	name := e.Mnemonic
	for _, o := range e.Operands {
		switch o.Class {
		case "IMM32":
			if name == "mov" {
				name = "movl"
			}
			if name == "prepare" {
				at := strings.LastIndexByte(text, ',')
				text = text[:at+1] + fmt.Sprintf(" hilo(%d)", values[o.Name])
			}
		case "IMM16HI":
			if name == "prepare" {
				at := strings.LastIndexByte(text, ',')
				text = text[:at+1] + fmt.Sprintf(" hi0(%d)", values[o.Name])
			}
		case "D17_16":
			if !strings.HasSuffix(name, "17") {
				name += "17"
			}
		case "D32_31_PCREL":
			if name == "jarl" || name == "jr" {
				name += "32"
			}
		case "D32_31":
			if name == "jmp" {
				name += "32"
			}
		case "D23", "D23_ALIGN1":
			if !strings.HasSuffix(name, "23") {
				name += "23"
			}
		}
	}
	return name + strings.TrimPrefix(text, e.Mnemonic)
}
func TestGNUOracle(t *testing.T) {
	as := os.Getenv("MKASM_V850_AS")
	if as == "" {
		t.Skip("set MKASM_V850_AS to GNU binutils 2.44 v850 assembler")
	}
	c := load(t)
	dir := t.TempDir()
	if p := os.Getenv("MKASM_V850_ARTIFACT_DIR"); p != "" {
		dir = p
		os.MkdirAll(dir, 0755)
	}
	var vectors []vector
	for j := range c.Encodings {
		e := &c.Encodings[j]
		v := sample(e)
		expected, err := c.Encode(e.ID, v)
		if err != nil {
			t.Fatal(err)
		}
		text := oracleText(e, v)
		mask, _ := strconv.Atoi(strings.TrimPrefix(e.Features[0], "cpu_"))
		cpu := "v850"
		for i, n := range []string{"v850", "v850e", "v850e1", "v850e2", "v850e2v3", "v850e3v5"} {
			if mask&(1<<uint(i)) != 0 {
				cpu = n
			}
		}
		object := filepath.Join(dir, "current.o")
		cmd := exec.Command(as, "-m"+cpu, "-mextension", "-o", object)
		cmd.Stdin = strings.NewReader(".text\n" + text + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s %q: %v %s", e.ID, text, err, out)
			continue
		}
		f, err := elf.Open(object)
		if err != nil {
			t.Fatal(err)
		}
		data, err := f.Section(".text").Data()
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		if len(data) < len(expected) || !bytes.Equal(data[:len(expected)], expected) {
			t.Errorf("%s %q: GNU %x codec %x", e.ID, text, data, expected)
			continue
		}
		for _, b := range data[len(expected):] {
			if b != 0 {
				t.Errorf("%s unexpected trailing bytes %x", e.ID, data)
			}
		}
		vectors = append(vectors, vector{e.ID, cpu, text, hex.EncodeToString(expected)})
	}
	b, _ := json.MarshalIndent(vectors, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "gnu-vectors.json"), b, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d/%d forms match independent GNU assembler", len(vectors), len(c.Encodings))
}
func TestGhidraOracle(t *testing.T) {
	if os.Getenv("MKASM_V850_GHIDRA") == "" {
		t.Skip("set MKASM_V850_GHIDRA=1 for installed Ghidra 12.1.2")
	}
	c := load(t)
	dir := t.TempDir()
	if p := os.Getenv("MKASM_V850_ARTIFACT_DIR"); p != "" {
		dir = filepath.Join(p, "oracle")
	}
	script, err := filepath.Abs("../../scripts/ghidra-codec-oracle.py")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", script, "--output", dir)
	var input bytes.Buffer
	enc := json.NewEncoder(&input)
	for j := range c.Encodings {
		e := &c.Encodings[j]
		b, err := c.Encode(e.ID, sample(e))
		if err != nil {
			t.Fatal(err)
		}
		enc.Encode(map[string]any{"id": e.ID, "language": "V850:LE:32:default", "address": "0x1000", "bytes": hex.EncodeToString(b)})
	}
	cmd.Stdin = &input
	var out, diagnostics bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &diagnostics
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v %s", err, diagnostics.String())
	}
	var results []map[string]any
	decoder := json.NewDecoder(&out)
	accepted, mismatch, unsupported := 0, 0, 0
	for j := range c.Encodings {
		var r map[string]any
		if err := decoder.Decode(&r); err != nil {
			t.Fatal(err)
		}
		e := &c.Encodings[j]
		if r["id"] != e.ID {
			t.Fatal("oracle response out of order")
		}
		results = append(results, r)
		if r["error"] != nil {
			unsupported++
			continue
		}
		if int(r["length"].(float64)) != len(e.Mask) {
			mismatch++
			continue
		}
		accepted++
	}
	if accepted != 331 || mismatch != 4 || unsupported != 68 {
		t.Fatalf("Ghidra 12.1.2 language coverage changed: %d same-length, %d different-length, %d unsupported", accepted, mismatch, unsupported)
	}
	if p := os.Getenv("MKASM_V850_ARTIFACT_DIR"); p != "" {
		b, _ := json.MarshalIndent(results, "", "  ")
		os.WriteFile(filepath.Join(p, "ghidra-results.json"), b, 0644)
		os.WriteFile(filepath.Join(p, "ghidra-diagnostics.log"), diagnostics.Bytes(), 0644)
	}
	t.Logf("Ghidra 12.1.2 default: %d same-length forms, %d different-length decodes, %d unsupported; all 403 are separately GNU byte validated", accepted, mismatch, unsupported)
}

func TestGhidraExactOracle(t *testing.T) {
	if os.Getenv("MKASM_V850_GHIDRA") == "" {
		t.Skip("set MKASM_V850_GHIDRA=1 for installed Ghidra 12.1.2")
	}
	raw, err := os.ReadFile("testdata/ghidra-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		ID       string `json:"id"`
		Bytes    string `json:"bytes"`
		Assembly string `json:"ghidra_assembly"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 308 {
		t.Fatal(len(rows))
	}
	dir := t.TempDir()
	if p := os.Getenv("MKASM_V850_ARTIFACT_DIR"); p != "" {
		dir = filepath.Join(p, "oracle-assembly")
	}
	script, err := filepath.Abs("../../scripts/ghidra-codec-oracle.py")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("python3", script, "--output", dir)
	var input, output, diagnostics bytes.Buffer
	enc := json.NewEncoder(&input)
	for _, row := range rows {
		enc.Encode(map[string]any{"id": row.ID, "language": "V850:LE:32:default", "address": "0x1000", "assembly": row.Assembly})
	}
	cmd.Stdin = &input
	cmd.Stdout = &output
	cmd.Stderr = &diagnostics
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v %s", err, diagnostics.String())
	}
	dec := json.NewDecoder(&output)
	for _, row := range rows {
		var result struct {
			ID      string `json:"id"`
			Encoded string `json:"encoded"`
			Error   string `json:"error"`
		}
		if err := dec.Decode(&result); err != nil {
			t.Fatal(err)
		}
		if result.ID != row.ID || result.Encoded != row.Bytes || result.Error != "" {
			t.Fatalf("Ghidra %s %q: %+v expected %s", row.ID, row.Assembly, result, row.Bytes)
		}
	}
	if p := os.Getenv("MKASM_V850_ARTIFACT_DIR"); p != "" {
		os.WriteFile(filepath.Join(p, "ghidra-exact-results.jsonl"), output.Bytes(), 0644)
		os.WriteFile(filepath.Join(p, "ghidra-exact-diagnostics.log"), diagnostics.Bytes(), 0644)
	}
	t.Logf("%d exact Ghidra decode/reassembly byte comparisons", len(rows))
}
