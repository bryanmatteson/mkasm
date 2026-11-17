package mos6502

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type vector struct {
	ID       string `json:"id"`
	Profile  string `json:"profile"`
	Bytes    string `json:"bytes"`
	Assembly string `json:"assembly"`
	Actual   string `json:"assembler_bytes,omitempty"`
	DA65     string `json:"da65,omitempty"`
	Status   string `json:"status"`
}

func ca65Text(e *codec.Encoding, v map[string]int64) string {
	text := (&codec.Decoded{Encoding: e, Values: v}).Format(0x1000)
	if e.Mnemonic == "brk" {
		return fmt.Sprintf("brk\n.byte $%02x", v["signature"])
	}
	for _, o := range e.Operands {
		if o.Relative {
			text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", uint16(0x1000+o.PCBias+v[o.Name])), fmt.Sprintf("*+%d", o.PCBias+v[o.Name]))
		}
	}
	if e.Mnemonic == "xaa" {
		text = "ane" + strings.TrimPrefix(text, "xaa")
	}
	if e.Mnemonic == "ahx" {
		text = "sha" + strings.TrimPrefix(text, "ahx")
	}
	return strings.ReplaceAll(regexp.MustCompile(`0x([0-9a-f]+)`).ReplaceAllString(text, "$$${1}"), "*+", "current+")
}
func TestCC65Oracle(t *testing.T) {
	bin := os.Getenv("MKASM_MOS6502_CC65")
	if bin == "" {
		t.Skip("set MKASM_MOS6502_CC65 to the built cc65 V2.19 bin directory")
	}
	c := load(t)
	dir := t.TempDir()
	if p := os.Getenv("MKASM_MOS6502_ARTIFACT_DIR"); p != "" {
		dir = p
	}
	cfg := filepath.Join(dir, "link.cfg")
	os.WriteFile(cfg, []byte("MEMORY { ROM:start=$1000,size=$1000,file=%O; } SEGMENTS { CODE:load=ROM,type=ro; }"), 0644)
	exact, alternative, unsupported, reserved := 0, 0, 0, 0
	var vectors []vector
	for _, e := range c.Encodings {
		profile := profileFor(c, &e)
		cpu := profile
		if cpu == "w65c02" || cpu == "w65c02+nops" {
			cpu = "65c02"
		}
		v := sample(&e)
		expected, err := c.Encode(e.ID, v)
		if err != nil {
			t.Fatal(err)
		}
		row := vector{ID: e.ID, Profile: profile, Bytes: hex.EncodeToString(expected), Assembly: ca65Text(&e, v), Status: "documented"}
		for _, f := range e.Features {
			if f == "undocumented" || f == "reserved-nop" {
				row.Status = f
			}
		}
		if row.Status == "reserved-nop" {
			reserved++
			vectors = append(vectors, row)
			continue
		}
		src := filepath.Join(dir, "current.s")
		obj := filepath.Join(dir, "current.o")
		binary := filepath.Join(dir, "current.bin")
		os.WriteFile(src, []byte(".setcpu \""+cpu+"\"\n.segment \"CODE\"\ncurrent:\n"+row.Assembly+"\n"), 0644)
		cmd := exec.Command(filepath.Join(bin, "ca65"), "-o", obj, src)
		if out, err := cmd.CombinedOutput(); err != nil {
			unsupported++
			row.Actual = "unsupported: " + strings.TrimSpace(string(out))
			t.Log(e.ID, row.Actual)
		} else {
			cmd = exec.Command(filepath.Join(bin, "ld65"), "-C", cfg, "-o", binary, obj)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s link: %v %s", e.ID, err, out)
			}
			actual, err := os.ReadFile(binary)
			if err != nil {
				t.Fatal(err)
			}
			row.Actual = hex.EncodeToString(actual)
			if bytes.Equal(actual, expected) {
				exact++
			} else {
				// NMOS repeated NOP/JAM/ANC and the alternate SBC opcode have no
				// ca65 syntax that selects each redundant physical opcode.
				if row.Status != "undocumented" {
					t.Fatalf("%s assembler %x codec %x", e.ID, actual, expected)
				}
				d, err := c.DecodeWithFeatures(actual, c.FeatureSets[profile])
				if err != nil || d.Encoding.Mnemonic != e.Mnemonic {
					t.Fatalf("%s assembler chose different instruction %x %v", e.ID, actual, err)
				}
				alternative++
			}
		}
		os.WriteFile(binary, expected, 0644)
		listing := filepath.Join(dir, "current.dis.s")
		cmd = exec.Command(filepath.Join(bin, "da65"), "--cpu", cpu, "--start-addr", "4096", "-o", listing, binary)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s da65: %v %s", e.ID, err, out)
		}
		data, err := os.ReadFile(listing)
		if err != nil {
			t.Fatal(err)
		}
		// An opcode may carry a generated label on the same line. Operands
		// may use generated labels outside the single-instruction region.
		label := regexp.MustCompile(`\bL([0-9A-Fa-f]{4})\b`)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(strings.Split(line, ";")[0])
			if i := strings.IndexByte(line, ':'); i >= 0 && !strings.Contains(line, "a:") {
				line = strings.TrimSpace(line[i+1:])
			}
			if strings.HasPrefix(line, e.Mnemonic+" ") || line == e.Mnemonic {
				line = label.ReplaceAllString(line, "0x${1}")
				line = strings.ReplaceAll(line, "a:", "")
				row.DA65 = line
				break
			}
		}
		if row.DA65 == "" {
			t.Fatalf("%s missing da65 instruction\n%s", e.ID, data)
		}
		forms, err := c.AssembleWithFeatures(row.DA65, 0x1000, c.FeatureSets[profile])
		found := false
		for _, b := range forms {
			found = found || bytes.Equal(b, expected)
		}
		if err != nil || !found {
			t.Fatalf("%s da65 text %q: %v", e.ID, row.DA65, err)
		}
		vectors = append(vectors, row)
	}
	if exact != 282 || alternative != 35 || unsupported != 0 || reserved != 44 {
		t.Fatal("unexpected assembler coverage", exact, alternative, unsupported, reserved)
	}
	raw, _ := json.MarshalIndent(vectors, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "cc65-vectors.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	t.Logf("ca65 exact %d, redundant alternatives %d, unsupported mnemonics %d; WDC reserved NOP %d; da65 verified all %d non-reserved forms", exact, alternative, unsupported, reserved, len(vectors)-reserved)
}

func TestGhidraOracle(t *testing.T) {
	if os.Getenv("MKASM_MOS6502_GHIDRA") == "" {
		t.Skip("set MKASM_MOS6502_GHIDRA=1 for Ghidra12.1.2")
	}
	c := load(t)
	script, err := filepath.Abs("../../scripts/ghidra-codec-oracle.py")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if p := os.Getenv("MKASM_MOS6502_ARTIFACT_DIR"); p != "" {
		dir = filepath.Join(p, "ghidra")
	}
	cmd := exec.Command("python3", script, "--output", dir)
	var input, output, diagnostics bytes.Buffer
	enc := json.NewEncoder(&input)
	expected := map[string][]byte{}
	order := []string{}
	for _, e := range c.Encodings {
		status := "documented"
		for _, f := range e.Features {
			if f == "undocumented" || f == "reserved-nop" {
				status = f
			}
		}
		if status != "documented" {
			continue
		}
		profile := profileFor(c, &e)
		lang := "6502:LE:16:default"
		if profile != "6502" {
			lang = "65C02:LE:16:default"
		}
		v := sample(&e)
		b, err := c.Encode(e.ID, v)
		if err != nil {
			t.Fatal(err)
		}
		asm := (&codec.Decoded{Encoding: &e, Values: v}).Format(0x1000)
		// Ghidra spells bit indices as a separate immediate operand.
		if strings.HasPrefix(e.Mnemonic, "bbr") || strings.HasPrefix(e.Mnemonic, "bbs") || strings.HasPrefix(e.Mnemonic, "rmb") || strings.HasPrefix(e.Mnemonic, "smb") {
			n := e.Mnemonic[len(e.Mnemonic)-1:]
			asm = e.Mnemonic[:3] + " #" + n + "," + strings.TrimPrefix(asm, e.Mnemonic)
		}
		if e.Mnemonic == "brk" {
			asm = "brk"
		}
		asm = strings.ReplaceAll(strings.ToUpper(asm), "0X", "0x")
		expected[e.ID] = b
		order = append(order, e.ID)
		enc.Encode(map[string]any{"id": e.ID, "language": lang, "address": "0x1000", "bytes": hex.EncodeToString(b), "assembly": asm})
	}
	cmd.Stdin = &input
	cmd.Stdout = &output
	cmd.Stderr = &diagnostics
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v %s", err, diagnostics.String())
	}
	exact, decodeOnly, mismatch, unsupported := 0, 0, 0, 0
	results := []map[string]any{}
	dec := json.NewDecoder(&output)
	for _, id := range order {
		var row map[string]any
		if err := dec.Decode(&row); err != nil {
			t.Fatal(err)
		}
		if row["id"] != id {
			t.Fatal("response order")
		}
		results = append(results, row)
		if row["error"] != nil {
			unsupported++
			t.Log(id, row)
			continue
		}
		if int(row["length"].(float64)) != len(expected[id]) {
			mismatch++
			t.Log(id, row)
			continue
		}
		if row["encoded"] == hex.EncodeToString(expected[id]) {
			exact++
		} else {
			decodeOnly++
			t.Log(id, row)
		}
	}
	raw, _ := json.MarshalIndent(results, "", "  ")
	if p := os.Getenv("MKASM_MOS6502_ARTIFACT_DIR"); p != "" {
		os.WriteFile(filepath.Join(p, "ghidra-results.json"), raw, 0644)
		os.WriteFile(filepath.Join(p, "ghidra-diagnostics.log"), diagnostics.Bytes(), 0644)
	}
	if exact != 209 || decodeOnly != 0 || mismatch != 1 || unsupported != 2 {
		t.Fatal("Ghidra coverage too low", exact, decodeOnly, mismatch, unsupported)
	}
	t.Logf("Ghidra: %d exact assembly+decode, %d decode-only, %d framing difference, %d unsupported", exact, decodeOnly, mismatch, unsupported)
}
