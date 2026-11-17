package pic

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// Run the real SLEIGH decoder and assembler. Retained vectors identify pinned
// tool limitations explicitly; they are never counted as exact byte matches.
func TestIndependentGhidraAllProfiles(t *testing.T) {
	home := os.Getenv("MKASM_GHIDRA_HOME")
	if home == "" {
		t.Skip("set MKASM_GHIDRA_HOME to an installed Ghidra distribution")
	}
	f, err := os.Open("testdata/ghidra-vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	var rows []struct {
		reference
		Language, Address, Text, Mnemonic string
		Context                           map[string]string
	}
	if err := json.NewDecoder(z).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 23607 {
		t.Fatalf("reference corpus changed: %d", len(rows))
	}
	byID := map[string]int{}
	covered := map[string]bool{}
	var gnuFallbacks []struct{ id, text, bytes string }
	var input bytes.Buffer
	encoder := json.NewEncoder(&input)
	for n, row := range rows {
		byID[row.ID] = n
		raw := row.Bytes
		if row.SourceBytes != "" {
			raw = row.SourceBytes
		}
		request := map[string]any{"id": row.ID, "language": row.Language, "address": row.Address, "bytes": raw}
		if len(row.Context) > 0 {
			request["context"] = row.Context
		}
		if err := encoder.Encode(request); err != nil {
			t.Fatal(err)
		}
		delete(request, "bytes")
		request["id"] = row.ID + "/assemble"
		request["assembly"] = row.Text
		if row.Error == "" && row.SourceBytes == "" && row.Encoded != row.Bytes {
			request["all_encodings"] = true
		}
		if row.Error != "" || row.SourceBytes != "" {
			gnuFallbacks = append(gnuFallbacks, struct{ id, text, bytes string }{row.ID, row.Text, row.Bytes})
		}
		if err := encoder.Encode(request); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("python3", "../../scripts/ghidra-codec-oracle.py", "--ghidra", home, "--output", t.TempDir())
	command.Stdin = &input
	var stderr bytes.Buffer
	command.Stderr = &stderr
	out, err := command.Output()
	if err != nil {
		t.Fatalf("Ghidra: %v\n%s", err, stderr.String())
	}
	decoder := json.NewDecoder(bytes.NewReader(out))
	exact, alternatives := 0, 0
	for _, row := range rows {
		var decoded struct {
			ID, Error, Mnemonic string
			Length              int
		}
		if err := decoder.Decode(&decoded); err != nil {
			t.Fatal(row.ID, err)
		}
		if decoded.ID != row.ID || decoded.Error != "" || decoded.Length != row.Length || decoded.Mnemonic != row.Mnemonic {
			t.Fatalf("Ghidra decoder %s: %+v", row.ID, decoded)
		}
		var assembled struct {
			ID, Error, Encoded string
			Patterns           []nativeEncodingPattern `json:"encoding_patterns"`
		}
		if err := decoder.Decode(&assembled); err != nil {
			t.Fatal(row.ID, err)
		}
		if row.Error != "" {
			if assembled.ID != row.ID+"/assemble" || assembled.Error == "" || assembled.Encoded != "" {
				t.Fatalf("pinned Ghidra solver limitation changed for %s: %+v", row.ID, assembled)
			}
			continue
		}
		if assembled.ID != row.ID+"/assemble" || assembled.Error != "" || assembled.Encoded != row.Encoded {
			t.Fatalf("Ghidra assembler %s: %+v, retained=%s", row.ID, assembled, row.Encoded)
		}
		if assembled.Encoded == row.Bytes {
			exact++
		}
		if row.SourceBytes == "" {
			if assembled.Encoded == row.Bytes {
				covered[row.ID] = true
			} else {
				data, _ := hex.DecodeString(row.Bytes)
				for _, pattern := range assembled.Patterns {
					if pattern.accepts(t, data) {
						covered[row.ID] = true
						break
					}
				}
				if !covered[row.ID] {
					t.Fatalf("%s: no native solver candidate accepts %s", row.ID, row.Bytes)
				}
				alternatives++
			}
		}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatal("extra Ghidra responses", err)
	}
	if exact != 23179 {
		t.Fatalf("Ghidra exact byte comparison count changed: %d", exact)
	}
	verifyPICGNUFallbacks(t, gnuFallbacks)
	for _, row := range gnuFallbacks {
		covered[row.id] = true
	}
	if len(covered) != len(rows) {
		t.Fatalf("native coverage: %d/%d forms", len(covered), len(rows))
	}
	// Check the public architecture selectors too, including every device profile
	// and the historical pic16 alias, against the same independently emitted bytes.
	for _, arch := range []string{"pic12", "pic16c5x", "pic14", "pic14-enhanced", "pic16", "pic17", "pic18", "pic24", "pic24e", "pic24f", "pic24h", "dspic", "dspic30f", "dspic33f", "dspic33e", "dspic33c"} {
		t.Run(arch, func(t *testing.T) {
			c, err := Parse(nil, arch)
			if err != nil {
				t.Fatal(err)
			}
			matches, variants, fallbacks := 0, 0, 0
			for _, encoding := range c.Encodings {
				n, ok := byID[encoding.ID]
				if !ok {
					t.Fatal("missing independent case: ", encoding.ID)
				}
				row := rows[n]
				actual, err := codec.Encode(&encoding, sample(&encoding))
				if err != nil || hex.EncodeToString(actual) != row.Bytes {
					t.Fatalf("%s: mkasm=%x reference=%s err=%v", encoding.ID, actual, row.Bytes, err)
				}
				switch {
				case row.Error != "" || row.SourceBytes != "":
					fallbacks++
				case row.Encoded == row.Bytes:
					matches++
				default:
					variants++
				}
				if !covered[row.ID] {
					t.Fatal("uncovered public form: ", row.ID)
				}
			}
			t.Logf("live native references: %d default exact encodings, %d solver candidates, %d GNU fallbacks; %d forms", matches, variants, fallbacks, len(c.Encodings))
		})
	}
	t.Logf("native coverage: all 23607 union forms checked; %d Ghidra default exact selections, %d native solver alternatives, %d GNU fallbacks; zero uncovered forms", exact, alternatives, len(gnuFallbacks))
}

type nativeEncodingPattern struct {
	Value, Mask   string
	Length        int
	DefinedLength int `json:"defined_length"`
	Forbidden     []nativeEncodingPattern
}

func (p nativeEncodingPattern) matches(t *testing.T, data []byte) bool {
	t.Helper()
	value, err := hex.DecodeString(p.Value)
	if err != nil {
		t.Fatal(err)
	}
	mask, err := hex.DecodeString(p.Mask)
	if err != nil || len(value) != len(mask) {
		t.Fatal("invalid native pattern", p, err)
	}
	for n, m := range mask {
		if m != 0 && (n >= len(data) || data[n]&m != value[n]&m) {
			return false
		}
	}
	return true
}

func (p nativeEncodingPattern) accepts(t *testing.T, data []byte) bool {
	if p.Length != len(data) || !p.matches(t, data) {
		return false
	}
	for _, forbidden := range p.Forbidden {
		if forbidden.DefinedLength <= len(data) && forbidden.matches(t, data) {
			return false
		}
	}
	return true
}

func verifyPICGNUFallbacks(t *testing.T, rows []struct{ id, text, bytes string }) {
	t.Helper()
	assembler := os.Getenv("MKASM_GPASM")
	if assembler == "" {
		t.Fatal("set MKASM_GPASM for the independent PIC18 fallback assembler")
	}
	dir := t.TempDir()
	var source strings.Builder
	source.WriteString(" org 0\n")
	for _, row := range rows {
		text := strings.ReplaceAll(row.text, "#", "")
		for n := 0; n < 3; n++ {
			text = strings.ReplaceAll(text, fmt.Sprintf("FSR%d", n), fmt.Sprint(n))
		}
		fmt.Fprintln(&source, " "+text)
	}
	source.WriteString(" end\n")
	input, output := filepath.Join(dir, "fallbacks.asm"), filepath.Join(dir, "fallbacks.hex")
	if err := os.WriteFile(input, []byte(source.String()), 0644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(assembler, "-y", "-p18f4520", "-o", output, input).CombinedOutput(); err != nil {
		t.Fatalf("native gpasm: %v\n%s", err, out)
	}
	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	memory := map[int]byte{}
	base := 0
	for _, line := range strings.Fields(string(body)) {
		if !strings.HasPrefix(line, ":") {
			t.Fatal("invalid Intel HEX record")
		}
		record, err := hex.DecodeString(line[1:])
		if err != nil || len(record) < 5 || len(record) != int(record[0])+5 {
			t.Fatal("invalid Intel HEX record", line)
		}
		var sum byte
		for _, v := range record {
			sum += v
		}
		if sum != 0 {
			t.Fatal("invalid Intel HEX checksum")
		}
		address := int(record[1])<<8 | int(record[2])
		data := record[4 : len(record)-1]
		switch record[3] {
		case 0:
			for n, v := range data {
				memory[base+address+n] = v
			}
		case 1:
		case 4:
			if len(data) != 2 {
				t.Fatal("invalid extended address")
			}
			base = (int(data[0])<<8 | int(data[1])) << 16
		default:
			t.Fatal("unexpected Intel HEX record type", record[3])
		}
	}
	at := 0
	for _, row := range rows {
		want, err := hex.DecodeString(row.bytes)
		if err != nil {
			t.Fatal(err)
		}
		for n, v := range want {
			if actual, ok := memory[at+n]; !ok || actual != v {
				t.Fatalf("native gpasm %s %q at %d: %02x != %02x", row.id, row.text, n, actual, v)
			}
		}
		at += len(want)
	}
	if len(memory) != at {
		t.Fatalf("unexpected native output length %d != %d", len(memory), at)
	}
}
