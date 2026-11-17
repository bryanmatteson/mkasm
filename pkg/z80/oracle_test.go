package z80

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var lexicalNumber = regexp.MustCompile(`(?i)\b(?:0x[0-9a-f]+|[0-9]+)\b`)

func norm(s string) string {
	s = strings.ToLower(s)
	if strings.HasPrefix(s, "tstio (") {
		s = strings.ReplaceAll(strings.ReplaceAll(s, "(", ""), ")", "")
	}
	s = strings.NewReplacer("af_", "af'", "flag", "f", "+-", "-").Replace(s)
	s = lexicalNumber.ReplaceAllStringFunc(s, func(v string) string {
		n, e := strconv.ParseInt(v, 0, 64)
		if e != nil {
			return v
		}
		return strconv.FormatInt(n, 10)
	})
	return strings.Join(strings.Fields(s), "")
}

type oracleCase struct {
	architecture, id, text string
	bytes                  []byte
	catalog                *Catalog
}

func oracleCases(t *testing.T) []oracleCase {
	t.Helper()
	var out []oracleCase
	for _, arch := range []string{"z80", "z180"} {
		c, err := Parse(nil, arch)
		if err != nil {
			t.Fatal(err)
		}
		for i := range c.Encodings {
			e := &c.Encodings[i]
			b, err := codec.Encode(e, sample(e))
			if err != nil {
				t.Fatal(err)
			}
			d, err := c.Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, oracleCase{arch, e.ID, d.CanonicalFormat(0x1000), b, c})
		}
		if arch == "z80" {
			for i, b := range [][]byte{{0xdd, 0}, {0xfd, 0x76}, {0xdd, 0xfd, 0x21, 0x34, 0x12}, {0xfd, 0xed, 0x44}, {0xdd, 0xfd, 0xdd, 0xcb, 0x80, 0x40}, {0xdd, 0x18, 0xfd}, {0xdd, 0xdd, 0xeb}} {
				d, err := c.Decode(b)
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, oracleCase{arch, fmt.Sprintf("prefix%d", i), d.CanonicalFormat(0x1000), b, c})
			}
		}
	}
	return out
}

func TestIndependentGhidra(t *testing.T) {
	if os.Getenv("MKASM_Z80_GHIDRA") == "" {
		t.Skip("set MKASM_Z80_GHIDRA=1")
	}
	artifact := os.Getenv("MKASM_Z80_ARTIFACT")
	if artifact == "" {
		artifact = t.TempDir()
	}
	if err := os.MkdirAll(artifact, 0755); err != nil {
		t.Fatal(err)
	}
	cases := oracleCases(t)
	var input bytes.Buffer
	for i, c := range cases {
		for _, mode := range []string{"d", "a"} {
			req := map[string]any{"id": fmt.Sprint(i) + mode, "language": c.architecture + ":LE:16:default", "address": "0x1000"}
			if mode == "d" {
				req["bytes"] = hex.EncodeToString(c.bytes)
			} else {
				text := strings.ReplaceAll(strings.ToUpper(c.text), "0X", "0x")
				text = strings.ReplaceAll(text, "AF'", "AF_")
				text = strings.ReplaceAll(text, "IN0 F,", "IN0 Flag,")
				if c.id == "ed74" && c.architecture == "z180" {
					text = "TSTIO (1)"
				}
				req["assembly"] = text
			}
			b, _ := json.Marshal(req)
			input.Write(b)
			input.WriteByte('\n')
		}
	}
	os.WriteFile(filepath.Join(artifact, "ghidra-requests.jsonl"), input.Bytes(), 0644)
	cmd := exec.Command("python3", "../../scripts/ghidra-codec-oracle.py", "--output", filepath.Join(artifact, "ghidra-helper"))
	cmd.Stdin = &input
	var output, log bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &log
	if err := cmd.Run(); err != nil {
		t.Fatalf("Ghidra: %v\n%s", err, log.Bytes())
	}
	os.WriteFile(filepath.Join(artifact, "ghidra-responses.jsonl"), output.Bytes(), 0644)
	type gap struct{ Architecture, ID, Mode, Bytes, Text, Actual, Reason string }
	var gaps []gap
	counts := map[string]int{}
	responses := 0
	scan := bufio.NewScanner(&output)
	for scan.Scan() {
		var r struct {
			ID, Encoded, Error, Text string
			Length                   int
		}
		if err := json.Unmarshal(scan.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		responses++
		i, err := strconv.Atoi(r.ID[:len(r.ID)-1])
		if err != nil || i >= len(cases) {
			t.Fatalf("bad response %q", r.ID)
		}
		c := cases[i]
		mode := r.ID[len(r.ID)-1:]
		bad := r.Error != ""
		actual := r.Error
		if mode == "d" && r.Error == "" {
			bad = r.Length != len(c.bytes) || norm(c.text) != norm(r.Text)
			actual = fmt.Sprintf("%s (length %d)", r.Text, r.Length)
		}
		if mode == "a" && r.Error == "" {
			b, err := hex.DecodeString(r.Encoded)
			if err != nil {
				t.Fatal(err)
			}
			all, err := c.catalog.Assemble(c.text, 0x1000)
			bad = err != nil
			found := false
			for _, v := range all {
				found = found || bytes.Equal(v, b)
			}
			bad = bad || !found
			actual = r.Encoded
		}
		if !bad {
			counts[c.architecture+mode]++
			continue
		}
		reason := ghidraGap(c, mode)
		gaps = append(gaps, gap{c.architecture, c.id, mode, hex.EncodeToString(c.bytes), c.text, actual, reason})
		if reason == "" {
			t.Errorf("%s %s %s %x ours%q actual%q", c.architecture, c.id, mode, c.bytes, c.text, actual)
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if responses != 2*len(cases) {
		t.Errorf("responses %d want%d", responses, 2*len(cases))
	}
	b, _ := json.MarshalIndent(gaps, "", "  ")
	os.WriteFile(filepath.Join(artifact, "ghidra-gaps.json"), b, 0644)
	t.Logf("verified %v; explicit upstream gaps %d", counts, len(gaps))
}

// Known limitations are narrowed to physical opcodes, never whole mnemonics.
func ghidraGap(c oracleCase, mode string) string {
	if mode == "d" && strings.HasPrefix(c.id, "prefix") {
		return "Ghidra lacks ignored/repeated DD/FD prefix framing"
	}
	if strings.HasPrefix(c.id, "ddcb") || strings.HasPrefix(c.id, "fdcb") {
		op := c.bytes[3]
		if op&7 != 6 {
			return "Ghidra omits indexed-CB register results and ignored BIT selector aliases"
		}
	}
	if c.architecture == "z80" && strings.HasPrefix(c.id, "ed") {
		op := c.bytes[1]
		if c.text == "nop" {
			return "Ghidra omits source-defined undefined-ED no-ops"
		}
		if op == 0x70 || op == 0x71 {
			return "Ghidra omits flag-only IN and zero OUT"
		}
		if op == 0x6e {
			return "Ghidra ED6E says IM1; primary execution source sets IM0"
		}
		if (op&0xc7 == 0x44 && op != 0x44) || (op&0xc7 == 0x45 && op != 0x45 && op != 0x4d) || (op == 0x66 || op == 0x76 || op == 0x7e) {
			return "Ghidra omits duplicate ED encodings"
		}
	}
	if c.id == "dd64" || c.id == "dd6d" || c.id == "fd64" || c.id == "fd6d" {
		return "Ghidra source leaves the source H/L unsubstituted in index-half self loads"
	}
	if c.architecture == "z180" && c.id == "ed7c" {
		return "Ghidra MLT pair table incorrectly names slot3 AF; Zilog/GNU specify SP"
	}
	if c.id == "fd29" {
		return "Ghidra FD29 source incorrectly substitutes IX as the source of ADD IY,IY"
	}
	if c.id == "ddcb36" || c.id == "fdcb36" {
		return "Ghidra omits indexed undocumented SLL"
	}
	return ""
}
