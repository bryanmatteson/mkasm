package tricore

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

var lexicalNumber = regexp.MustCompile(`(?i)-?(?:0x[0-9a-f]+|[0-9]+)`)

func norm(s string) string {
	s = lexicalNumber.ReplaceAllStringFunc(s, func(v string) string {
		n, err := strconv.ParseInt(v, 0, 64)
		if err != nil {
			return v
		}
		if n >= 1<<31 && n < 1<<32 {
			n = int64(int32(n))
		}
		return strconv.FormatInt(n, 10)
	})
	return strings.ToLower(strings.Join(strings.Fields(s), ""))
}

func TestIndependentGhidra(t *testing.T) {
	if os.Getenv("MKASM_TRICORE_GHIDRA") == "" {
		t.Skip("set MKASM_TRICORE_GHIDRA=1 to run independent Ghidra oracle")
	}
	artifact := os.Getenv("MKASM_TRICORE_ARTIFACT")
	if artifact == "" {
		artifact = t.TempDir()
	}
	if err := os.MkdirAll(artifact, 0755); err != nil {
		t.Fatal(err)
	}
	definitions := prepareOracleLanguages(t, artifact)
	type testCase struct {
		e     codec.Encoding
		text  string
		bytes []byte
		pcp   bool
	}
	var cases []testCase
	catalogs := map[bool]*Catalog{}
	wantResponses := 0
	var input bytes.Buffer
	for _, arch := range []string{"tricore", "tricore-pcp"} {
		c, err := Parse(nil, arch)
		catalogs[arch == "tricore-pcp"] = c
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range c.Encodings {
			for _, v := range corpusSamples(&e) {
				b, err := codec.Encode(&e, v)
				if err != nil {
					t.Fatal(err)
				}
				d := codec.Decoded{Encoding: &e, Values: v, Length: len(b)}
				text := d.Format(0x1000)
				id := len(cases)
				cases = append(cases, testCase{e, text, b, arch == "tricore-pcp"})
				req := map[string]any{"id": strconv.Itoa(id) + "d", "language": "tricore:LE:32:mkasm-v2", "language_definitions": definitions, "address": "0x1000", "bytes": hex.EncodeToString(b)}
				if arch == "tricore" {
					req["language"] = "tricore:LE:32:mkasm-" + strings.TrimPrefix(e.Features[0], "tricore-")
				}
				if arch == "tricore-pcp" {
					req["context"] = map[string]string{"PCPMode": "1"}
				}
				raw, _ := json.Marshal(req)
				input.Write(raw)
				input.WriteByte('\n')
				wantResponses++
				{
					req = map[string]any{"id": strconv.Itoa(id) + "a", "language": "tricore:LE:32:mkasm-v2", "language_definitions": definitions, "address": "0x1000", "assembly": text}
					if arch == "tricore" {
						req["language"] = "tricore:LE:32:mkasm-" + strings.TrimPrefix(e.Features[0], "tricore-")
					}
					if arch == "tricore-pcp" {
						req["context"] = map[string]string{"PCPMode": "1"}
					}
					raw, _ = json.Marshal(req)
					input.Write(raw)
					input.WriteByte('\n')
					wantResponses++
				}
			}
		}
	}
	if err := os.WriteFile(filepath.Join(artifact, "requests.jsonl"), input.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	args := []string{"../../scripts/ghidra-codec-oracle.py", "--output", filepath.Join(artifact, "helper")}
	if home := os.Getenv("MKASM_GHIDRA_HOME"); home != "" {
		args = append(args, "--ghidra", home)
	}
	cmd := exec.Command("python3", args...)
	cmd.Stdin = &input
	var out, log bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &log
	if err := cmd.Run(); err != nil {
		t.Fatalf("Ghidra: %v\n%s", err, log.Bytes())
	}
	if err := os.WriteFile(filepath.Join(artifact, "responses.jsonl"), out.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(&out)
	count := 0
	for scanner.Scan() {
		var res struct {
			ID       string `json:"id"`
			Encoded  string `json:"encoded"`
			Error    string `json:"error"`
			Length   int    `json:"length"`
			Text     string `json:"text"`
			Mnemonic string `json:"mnemonic"`
			Flow     string `json:"flow"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		id, err := strconv.Atoi(res.ID[:len(res.ID)-1])
		if err != nil {
			t.Fatal(err)
		}
		c := cases[id]
		count++
		if res.Error != "" {
			t.Errorf("%s %s %q (%x): %s", res.ID, c.e.ID, c.text, c.bytes, res.Error)
			continue
		}
		if strings.HasSuffix(res.ID, "d") {
			wantFlow := map[string]string{"FALL_THROUGH": "next", "TERMINATOR": "return", "UNCONDITIONAL_CALL": "call", "COMPUTED_CALL": "call", "UNCONDITIONAL_JUMP": "branch", "COMPUTED_JUMP": "branch", "CONDITIONAL_JUMP": "conditional_branch", "CONDITIONAL_COMPUTED_JUMP": "conditional_branch"}[res.Flow]
			if c.e.FlowControl != wantFlow {
				t.Errorf("%s %s %q: flow ours%s Ghidra%s", res.ID, c.e.ID, c.text, c.e.FlowControl, res.Flow)
			}
			if res.Length != len(c.bytes) || norm(res.Text) != norm(c.text) {
				t.Errorf("%s %s bytes%x: ours%q length%d Ghidra%q length%d", res.ID, c.e.ID, c.bytes, c.text, len(c.bytes), res.Text, res.Length)
			}
		} else {
			b, err := hex.DecodeString(res.Encoded)
			if err != nil {
				t.Fatal(err)
			}
			// Assemblers may choose an equivalent shorter encoding. Verify the chosen
			// independent bytes are among the catalog's supported assembly results.
			catalog := catalogs[c.pcp]
			all, err := catalog.AssembleWithFeatures(c.text, 0x1000, c.e.Features)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, candidate := range all {
				found = found || bytes.Equal(candidate, b)
			}
			if !found {
				t.Errorf("%s %s %q: Ghidra%x absent from%x", res.ID, c.e.ID, c.text, b, all)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("source samples%d oracle responses%d", len(cases), count)
	if count != wantResponses {
		t.Fatal(fmt.Sprintf("incomplete oracle responses %d", count))
	}
}
