// Package testreference supplies live native LLVM MC vectors to owning tests.
// Inputs are positive tests from an explicit LLVM source checkout. Expected
// bytes always come from executing LLVM, never FileCheck comments or mkasm.
package testreference

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// StandaloneRust keeps a retained consumer out of an unrelated ancestor's
// artifact workspace. Runtime source and production generated metadata remain
// unchanged; only the test consumer's Cargo workspace boundary is added.
func StandaloneRust(output string) error {
	p := filepath.Join(output, "Cargo.toml")
	body, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	if strings.Contains(string(body), "[workspace]") {
		return nil
	}
	return os.WriteFile(p, append(body, []byte("\n[workspace]\n")...), 0644)
}

type Vector struct {
	Text  string
	Bytes []byte
}

var encoding = regexp.MustCompile(`^(.*?)\s*(?:@|#|//)\s*encoding: \[([^]]+)\]`)

func AssembleFile(llvm, path string, args ...string) ([]Vector, int, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	args = append(append([]string{}, args...), "-show-encoding")
	cmd := exec.Command(llvm, args...)
	cmd.Stdin = bytes.NewReader(body)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, 0, fmt.Errorf("native LLVM %s: %w\n%s", path, err, stderr.String())
	}
	var result []Vector
	fixups := 0
	for _, line := range strings.Split(string(out), "\n") {
		m := encoding.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		var raw []byte
		complete := true
		for _, token := range strings.Split(m[2], ",") {
			token = strings.TrimSpace(token)
			if len(token) != 4 || !strings.HasPrefix(token, "0x") {
				complete = false
				break
			}
			b, err := hex.DecodeString(token[2:])
			if err != nil {
				complete = false
				break
			}
			raw = append(raw, b[0])
		}
		if !complete {
			fixups++
			continue
		}
		result = append(result, Vector{Text: strings.TrimSpace(m[1]), Bytes: raw})
	}
	if len(result) == 0 {
		return nil, fixups, fmt.Errorf("%s: LLVM emitted no concrete instruction vectors", path)
	}
	return result, fixups, nil
}
