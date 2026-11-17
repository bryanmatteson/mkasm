package msp430

import (
	"encoding/hex"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestIndependentLLVMBytes(t *testing.T) {
	tool := os.Getenv("LLVM_MC")
	if tool == "" {
		tool, _ = exec.LookPath("llvm-mc")
	}
	if tool == "" {
		candidate := "/opt/homebrew/opt/llvm/bin/llvm-mc"
		if _, err := os.Stat(candidate); err == nil {
			tool = candidate
		}
	}
	if tool == "" {
		t.Skip("set LLVM_MC to LLVM assembler")
	}
	c := load(t, "msp430")
	tests := []string{"mov #0,r4", "mov #1,r4", "mov #2,r4", "mov #4,r4", "mov #8,r4", "mov #-1,r4", "push #4", "push #8", "mov #65535,r4", "mov @r5+,r4", "mov &0xabcd,r4", "mov -2(r5),r4", "add.b 20(r4),30(r5)", "call #0x1234", "sxt r5", "ret", "reti"}
	cmd := exec.Command(tool, "-triple=msp430", "-show-encoding")
	cmd.Stdin = strings.NewReader(strings.Join(tests, "\n") + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("LLVM: %v\n%s", err, out)
	}
	enc := regexp.MustCompile(`encoding: \[([^\]]*)\]`).FindAllStringSubmatch(string(out), -1)
	if len(enc) != len(tests) {
		t.Fatalf("LLVM produced%d encodings, want%d: %s", len(enc), len(tests), out)
	}
	for i, m := range enc {
		var raw []byte
		for _, part := range strings.Split(m[1], ",") {
			v, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(part), "0x"))
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, v...)
		}
		requireAssembly(t, c, tests[i], 0, hex.EncodeToString(raw))
	}
}
