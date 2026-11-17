package amdgpu

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// These samples retain mkasm's exact spelling/bytes. LLVMText is independently
// printed from the native MCInst; LLVMHex is that MCInst's native re-emission.
// A differing LLVMHex is normalization, never an exact native byte match.
type alternateNativeSample struct {
	ID, Text, Hex, CPU            string
	Values                        map[string]int64
	Mnemonic                      string
	Status                        int
	Length                        int
	LLVMOpcode, LLVMText, LLVMHex string
}

func buildAlternateNativeOracle(t *testing.T, output string) string {
	t.Helper()
	if existing := os.Getenv("MKASM_AMDGPU_NATIVE_ORACLE"); existing != "" {
		if _, err := os.Stat(existing); err != nil {
			t.Fatal(err)
		}
		return existing
	}
	config := os.Getenv("MKASM_AMDGPU_LLVM_CONFIG")
	if config == "" {
		config = "/opt/homebrew/opt/llvm/bin/llvm-config"
	}
	flags, err := exec.Command(config, "--cxxflags", "--ldflags", "--system-libs", "--libs").CombinedOutput()
	if err != nil {
		t.Fatalf("LLVM native oracle requires llvm-config: %v\n%s", err, flags)
	}
	executable := filepath.Join(output, "llvm-native-alternates")
	args := append(strings.Fields(string(flags)), "-Wl,-rpath,"+filepath.Dir(config)+"/../lib", "testdata/native-alternates.cpp", "-o", executable)
	compiler := os.Getenv("CXX")
	if compiler == "" {
		compiler = "clang++"
	}
	if data, err := exec.Command(compiler, args...).CombinedOutput(); err != nil {
		t.Fatalf("build LLVM native oracle: %v\n%s", err, data)
	}
	return executable
}

func llvmCPU(cpu string) (string, string) {
	target := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(cpu, "-wave32"), "-wave64"), "-true16")
	var attrs []string
	if strings.Contains(cpu, "-wave32") {
		attrs = append(attrs, "+wavefrontsize32", "-wavefrontsize64")
	}
	if strings.Contains(cpu, "-wave64") {
		attrs = append(attrs, "-wavefrontsize32", "+wavefrontsize64")
	}
	if strings.Contains(cpu, "-true16") {
		attrs = append(attrs, "+real-true16")
	}
	return target, strings.Join(attrs, ",")
}

func runAlternateNativeOracle(t *testing.T, executable, output, cpu string, samples []alternateNativeSample) []alternateNativeSample {
	t.Helper()
	var input strings.Builder
	for i, s := range samples {
		fmt.Fprintf(&input, "%d %s\n", i, s.Hex)
	}
	target, attrs := llvmCPU(cpu)
	command := exec.Command(executable, target, attrs)
	command.Stdin = strings.NewReader(input.String())
	var stderr bytes.Buffer
	command.Stderr = &stderr
	data, err := command.Output()
	_ = os.WriteFile(filepath.Join(output, cpu+".alternate.in"), []byte(input.String()), 0644)
	_ = os.WriteFile(filepath.Join(output, cpu+".alternate.out"), data, 0644)
	_ = os.WriteFile(filepath.Join(output, cpu+".alternate.err"), stderr.Bytes(), 0644)
	if err != nil {
		t.Fatalf("LLVM native %s: %v\n%s", cpu, err, stderr.String())
	}
	seen := map[int]bool{}
	scan := bufio.NewScanner(bytes.NewReader(data))
	for scan.Scan() {
		fields := strings.SplitN(scan.Text(), "\t", 6)
		if len(fields) != 6 {
			t.Fatalf("invalid native oracle response %q", scan.Text())
		}
		i, e := strconv.Atoi(fields[0])
		if e != nil || i < 0 || i >= len(samples) || seen[i] {
			t.Fatalf("invalid native sample index %q", fields[0])
		}
		seen[i] = true
		s := &samples[i]
		s.Status, e = strconv.Atoi(fields[1])
		if e != nil {
			t.Fatal(e)
		}
		s.Length, e = strconv.Atoi(fields[2])
		if e != nil {
			t.Fatal(e)
		}
		s.LLVMOpcode, s.LLVMHex, s.LLVMText = fields[3], fields[4], strings.TrimSpace(fields[5])
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(samples) {
		t.Fatalf("native oracle returned %d of %d cases", len(seen), len(samples))
	}
	return samples
}

// Test the independent native path with both a canonical spelling and physical
// bits which LLVM deliberately drops. Neither the private spelling nor those
// bits are silently rewritten in the retained source sample.
func TestAlternateNativeOracle(t *testing.T) {
	if _, err := os.Stat("/opt/homebrew/opt/llvm/bin/llvm-config"); err != nil {
		t.Skip(err)
	}
	c := sourceCatalog(t)
	output := t.TempDir()
	oracle := buildAlternateNativeOracle(t, output)
	id := "S_LOAD_DWORD_SGPR_alt_gfx9"
	var form *codec.Encoding
	for i := range c.Encodings {
		if c.Encodings[i].ID == id {
			form = &c.Encodings[i]
			break
		}
	}
	if form == nil {
		t.Fatal("missing alternate source form")
	}
	var samples []alternateNativeSample
	for _, offset := range []int64{0, 256, 511} {
		values := representative(form)
		values["Offset"] = offset
		code, err := codec.Encode(form, values)
		if err != nil {
			t.Fatal(err)
		}
		d := &codec.Decoded{Encoding: form, Values: values, Length: len(code)}
		text := d.Format(0)
		parsed, ok := codec.ParseOperands(form, text, 0)
		if !ok || parsed["Offset"] != offset {
			t.Fatalf("hidden operand lost in %q", text)
		}
		raw, err := codec.Encode(form, parsed)
		if err != nil || !bytes.Equal(raw, code) {
			t.Fatalf("exact syntax lost bytes: %x -> %x %v", code, raw, err)
		}
		samples = append(samples, alternateNativeSample{ID: id, Text: text, Hex: hex.EncodeToString(code), CPU: "gfx900", Values: values, Mnemonic: form.Mnemonic})
	}
	results := runAlternateNativeOracle(t, oracle, output, "gfx900", samples)
	for i, s := range results {
		if s.Status != 3 || s.Length != 8 || s.LLVMText == "" {
			t.Fatalf("native decode failed: %+v", s)
		}
		if strings.Contains(s.LLVMText, "enc[") || strings.Contains(s.LLVMText, "Offset:") {
			t.Fatalf("private syntax leaked to LLVM: %+v", s)
		}
		if i == 0 && s.LLVMHex != s.Hex {
			t.Fatalf("canonical sample unexpectedly changed: %+v", s)
		}
		if i != 0 && s.LLVMHex == s.Hex {
			t.Fatalf("expected LLVM normalization of hidden offset: %+v", s)
		}
	}
}
