package powerpc

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func corpus(t *testing.T, architecture string) *codec.Catalog {
	t.Helper()
	path := os.Getenv("MKASM_POWERPC_TABLEGEN_JSON")
	compressed := path == ""
	if compressed {
		path = "testdata/llvm-22.1.8-powerpc.json.gz"
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var input io.Reader = f
	if compressed {
		z, err := gzip.NewReader(f)
		if err != nil {
			t.Fatal(err)
		}
		defer z.Close()
		input = z
	}
	c, err := Parse(input, architecture)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLLVMCorpus(t *testing.T) {
	for _, arch := range []string{"powerpc32", "powerpc64", "powerpc32le", "powerpc64le"} {
		t.Run(arch, func(t *testing.T) {
			c := corpus(t, arch)
			if len(c.Encodings) < 2100 {
				t.Fatalf("unexpected corpus size %d", len(c.Encodings))
			}
			cases := map[string]string{"addi 3, 4, -1": "3864ffff", "lwz 3, 16(4)": "80640010", "ld 3, -16(4)": "e864fff0", "b 16": "48000010", "mfspr 3, 8": "7c6802a6", "lxvp 34, -16(4)": "1864fff0", "paddi 3, 4, -1, 0": "0603ffff3864ffff", "pld 3, 16(4), 0": "04000000e4640010", "xxlor 34, 35, 36": "f0432497", "mfocrf 3, 128": "7c780026", "mr 3, 4": "7c832378", "li 3, -1": "3860ffff", "nop": "60000000", "beq 16": "41820010", "trap": "7fe00008"}
			for asm, want := range cases {
				b, _ := hex.DecodeString(want)
				if strings.HasSuffix(arch, "le") {
					for i := 0; i < len(b); i += 4 {
						b[i], b[i+3] = b[i+3], b[i]
						b[i+1], b[i+2] = b[i+2], b[i+1]
					}
				}
				got, err := c.Assemble(asm, 0)
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, v := range got {
					if bytes.Equal(v, b) {
						found = true
					}
				}
				if !found {
					t.Errorf("%s: got %x want %x", asm, got, b)
				}
				d, err := c.Decode(b)
				if err != nil {
					t.Fatal(err)
				}
				again, err := c.Assemble(d.Format(0), 0)
				if err != nil {
					t.Fatal(err)
				}
				found = false
				for _, v := range again {
					if bytes.Equal(v, b) {
						found = true
					}
				}
				if !found {
					t.Errorf("formatted %s does not round trip %x", d.Format(0), b)
				}
			}
			for _, text := range []string{"addis 3, 4, 65535", "addis 3, 4, -65536", "lis 3, 65535", "lis 3, -65536"} {
				if _, err := c.Assemble(text, 0); err != nil {
					t.Fatal(err)
				}
			}
			for _, text := range []string{"addis 3, 4, 65536", "addis 3, 4, -65537"} {
				if _, err := c.Assemble(text, 0); err == nil {
					t.Fatalf("accepted GNU immediate out of range: %s", text)
				}
			}
			for _, value := range []int64{-32768, 32767} {
				if _, err := c.Encode("ADDI", map[string]int64{"RST": 3, "RA": 4, "D": value}); err != nil {
					t.Fatal(err)
				}
			}
			for _, value := range []int64{-32769, 32768} {
				if _, err := c.Encode("ADDI", map[string]int64{"RST": 3, "RA": 4, "D": value}); err == nil {
					t.Fatalf("addi accepted out of range %d", value)
				}
			}
			if _, err := c.Assemble("lxvp 35, 16(4)", 0); err == nil {
				t.Fatal("unaligned register pair accepted")
			}
			branch, err := c.Assemble("b 0x110", 0x100)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := c.Decode(branch[0])
			if err != nil || decoded.Values["LI"] != 16 {
				t.Fatalf("branch PC-relative address transform: %+v %v", decoded, err)
			}
			prefix, err := c.Encode("PADDI", map[string]int64{"RT": 3, "RA": 4, "SI": -1})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := c.Decode(prefix[:7]); err != codec.ErrTruncated {
				t.Fatalf("prefixed truncation: %v", err)
			}
			if _, err := c.AssembleWithFeatures("paddi 3, 4, -1, 0", 0, []string{}); err == nil {
				t.Fatal("disabled prefix extension admitted")
			}
			if _, err := c.AssembleWithFeatures("paddi 3, 4, -1, 0", 0, []string{"PrefixInstrs"}); err != nil {
				t.Fatal(err)
			}
			t.Logf("imported %d forms, explicitly unsupported %d", len(c.Encodings), len(c.Unsupported))
		})
	}
}

// llvmInstructionText renders the encoded branch immediate in LLVM's assembly
// dialect. Catalog text uses resolved architectural target addresses instead;
// LLVM interprets relative operands as displacements and does not sign-extend
// wrapped 32-bit hex operands for conditional branches. Parentheses also keep
// the PPC lexer from interpreting a leading minus as a mnemonic branch hint.
func llvmInstructionText(e codec.Encoding, values map[string]int64) string {
	if mnemonic := map[string]string{
		"BCC": "bc", "CTRL_DEP": "bc", "BCCA": "bca", "BCCL": "bcl", "BCCLA": "bcla",
		"BCCCTR": "bcctr", "BCCCTR8": "bcctr", "BCCCTRL": "bcctrl", "BCCCTRL8": "bcctrl",
		"BCCLR": "bclr", "BCCLRL": "bclrl",
	}[e.ID]; mnemonic != "" {
		text := fmt.Sprintf("%s %d, %d", mnemonic, values["BIBO"]&31, values["CR"]*4+(values["BIBO"]>>5))
		if value, ok := values["BD"]; ok {
			text += fmt.Sprintf(", (%d)", value)
		}
		return text
	}
	e.Syntax = strings.TrimPrefix(e.Syntax, "enc["+e.ID+"] ")
	if e.ID == "TAILBA" || e.ID == "TAILBA8" {
		e.Syntax = "b {LI}"
	}
	e.Operands = append([]codec.Operand(nil), e.Operands...)
	for i := range e.Operands {
		o := &e.Operands[i]
		if !o.Relative && o.Kind != "address" {
			continue
		}
		o.Relative = false
		o.Kind = "immediate"
		e.Syntax = strings.ReplaceAll(e.Syntax, "{"+o.Name+"}", "({"+o.Name+"})")
	}
	return (&codec.Decoded{Encoding: &e, Values: values, Length: len(e.Value)}).Format(0)
}

func TestLLVMBranchImmediateDialect(t *testing.T) {
	mc := os.Getenv("LLVM_MC")
	if mc == "" {
		mc = "llvm-mc"
	}
	_, llvmErr := exec.LookPath(mc)
	for _, arch := range []string{"powerpc32", "powerpc64", "powerpc32le", "powerpc64le"} {
		t.Run(arch, func(t *testing.T) {
			c := corpus(t, arch)
			var source strings.Builder
			var expected [][]byte
			for _, tc := range []struct {
				id, negative, positive string
			}{
				{"BDNZp", "4320fffc", "43200008"},
				{"BDNZAp", "4320fffe", "4320000a"},
				{"BC", "4180fffc", "41800008"},
				{"BCL", "4180fffd", "41800009"},
				{"B", "4bfffffc", "48000008"},
				{"BA", "4bfffffe", "4800000a"},
			} {
				var e *codec.Encoding
				for i := range c.Encodings {
					if c.Encodings[i].ID == tc.id {
						e = &c.Encodings[i]
						break
					}
				}
				if e == nil {
					t.Fatalf("missing source form %s", tc.id)
				}
				for _, value := range []int64{-4, 8} {
					values := map[string]int64{}
					var target codec.Operand
					for _, o := range e.Operands {
						values[o.Name] = 0
						if o.Relative || o.Kind == "address" {
							target = o
							values[o.Name] = value
						}
					}
					if target.Name == "" || !target.Signed || target.Scale != 4 {
						t.Fatalf("%s lost signed scaled branch metadata: %+v", tc.id, target)
					}
					is32 := strings.HasPrefix(arch, "powerpc32")
					if is32 && (e.TargetMask != 0xffffffff || target.Relative && target.PCWrapBits != 32 || !target.Relative && target.InputSignedBits != 32) {
						t.Fatalf("%s lost 32-bit target semantics: %+v", tc.id, target)
					}
					wantHex := tc.negative
					if value > 0 {
						wantHex = tc.positive
					}
					want, _ := hex.DecodeString(wantHex)
					if strings.HasSuffix(arch, "le") {
						want[0], want[3], want[1], want[2] = want[3], want[0], want[2], want[1]
					}
					got, err := codec.Encode(e, values)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("%s value %d: encoded %x want %x: %v", tc.id, value, got, want, err)
					}
					d := &codec.Decoded{Encoding: e, Values: values, Length: len(got)}
					for _, address := range []uint64{0, 0x100, 0xfffffffc} {
						wantTarget := uint64(value)
						if target.Relative {
							wantTarget += address
						}
						if is32 {
							wantTarget &= 0xffffffff
						}
						if gotTarget, ok := d.BranchTarget(address); !ok || gotTarget != wantTarget {
							t.Fatalf("%s target at %#x: %#x/%v want %#x", tc.id, address, gotTarget, ok, wantTarget)
						}
						text := d.Format(address)
						if !strings.HasSuffix(text, fmt.Sprintf("0x%x", wantTarget)) {
							t.Fatalf("%s formatted target %q want %#x", tc.id, text, wantTarget)
						}
						assembled, err := c.Assemble(text, address)
						found := false
						for _, b := range assembled {
							found = found || bytes.Equal(b, want)
						}
						if err != nil || !found {
							t.Fatalf("%s canonical text %q at %#x: %x want %x: %v", tc.id, text, address, assembled, want, err)
						}
					}
					native := llvmInstructionText(*e, values)
					if !strings.HasSuffix(native, fmt.Sprintf("(%d)", value)) {
						t.Fatalf("%s native branch immediate %q", tc.id, native)
					}
					source.WriteString(native + "\n")
					expected = append(expected, want)
				}
			}
			if llvmErr != nil {
				t.Logf("independent LLVM branch checks unavailable: %v", llvmErr)
				return
			}
			triple := map[string]string{"powerpc32": "powerpc", "powerpc64": "powerpc64", "powerpc32le": "powerpcle", "powerpc64le": "powerpc64le"}[arch]
			cmd := exec.Command(mc, "-triple="+triple, "-show-encoding")
			cmd.Stdin = strings.NewReader(source.String())
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("LLVM rejected branch immediates: %v\n%s", err, output)
			}
			matches := regexp.MustCompile(`encoding: \[([^]]+)\]`).FindAllStringSubmatch(string(output), -1)
			if len(matches) != len(expected) {
				t.Fatalf("LLVM returned %d encodings want %d:\n%s", len(matches), len(expected), output)
			}
			for i, match := range matches {
				var got []byte
				for _, part := range strings.Split(match[1], ",") {
					n, err := strconv.ParseUint(strings.TrimSpace(part), 0, 8)
					if err != nil {
						t.Fatal(err)
					}
					got = append(got, byte(n))
				}
				if !bytes.Equal(got, expected[i]) {
					t.Fatalf("LLVM branch %d encoded %x want %x", i, got, expected[i])
				}
			}
		})
	}
}

// Each imported real record is exercised against LLVM, including records whose
// extension requires a different CPU selection. Retain the unsupported assembly
// diagnostics so a corpus expansion cannot silently masquerade as parity.
func TestLLVMWholeCorpusParity(t *testing.T) {
	for _, arch := range []string{"powerpc32", "powerpc64", "powerpc32le", "powerpc64le"} {
		t.Run(arch, func(t *testing.T) { wholeCorpusParity(t, arch) })
	}
}
func wholeCorpusParity(t *testing.T, architecture string) {
	c := corpus(t, architecture)
	mc := os.Getenv("LLVM_MC")
	if mc == "" {
		mc = "llvm-mc"
	}
	if _, err := exec.LookPath(mc); err != nil {
		t.Skip(err)
	}
	var source strings.Builder
	var historical strings.Builder
	var disassembly []string
	nativeOperands := map[string][]string{}
	expected := map[string][]byte{}
	ids := map[string]string{}
	count := 0
	for _, e := range c.Encodings {
		for variant := 0; variant < 2; variant++ {
			values := map[string]int64{}
			for i, o := range e.Operands {
				raw := int64((i + variant*3 + 1) % 4)
				if o.Width() < 3 {
					raw %= 1 << uint(o.Width())
					if o.Signed {
						raw %= 1 << uint(o.Width()-1)
					}
				}
				if len(o.Names) > 0 {
					raw = -1
					for offset := 0; offset < len(o.Names); offset++ {
						n := (offset + i + variant*3 + 1) % len(o.Names)
						if o.Names[n] != "" {
							raw = int64(n)
							break
						}
					}
				}
				var represented int64
				for _, slice := range o.Bits {
					for bit := 0; bit < slice.Width; bit++ {
						represented |= 1 << uint(slice.ValueBit+bit)
					}
				}
				raw &= represented
				if variant == 1 && strings.HasPrefix(e.Syntax, "enc[") && !o.Signed {
					// Exercise every predicate bit (BO and both halves of BI)
					// and boundary registers in the exact source spellings.
					raw = represented
				}
				if raw < 0 {
					t.Fatalf("empty register class %s %s", e.ID, o.Name)
				}
				scale := o.Scale
				if scale == 0 {
					scale = 1
				}
				if variant == 1 && o.Signed && !strings.HasSuffix(e.ID, "_bare_syntax") {
					raw = -raw - 1
				}
				values[o.Name] = raw*scale + o.Bias
			}
			b, err := codec.Encode(&e, values)
			if err != nil {
				t.Fatalf("unencodable sample %s: %v", e.ID, err)
			}
			label := fmt.Sprintf("ppctest_%d", count)
			count++
			d := &codec.Decoded{Encoding: &e, Values: values, Length: len(b)}
			text := d.Format(0)
			single := &codec.Catalog{Encodings: []codec.Encoding{e}}
			assembled, err := single.Assemble(text, 0)
			if err != nil {
				t.Fatalf("%s cannot assemble formatted sample %q: %v", e.ID, text, err)
			}
			found := false
			for _, a := range assembled {
				if bytes.Equal(a, b) {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s formatted sample changes bytes", e.ID)
			}
			if !e.AssemblyOnly {
				decoded, err := single.Decode(b)
				if err != nil {
					t.Fatalf("%s cannot decode encoded sample: %v", e.ID, err)
				}
				for key, want := range values {
					if decoded.Values[key] != want {
						t.Fatalf("%s operand %s decoded %d want %d", e.ID, key, decoded.Values[key], want)
					}
				}
			}
			switch {
			case e.ID == "EVFSCTUF" || e.ID == "EVFSCTUIZ" || e.ID == "EVSEL":
				disassembly = append(disassembly, label)
				for _, o := range e.Operands {
					prefix := "S"
					if o.Class == "crrc" {
						prefix = "CR"
					}
					nativeOperands[label] = append(nativeOperands[label], fmt.Sprintf("Reg:%s%d", prefix, values[o.Name]))
				}
			case e.ID == "MFTB" || strings.HasPrefix(e.Syntax, "enc[alias_") && strings.Contains(e.Syntax, " mftb"):
				historical.WriteString(label + ":\n" + llvmInstructionText(e, values) + "\n")
			default:
				source.WriteString(label + ":\n" + llvmInstructionText(e, values) + "\n")
			}
			expected[label] = b
			ids[label] = e.ID
		}
	}
	triple := map[string]string{"powerpc32": "powerpc", "powerpc64": "powerpc64", "powerpc32le": "powerpcle", "powerpc64le": "powerpc64le"}[architecture]
	var stdout, stderr bytes.Buffer
	for _, profile := range []struct{ cpu, source string }{{"future", source.String()}, {"601", historical.String()}} {
		if profile.source == "" {
			continue
		}
		cmd := exec.Command(mc, "-triple="+triple, "-mcpu="+profile.cpu, "-mattr=+spe,+htm", "-show-encoding")
		cmd.Stdin = strings.NewReader(profile.source)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		_ = cmd.Run()
	}
	labelRE := regexp.MustCompile(`^(ppctest_[0-9]+):`)
	encodingRE := regexp.MustCompile(`encoding: \[([^]]+)\]`)
	current := ""
	matched := 0
	failures := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(stdout.String(), "\n") {
		if m := labelRE.FindStringSubmatch(line); m != nil {
			current = m[1]
		}
		if m := encodingRE.FindStringSubmatch(line); m != nil && current != "" {
			var b []byte
			valid := true
			for _, p := range strings.Split(m[1], ",") {
				n, err := strconv.ParseUint(strings.TrimSpace(p), 0, 8)
				if err != nil {
					valid = false
					break
				}
				b = append(b, byte(n))
			}
			if !valid {
				continue
			}
			seen[current] = true
			if !bytes.Equal(b, expected[current]) {
				failures = append(failures, fmt.Sprintf("%s %s got %x LLVM %x", current, ids[current], expected[current], b))
			} else {
				matched++
			}
		}
	}
	// These three source records have malformed LLVM AsmStrings. Independently
	// decode their bytes into the named MCInst and re-emit that instruction;
	// feeding a raw directive to the assembler would only check a byte copier.
	for _, label := range disassembly {
		var input strings.Builder
		for _, b := range expected[label] {
			fmt.Fprintf(&input, "0x%02x ", b)
		}
		cmd := exec.Command(mc, "-triple="+triple, "-mcpu=future", "-mattr=+spe,+htm", "-disassemble", "-show-inst", "-show-encoding")
		cmd.Stdin = strings.NewReader(input.String())
		output, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(output), " "+ids[label]+"\n") {
			fmt.Fprintf(&stderr, "%s native decode: %v\n%s", ids[label], err, output)
			continue
		}
		match := encodingRE.FindStringSubmatch(string(output))
		if match == nil {
			fmt.Fprintf(&stderr, "%s native re-emission missing:\n%s", ids[label], output)
			continue
		}
		var got []byte
		for _, p := range strings.Split(match[1], ",") {
			n, err := strconv.ParseUint(strings.TrimSpace(p), 0, 8)
			if err != nil {
				t.Fatalf("%s native re-emission: %v", ids[label], err)
			}
			got = append(got, byte(n))
		}
		seen[label] = true
		operands := regexp.MustCompile(`MCOperand ([^>]+)>`).FindAllStringSubmatch(string(output), -1)
		fieldsMatch := len(operands) == len(nativeOperands[label])
		for i := range operands {
			if i >= len(nativeOperands[label]) || operands[i][1] != nativeOperands[label][i] {
				fieldsMatch = false
			}
		}
		if !fieldsMatch {
			failures = append(failures, fmt.Sprintf("%s %s native operand identity differs: got %v want %v", label, ids[label], operands, nativeOperands[label]))
			continue
		}
		if !bytes.Equal(got, expected[label]) {
			failures = append(failures, fmt.Sprintf("%s %s got %x LLVM decode+emit %x", label, ids[label], expected[label], got))
		} else {
			matched++
		}
	}
	missing := []string{}
	for label := range expected {
		if !seen[label] {
			missing = append(missing, ids[label])
		}
	}
	report := struct {
		Imported, Attempted, Matched int
		NativeDecoded                int
		Unsupported                  []codec.Unsupported
		Mismatches, LLVMRejected     []string
		Diagnostics                  string
	}{len(c.Encodings), count, matched, len(disassembly), c.Unsupported, failures, missing, stderr.String()}
	b, _ := json.MarshalIndent(report, "", "  ")
	if dir := os.Getenv("MKASM_POWERPC_PARITY_DIR"); dir != "" {
		_ = os.MkdirAll(dir, 0755)
		_ = os.WriteFile(filepath.Join(dir, architecture+"-parity.json"), b, 0644)
	}
	t.Logf("imported %d; %d samples, %d LLVM matches, %d mismatches, %d LLVM rejected", len(c.Encodings), count, matched, len(failures), len(missing))
	if len(failures) > 0 {
		if len(failures) > 30 {
			failures = failures[:30]
		}
		t.Fatalf("LLVM mismatches: %s", strings.Join(failures, "\n"))
	}
	if len(missing) > 0 {
		t.Fatalf("LLVM rejected %d imported samples: %s", len(missing), strings.Join(missing, ", "))
	}
	if matched < 6000 {
		t.Fatalf("insufficient independent corpus validation: %d; diagnostics: %.2000s", matched, stderr.String())
	}
}
