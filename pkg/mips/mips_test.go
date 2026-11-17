package mips

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func corpus(t *testing.T, arch string) *codec.Catalog {
	t.Helper()
	p := os.Getenv("MKASM_MIPS_TABLEGEN_JSON")
	if p == "" {
		t.Skip("set MKASM_MIPS_TABLEGEN_JSON to real llvm-tblgen --dump-json Mips.td output")
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f, arch)
	if err != nil {
		t.Fatal(err)
	}
	return c.InstructionCatalog()
}
func TestRealTableGenCorpus(t *testing.T) {
	for _, arch := range []string{"mips32", "mips32el", "mips64", "mips64el"} {
		t.Run(arch, func(t *testing.T) {
			c := corpus(t, arch)
			reasons := map[string]int{}
			for _, u := range c.Unsupported {
				reasons[u.Reason]++
			}
			t.Logf("encodings=%d unsupported=%d reasons=%v", len(c.Encodings), len(c.Unsupported), reasons)
			if len(c.Encodings) < 800 {
				t.Fatalf("unexpectedly small real corpus %d", len(c.Encodings))
			}
			for _, e := range c.Encodings {
				if len(e.Mask) != 4 {
					t.Errorf("%s has non-standard framing", e.ID)
				}
				if strings.Contains(e.ID, "_MM") {
					t.Errorf("microMIPS leaked into standard mode: %s", e.ID)
				}
			}
		})
	}
}

func smallCorpus(t *testing.T, arch string) *codec.Catalog {
	t.Helper()
	f, err := os.Open("testdata/llvm22-mips.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c, err := Parse(f, arch)
	if err != nil {
		t.Fatal(err)
	}
	return c.InstructionCatalog()
}
func TestArchitectureAndOperands(t *testing.T) {
	for _, arch := range []string{"mips32", "mips32el", "mips64", "mips64el"} {
		t.Run(arch, func(t *testing.T) {
			c := smallCorpus(t, arch)
			b, err := c.Encode("LW", map[string]int64{"rt": 8, "addr_base": 29, "addr_offset": -16})
			if err != nil {
				t.Fatal(err)
			}
			expected := []byte{0x8f, 0xa8, 0xff, 0xf0}
			if strings.HasSuffix(arch, "el") {
				expected = []byte{0xf0, 0xff, 0xa8, 0x8f}
			}
			if !bytes.Equal(b, expected) {
				t.Fatalf("lw = %x, want %x", b, expected)
			}
			decoded, err := c.Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Length != 4 {
				t.Fatalf("wrong framing: %d", decoded.Length)
			}
			candidates, err := c.Assemble(decoded.Format(0), 0)
			if err != nil || !containsBytes(candidates, b) {
				t.Fatalf("decode/assemble %q = %x, %v", decoded.Format(0), candidates, err)
			}
			if _, err := c.Decode(b[:3]); !errors.Is(err, codec.ErrTruncated) {
				t.Fatalf("truncated word: %v", err)
			}
			jump, err := c.Encode("J", map[string]int64{"target": 0x120})
			if err != nil {
				t.Fatal(err)
			}
			d, err := c.Decode(jump)
			if err != nil {
				t.Fatal(err)
			}
			if got := d.Format(0x80000000); got != "j 0x80000120" {
				t.Fatalf("pseudo-direct region: %s", got)
			}
			if candidates, err := c.Assemble("j 0x80000120", 0x80000000); err != nil || !containsBytes(candidates, jump) {
				t.Fatalf("jump assembly: %x %v", candidates, err)
			}
			branch, err := c.Encode("BEQ", map[string]int64{"rs": 8, "rt": 9, "offset": -8})
			if err != nil {
				t.Fatal(err)
			}
			d, err = c.Decode(branch)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasSuffix(d.Format(0x1000), "0xffc") {
				t.Fatalf("PC+4 branch: %s", d.Format(0x1000))
			}
			if _, err := c.Encode("BEQ", map[string]int64{"rs": 8, "rt": 9, "offset": 3}); err == nil {
				t.Fatal("accepted unaligned branch")
			}
			if _, err := c.Encode("BOVC", map[string]int64{"rs": 8, "rt": 9, "offset": 4}); err == nil {
				t.Fatal("accepted invalid compact branch register order")
			}
			if _, err := c.Encode("INS", map[string]int64{"rt": 8, "rs": 9, "pos": 8, "size": 0}); err == nil {
				t.Fatal("accepted zero bitfield size")
			}
			ins, err := c.Encode("INS", map[string]int64{"rt": 8, "rs": 9, "pos": 8, "size": 7})
			if err != nil {
				t.Fatal(err)
			}
			d, err = c.Decode(ins)
			if err != nil {
				t.Fatal(err)
			}
			if d.Values["size"] != 7 {
				t.Fatalf("dependent size %v", d.Values)
			}
			// The third CRC register is tied to the destination by encoding semantics.
			if _, err := c.Assemble("crc32b $8, $9, $10", 0); err == nil {
				t.Fatal("accepted unequal CRC destination/source")
			}
			if _, err := c.Encode("EXT", map[string]int64{"rt": 8, "rs": 9, "pos": 31, "size": 2}); err == nil {
				t.Fatal("accepted overflowing bitfield")
			}
			expectedRelaxed, err := c.Encode("ADDiu", map[string]int64{"rt": 8, "rs": 9, "imm16": -1})
			if err != nil {
				t.Fatal(err)
			}
			if candidates, err := c.Assemble("addiu $8, $9, 65535", 0); err != nil || !containsBytes(candidates, expectedRelaxed) {
				t.Fatalf("relaxed signed immediate: %x %v", candidates, err)
			}
			expectedLUI, err := c.Encode("LUi", map[string]int64{"rt": 8, "imm16": 65535})
			if err != nil {
				t.Fatal(err)
			}
			if candidates, err := c.Assemble("lui $8, -1", 0); err != nil || !containsBytes(candidates, expectedLUI) {
				t.Fatalf("relaxed unsigned immediate: %x %v", candidates, err)
			}
			expectedSub, err := c.Encode("ADDiu", map[string]int64{"rt": 8, "rs": 8, "imm16": -3})
			if err != nil {
				t.Fatal(err)
			}
			if candidates, err := c.Assemble("subu $8, 3", 0); err != nil || !containsBytes(candidates, expectedSub) {
				t.Fatalf("inverted alias: %x %v", candidates, err)
			}
			if _, err := c.Assemble("nop", 0); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(arch, "mips32") {
				if _, err := c.Encode("DADD", map[string]int64{"rd": 8, "rs": 9, "rt": 10}); err == nil {
					t.Fatal("MIPS64 encoding leaked into MIPS32")
				}
			}
		})
	}
	if _, err := Parse(strings.NewReader(`{}`), "mips"); err == nil {
		t.Fatal("accepted unknown architecture")
	}
}
func containsBytes(all [][]byte, b []byte) bool {
	for _, v := range all {
		if bytes.Equal(v, b) {
			return true
		}
	}
	return false
}

func TestLLVMIndependentAssembly(t *testing.T) {
	llvm := os.Getenv("LLVM_MC")
	if llvm == "" {
		llvm = "/opt/homebrew/opt/llvm/bin/llvm-mc"
	}
	if _, err := os.Stat(llvm); err != nil {
		t.Skip("LLVM_MC is not available")
	}
	cases := []struct {
		id, text, cpu, attr string
		values              map[string]int64
		only64              bool
	}{
		{"ADD", "add $8, $9, $10", "mips32r2", "", map[string]int64{"rd": 8, "rs": 9, "rt": 10}, false},
		{"ADDiu", "addiu $8, $9, -32768", "mips32r2", "", map[string]int64{"rt": 8, "rs": 9, "imm16": -32768}, false},
		{"ANDi", "andi $8, $9, 65535", "mips32r2", "", map[string]int64{"rt": 8, "rs": 9, "imm16": 65535}, false},
		{"LW", "lw $8, -16($sp)", "mips32r2", "", map[string]int64{"rt": 8, "addr_base": 29, "addr_offset": -16}, false},
		{"SW", "sw $10, 32767($9)", "mips32r2", "", map[string]int64{"rt": 10, "addr_base": 9, "addr_offset": 32767}, false},
		{"SLL", "sll $8, $9, 31", "mips32r2", "", map[string]int64{"rd": 8, "rt": 9, "shamt": 31}, false},
		{"BEQ", "beq $8, $9, -8", "mips32r2", "", map[string]int64{"rs": 8, "rt": 9, "offset": -8}, false},
		{"J", "j 1024", "mips32r2", "", map[string]int64{"target": 1024}, false},
		{"FADD_S", "add.s $f2, $f4, $f6", "mips32r2", "", map[string]int64{"fd": 2, "fs": 4, "ft": 6}, false},
		{"LDC1", "ldc1 $f2, -8($sp)", "mips32r2", "", map[string]int64{"rt": 2, "addr_base": 29, "addr_offset": -8}, false},
		{"INS", "ins $8, $9, 8, 7", "mips32r2", "", map[string]int64{"rt": 8, "rs": 9, "pos": 8, "size": 7}, false},
		{"BOVC", "bovc $10, $8, 16", "mips32r6", "", map[string]int64{"rs": 10, "rt": 8, "offset": 16}, false},
		{"BEQC", "beqc $8, $10, 16", "mips32r6", "", map[string]int64{"rs": 8, "rt": 10, "offset": 16}, false},
		{"CRC32B", "crc32b $8, $9, $8", "mips32r6", "+crc", map[string]int64{"rt": 8, "rs": 9}, false},
		{"LD_D", "ld.d $w4, -32($sp)", "mips32r5", "+msa", map[string]int64{"wd": 4, "addr_base": 29, "addr_offset": -32}, false},
		{"ADDV_B", "addv.b $w1, $w2, $w3", "mips32r5", "+msa", map[string]int64{"wd": 1, "ws": 2, "wt": 3}, false},
		{"INSVE_B", "insve.b $w1[3], $w2[0]", "mips32r5", "+msa", map[string]int64{"wd": 1, "n": 3, "ws": 2}, false},
		{"DADD", "dadd $8, $9, $10", "mips64r2", "", map[string]int64{"rd": 8, "rs": 9, "rt": 10}, true},
		{"DINS", "dins $8, $9, 8, 7", "mips64r2", "", map[string]int64{"rt": 8, "rs": 9, "pos": 8, "size": 7}, true},
		{"DINSM", "dinsm $8, $9, 8, 40", "mips64r2", "", map[string]int64{"rt": 8, "rs": 9, "pos": 8, "size": 40}, true},
		{"DINSU", "dinsu $8, $9, 40, 7", "mips64r2", "", map[string]int64{"rt": 8, "rs": 9, "pos": 40, "size": 7}, true},
		{"DEXTM", "dextm $8, $9, 8, 40", "mips64r2", "", map[string]int64{"rt": 8, "rs": 9, "pos": 8, "size": 40}, true},
		{"DEXTU", "dextu $8, $9, 40, 7", "mips64r2", "", map[string]int64{"rt": 8, "rs": 9, "pos": 40, "size": 7}, true},
		{"DAHI", "dahi $8, $8, 123", "mips64r6", "", map[string]int64{"rs": 8, "imm": 123}, true},
	}
	for _, arch := range []string{"mips32", "mips32el", "mips64", "mips64el"} {
		t.Run(arch, func(t *testing.T) {
			c := smallCorpus(t, arch)
			triple := strings.Replace(arch, "32", "", 1)
			for _, tc := range cases {
				if tc.only64 && !strings.HasPrefix(arch, "mips64") {
					continue
				}
				t.Run(tc.id, func(t *testing.T) {
					cpu := tc.cpu
					if strings.HasPrefix(arch, "mips64") {
						cpu = strings.Replace(cpu, "mips32", "mips64", 1)
					}
					argv := []string{"-triple=" + triple, "-mcpu=" + cpu, "-show-encoding"}
					if tc.attr != "" {
						argv = append(argv, "-mattr="+tc.attr)
					}
					cmd := exec.Command(llvm, argv...)
					cmd.Stdin = strings.NewReader(".set noreorder\n.set noat\n" + tc.text + "\n")
					result, err := cmd.CombinedOutput()
					if err != nil {
						t.Fatalf("LLVM: %s: %v", result, err)
					}
					match := regexp.MustCompile(`encoding: \[([^]]+)\]`).FindSubmatch(result)
					if match == nil {
						t.Fatalf("LLVM produced no encoding: %s", result)
					}
					var expected []byte
					for _, s := range strings.Split(string(match[1]), ",") {
						n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 8)
						if err != nil {
							t.Fatal(err)
						}
						expected = append(expected, byte(n))
					}
					got, err := c.Encode(tc.id, tc.values)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, expected) {
						t.Fatalf("%s: got %x, LLVM %x", tc.text, got, expected)
					}
					d, err := c.Decode(expected)
					if err != nil {
						t.Fatal(err)
					}
					again, err := c.Assemble(d.Format(0), 0)
					if err != nil || !containsBytes(again, expected) {
						t.Fatalf("real LLVM bytes -> %q -> %x, %v", d.Format(0), again, err)
					}
				})
			}
		})
	}
}

// This optional audit exercises every imported standard source encoding against
// an independent LLVM assembler, choosing CPU/features from its source predicates.
func TestLLVMWholeCorpus(t *testing.T) {
	if os.Getenv("MKASM_MIPS_VALIDATE_ALL") == "" {
		t.Skip("set MKASM_MIPS_VALIDATE_ALL=1 for independent whole-corpus audit")
	}
	arch := os.Getenv("MKASM_MIPS_AUDIT_ARCH")
	if arch == "" {
		arch = "mips64el"
	}
	verifyLLVMWholeCorpus(t, arch, arch)
}

func verifyLLVMWholeCorpus(t *testing.T, arch, referenceArch string) {
	t.Helper()
	llvm := os.Getenv("LLVM_MC")
	if llvm == "" {
		llvm = "/opt/homebrew/opt/llvm/bin/llvm-mc"
	}
	c := corpus(t, arch)
	referenceForms := map[string]*codec.Encoding{}
	if referenceArch != arch {
		physical := corpus(t, referenceArch)
		for i := range physical.Encodings {
			referenceForms[physical.Encodings[i].ID] = &physical.Encodings[i]
		}
	}
	matched, rejected, derived, gnuCorrected, gnu64 := 0, 0, 0, 0, 0
	for _, e := range c.Encodings {
		if strings.HasPrefix(e.ID, "GNU_MICRO64_ROW_") {
			// These machine rows have no LLVM counterpart. The enclosing
			// microMIPS64 job validates every one with the real GNU ELF64
			// assembler/linker and the fresh CLI-generated Rust consumer.
			gnu64++
			continue
		}
		// These text-order variants are derived by this adapter. LLVM's
		// microMIPS BEQC/BNEC parser does not commute reversed operands;
		// it emits the other opcode partition. Test our commutation separately.
		if e.AssemblyOnly && (strings.HasSuffix(e.ID, "_commuted") || strings.HasSuffix(e.ID, "_generic_spelling")) {
			derived++
			continue
		}
		values := referenceOperands(e)
		b, err := codec.Encode(&e, values)
		if err != nil {
			t.Errorf("sample %s: %v", e.ID, err)
			continue
		}
		referenceEncoding := &e
		if referenceArch != arch {
			referenceEncoding = referenceForms[e.ID]
			if referenceEncoding == nil {
				t.Fatalf("missing reference form %s", e.ID)
			}
		}
		d := codec.Decoded{Encoding: referenceEncoding, Values: values, Length: len(b)}
		text := d.Format(0)
		if correctedMicroDSP(e.ID) {
			as := os.Getenv("MKASM_MIPS_AS")
			if as == "" {
				t.Skip("set MKASM_MIPS_AS for the five independently corrected LLVM microMIPS DSP records")
			}
			sourceText := (&codec.Decoded{Encoding: &e, Values: values, Length: len(b)}).Format(0)
			expected := assembleGNUReference(t, as, arch, sourceText, true)
			if !bytes.Equal(b, expected) {
				t.Errorf("corrected %s: got %x GNU %x", e.ID, b, expected)
			} else {
				gnuCorrected++
			}
			continue
		}
		for _, o := range e.Operands {
			if o.Relative && o.PCRegionBits == 0 {
				text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", uint64(o.PCBias)+uint64(values[o.Name])), strconv.FormatInt(values[o.Name], 10))
			}
		}
		cpuBase := "mips64"
		if strings.Contains(referenceArch, "32") {
			cpuBase = "mips32"
		}
		cpu := cpuBase + "r5"
		if has(e.Features, "HasMips32r6") || has(e.Features, "HasMips64r6") {
			cpu = cpuBase + "r6"
		}
		if has(e.Features, "HasCnMips") {
			cpu = "octeon"
		}
		if has(e.Features, "HasCnMipsP") {
			cpu = "octeon+"
		}
		attr := []string{}
		if strings.HasPrefix(arch, "micromips") {
			attr = append(attr, "+micromips")
		}
		for _, p := range []struct{ predicate, attr string }{{"HasMSA", "+msa"}, {"HasDSP", "+dsp"}, {"HasDSPR2", "+dspr2"}, {"HasDSPR3", "+dspr3"}, {"HasEVA", "+eva"}, {"HasMT", "+mt"}, {"HasVirt", "+virt"}, {"HasCRC", "+crc"}, {"HasGINV", "+ginv"}, {"HasMips3D", "+mips3d"}, {"IsFP64bit", "+fp64"}, {"NotFP64bit", "-fp64"}} {
			if has(e.Features, p.predicate) {
				attr = append(attr, p.attr)
			}
		}
		triple := strings.TrimPrefix(referenceArch, "micro")
		argv := []string{"-triple=" + strings.Replace(triple, "32", "", 1), "-mcpu=" + cpu, "-show-encoding"}
		if len(attr) > 0 {
			argv = append(argv, "-mattr="+strings.Join(attr, ","))
		}
		cmd := exec.Command(llvm, argv...)
		cmd.Stdin = strings.NewReader(".set noreorder\n.set noat\n" + text + "\n")
		result, err := cmd.CombinedOutput()
		if err != nil {
			rejected++
			t.Logf("LLVM rejected %s %q: %s", e.ID, text, result)
			continue
		}
		match := regexp.MustCompile(`encoding: \[([^]]+)\]`).FindSubmatch(result)
		if match == nil {
			t.Errorf("no encoding %s %q: %s", e.ID, text, result)
			continue
		}
		var expected []byte
		for _, s := range strings.Split(string(match[1]), ",") {
			n, err := strconv.ParseUint(strings.TrimSpace(s), 0, 8)
			if err != nil {
				t.Errorf("nonconstant LLVM %s: %s", e.ID, result)
				break
			}
			expected = append(expected, byte(n))
		}
		if !bytes.Equal(b, expected) {
			// LLVM chooses one of several semantically equivalent move aliases.
			sourceText := (&codec.Decoded{Encoding: &e, Values: values, Length: len(b)}).Format(0)
			candidates, err := c.Assemble(sourceText, 0)
			if strings.HasPrefix(e.ID, "anonymous_") && (strings.HasPrefix(text, "move ") || text == "nop") && err == nil && containsBytes(candidates, expected) {
				matched++
				continue
			}
			t.Errorf("%s %q got %x LLVM %x", e.ID, text, b, expected)
		} else {
			matched++
		}
	}
	t.Logf("independent LLVM whole corpus: matched=%d gnu_corrected=%d rejected=%d imported=%d derived_text_variants=%d gnu64_rows=%d", matched, gnuCorrected, rejected, len(c.Encodings), derived, gnu64)
	if matched+gnuCorrected+derived+gnu64 != len(c.Encodings) {
		t.Errorf("reference coverage incomplete: %d/%d", matched+gnuCorrected+derived+gnu64, len(c.Encodings))
	}
	if rejected != 0 {
		t.Errorf("LLVM rejected %d corpus samples", rejected)
	}
}

// referenceOperands selects legal semantic operands, independently of the reference assembler.
func referenceOperands(e codec.Encoding) map[string]int64 {
	values := map[string]int64{}
	for i, o := range e.Operands {
		n := int64(3)
		if o.Kind == "register" {
			n = int64(8 + i)
			if n >= int64(len(o.Names)) || o.Names[n] == "" {
				for j, s := range o.Names {
					if s != "" {
						n = int64(j)
						break
					}
				}
			}
		}
		if o.Width() < 3 && n >= (1<<o.Width()) {
			n = 1
		}
		scale := o.Scale
		if scale == 0 {
			scale = 1
		}
		values[o.Name] = n*scale + o.Bias
		if len(o.Lookup) > 0 {
			values[o.Name] = o.Lookup[int(n)%len(o.Lookup)]
		}
		if o.Implicit {
			values[o.Name] = 0
		}
		if strings.HasPrefix(e.ID, "GNU_MICRO64_ROW_") && o.BiasOperand != "" {
			values[o.Name] += o.BiasScale * values[o.BiasOperand]
		}
		if o.Class == "MSA128CROpnd" {
			values[o.Name] = 1
		}
	}
	if _, ok := values["pos"]; ok {
		values["pos"] = 8
		for _, o := range e.Operands {
			if o.Name == "pos" && o.Bias == 32 {
				values["pos"] = 40
			}
		}
		for _, o := range e.Operands {
			if o.Name == "pos" && o.Bias == 32 {
				values["pos"] = 40
			}
		}
	}
	if _, ok := values["size"]; ok {
		values["size"] = 7
		for _, o := range e.Operands {
			if o.Name == "size" && o.Bias == 33 && o.BiasOperand == "" {
				values["size"] = 40
			}
			if o.Name == "size" && o.Bias == 33 && o.BiasOperand != "" && values["pos"] < 32 {
				values["size"] = 40
			}
		}
	}
	for _, con := range e.Constraints {
		if con.Kind == "ge" && con.Left == "rs" && con.Right == "rt" {
			values["rs"] = 12
			values["rt"] = 10
		}
	}
	return values
}
