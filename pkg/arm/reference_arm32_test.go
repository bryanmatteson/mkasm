package arm

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bryanmatteson/mkasm/internal/testreference"
	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// LLVM supplies the input bytes. A freshly generated full-corpus Rust codec
// decodes/encodes them and returns its rendered text for independent reassembly.
func TestIndependentARM32LLVM(t *testing.T) {
	input, llvm := os.Getenv("MKASM_REFERENCE_ARM32_CORPUS"), os.Getenv("MKASM_LLVM_MC")
	if input == "" || llvm == "" {
		t.Skip("set MKASM_REFERENCE_ARM32_CORPUS and MKASM_LLVM_MC")
	}
	corpus, err := OpenTarXMLCorpus(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	dir := os.Getenv("MKASM_ARM32_REFERENCE_RUST")
	if dir == "" {
		dir = t.TempDir()
	} else if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	cli := os.Getenv("MKASM_REFERENCE_CLI")
	parser := NewARMParser(ARMParserConfig{Corpus: corpus, EncodingIndexPath: ArchARM32.SpecIndexFile(), Arch: ArchARM32, Languages: []CodegenLang{LangRust}, OutputDirectory: dir, SkipCodegen: cli != ""})
	defer parser.Close(5 * time.Second)
	if err := parser.Parse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cli != "" {
		cmd := exec.Command(cli, "--arch", "arm32", "--codegen", "rust", "--output", dir, input)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("CLI ARM32 generation: %v\n%s", err, output)
		}
	}
	if err := testreference.StandaloneRust(dir); err != nil {
		t.Fatal(err)
	}
	type sample struct {
		text, mode, endian, triple string
		bytes                      []byte
	}
	var cases []sample
	for _, thumb := range []bool{false, true} {
		texts := []string{"add r0, r1, r2", "subs r3, r4, #1", "ldr r0, [r1, #-4]", "str r2, [sp, #12]", "ldrb r0, [r1, r2, lsl #1]", "push {r4, lr}", "pop {r4, pc}", "bx lr", "movw r0, #4660", "vadd.f32 s0, s1, s2", "vadd.i32 q0, q1, q2", "ldrex r0, [r1]", "strex r0, r2, [r1]", "dmb sy", "dbg #15", "nop", "b .", "vshr.u64 q0, q1, #63", "vtbl.8 d0, {d16, d17, d18, d19}, d3", "vld2.32 {d0[], d2[]}, [r0:64]", "vld4.32 {d0[1], d1[1], d2[1], d3[1]}, [r0:128]"}
		if thumb {
			texts = append(texts, "adds r0, r1, r2", "movs r0, #255", "lsl.w r0, r1, #31", "addw r0, r1, #4095", "add r8, sp, r8", "add sp, #508", "ldrex r3, [r4, #252]", "rsbs.w r2, r3, #15", "adcs.w r2, r3, r4, lsl #5", "ldmia r4!, {r0, r2}", "ldmia r4, {r0, r2, r4}", "pop.w {r8, pc}")
		}
		for _, big := range []bool{false, true} {
			mode, triple, endian := "Arm", "armv7-none-eabi", "Little"
			if thumb {
				mode, triple = "Thumb", "thumbv7-none-eabi"
			}
			if big {
				endian = "Big"
				if thumb {
					triple = "thumbebv7-none-eabi"
				} else {
					triple = "armebv7-none-eabi"
				}
			}
			for _, text := range texts {
				cases = append(cases, sample{text: text, mode: mode, endian: endian, triple: triple})
			}
		}
	}
	if source := os.Getenv("MKASM_LLVM_SOURCE"); source != "" {
		base := filepath.Join(source, "llvm", "test", "MC", "ARM")
		files := []string{"basic-arm-instructions.s", "basic-thumb-instructions.s", "basic-thumb2-instructions.s"}
		for _, pattern := range []string{"neon*-encoding.s", "neont2-*-encoding.s"} {
			matches, err := filepath.Glob(filepath.Join(base, pattern))
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range matches {
				files = append(files, filepath.Base(file))
			}
		}
		outside := map[string]int{}
		for _, file := range files {
			thumb := strings.Contains(file, "thumb") || strings.HasPrefix(file, "neont2-")
			for _, big := range []bool{false, true} {
				mode, triple, endian := "Arm", "armv7-none-eabi", "Little"
				if thumb {
					mode, triple = "Thumb", "thumbv7-none-eabi"
				}
				if big {
					endian = "Big"
					if thumb {
						triple = "thumbebv7-none-eabi"
					} else {
						triple = "armebv7-none-eabi"
					}
				}
				vectors, fixups, err := testreference.AssembleFile(llvm, filepath.Join(base, file), "-triple="+triple, "-mcpu=cortex-a8", "-mattr=+neon,+vfp4,+hwdiv,+hwdiv-arm")
				if err != nil {
					t.Fatal(err)
				}
				for _, vector := range vectors {
					var word uint32
					order := binary.ByteOrder(binary.LittleEndian)
					if big {
						order = binary.BigEndian
					}
					if thumb {
						word = uint32(order.Uint16(vector.Bytes))
						if len(vector.Bytes) == 4 {
							word = word<<16 | uint32(order.Uint16(vector.Bytes[2:]))
						}
					} else {
						word = order.Uint32(vector.Bytes)
					}
					present := false
					for _, insn := range parser.ResolvedInstructions() {
						if (insn.InstructionSet == "T32") != thumb || insn.Encoding.Width != len(vector.Bytes)*8 {
							continue
						}
						if ir.MatchWord(insn, word) {
							present = true
							break
						}
					}
					if !present {
						outside[strings.Fields(vector.Text)[0]]++
						continue
					}
					cases = append(cases, sample{text: vector.Text, mode: mode, endian: endian, triple: triple, bytes: vector.Bytes})
				}
				t.Logf("native %s %s: %d concrete vectors (%d relocatable fragments handled by separate relocation tests)", file, triple, len(vectors), fixups)
			}
		}
		if len(outside) > 0 {
			t.Logf("native forms outside the imported XML allocation vocabulary (not counted as corpus coverage): %v", outside)
		}
	}
	assemble := func(c sample, text string) []byte {
		t.Helper()
		state := ".arm\n"
		if c.mode == "Thumb" {
			state = ".thumb\n"
		}
		cmd := exec.Command(llvm, "-triple="+c.triple, "-mattr=+v8,+ras,+neon,+vfp4,+hwdiv,+hwdiv-arm", "-filetype=obj")
		cmd.Stdin = strings.NewReader(".syntax unified\n.text\n" + state + text + "\n")
		var diagnostics bytes.Buffer
		cmd.Stderr = &diagnostics
		object, err := cmd.Output()
		if err != nil {
			t.Fatalf("LLVM %s %q: %v\n%s", c.triple, text, err, diagnostics.String())
		}
		file, err := elf.NewFile(bytes.NewReader(object))
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		data, err := file.Section(".text").Data()
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var rust strings.Builder
	rust.WriteString("use arm32::*;\n#[test]fn independent_llvm(){\n")
	var vectors strings.Builder
	for n := range cases {
		c := &cases[n]
		if c.bytes == nil {
			c.bytes = assemble(*c, c.text)
		}
		fmt.Fprintf(&vectors, "%s\t%s\t%s\t%s\n", c.mode, c.endian, hex.EncodeToString(c.bytes), c.text)
	}
	rust.WriteString(`for (n,line) in include_str!("llvm.tsv").lines().enumerate(){
let parts:Vec<_>=line.splitn(4,'\t').collect();let mode=if parts[0]=="Arm"{Mode::Arm}else{Mode::Thumb};let endian=if parts[1]=="Little"{Endian::Little}else{Endian::Big};
let hex=parts[2];let expected:Vec<u8>=(0..hex.len()).step_by(2).map(|i|u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect();
let d=decode(&expected,mode,endian).unwrap_or_else(|e|panic!("case {n} {line}: {e:?}"));assert_eq!(d.length,expected.len());
if parts[3]=="b ."{assert_eq!(d.branch_target(0),Some(0));}
let fields:Vec<_>=d.encoding_fields().collect();
assert_eq!(encode(d.encoding_id(),&fields,endian).unwrap(),expected,"case {n} {line}");
use arm32::analysis::{Value,FlowKind};
let a=d.analyze_with_thumb_condition(0,Some(14));
let has=|v|a.components().iter().any(|c|c.value==v);
match parts[3]{
 "add r8, sp, r8"=>assert!(has(Value::Register(Register::Gpr(8)))),
 "add sp, #508"=>assert!(has(Value::Integer(508))),
 "ldrex r3, [r4, #252]"=>assert_eq!(a.memory.unwrap().displacement,252),
 "rsbs.w r2, r3, #15"=>assert!(has(Value::Integer(15))),
 "adcs.w r2, r3, r4, lsl #5"=>assert!(d.details(0).unwrap().operands.iter().any(|p|p.kind==OperandKind::Register(Register::Gpr(4))&&p.shift==Shift::Lsl(5))),
 "ldmia r4!, {r0, r2}"=>assert!(a.memory.unwrap().writeback),
 "ldmia r4, {r0, r2, r4}"=>assert!(!a.memory.unwrap().writeback),
 "pop.w {r8, pc}"=>{assert!(has(Value::RegisterMask(0x8100)));assert_eq!(a.control_flow.kind,FlowKind::Return);},
 "vshr.u64 q0, q1, #63"=>assert!(has(Value::Integer(63))),
 "vtbl.8 d0, {d16, d17, d18, d19}, d3"=>assert!(has(Value::RegisterSequence{first:Register::D(16),count:4,stride:1})),
 "vld2.32 {d0[], d2[]}, [r0:64]"=>{assert!(has(Value::RegisterSequence{first:Register::D(0),count:2,stride:2}));assert_eq!(a.memory.unwrap().alignment_bits,Some(64));},
 "vld4.32 {d0[1], d1[1], d2[1], d3[1]}, [r0:128]"=>assert_eq!(a.memory.unwrap().alignment_bits,Some(128)),
 _=>{}
}
println!("REFERENCE\t{n}\t{}\t{:?}\t{}",d.format(0).unwrap_or_else(|e|panic!("case {n} {line}: {e:?}")),d.branch_target(0),d.encoding_id());
}}
`)
	if err := os.MkdirAll(filepath.Join(dir, "tests"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "llvm.tsv"), []byte(vectors.String()), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "llvm_reference.rs"), []byte(rust.String()), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "analysis.rs"), []byte(rustAnalysisA32Behavior), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("cargo", "test", "--lib", "--test", "analysis", "--test", "llvm_reference", "--no-fail-fast", "--", "--nocapture", "--test-threads=1")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated ARM32 independent reference consumer: %v\n%s", err, out)
	}
	seen := map[int]bool{}
	rendered := map[int]string{}
	ids := map[int]string{}
	aliases := 0
	addressLiteral := regexp.MustCompile(`#?0x[0-9a-fA-F]+`)
	for _, line := range strings.Split(string(out), "\n") {
		marker := strings.Index(line, "REFERENCE\t")
		if marker < 0 {
			continue
		}
		line = line[marker:]
		parts := strings.SplitN(line, "\t", 5)
		n, err := strconv.Atoi(parts[1])
		if err != nil || n < 0 || n >= len(cases) || seen[n] {
			t.Fatal("invalid generated reference case", line)
		}
		seen[n] = true
		if len(parts) == 5 {
			ids[n] = parts[4]
		}
		c := cases[n]
		text := parts[2]
		if strings.HasPrefix(strings.ToLower(text), "adr") {
			// LLVM's numeric ADR operand is a PC-relative displacement. Use
			// wrapping 32-bit arithmetic: large modified immediates are legal
			// even when a signed symbolic fixup would be out of range.
			text = addressLiteral.ReplaceAllStringFunc(text, func(target string) string {
				value, err := strconv.ParseUint(strings.TrimPrefix(target, "#"), 0, 32)
				if err != nil {
					t.Fatal(err)
				}
				bias := uint32(8)
				if c.mode == "Thumb" {
					bias = 4
				}
				return fmt.Sprintf("#%d", int32(uint32(value)-bias))
			})
		} else if len(parts) >= 4 && strings.HasPrefix(parts[3], "Some(") {
			// LLVM's numeric branch operand is a displacement from the
			// architectural PC, while the formatter exposes an absolute target.
			text = addressLiteral.ReplaceAllStringFunc(text, func(target string) string {
				value, err := strconv.ParseUint(strings.TrimPrefix(target, "#"), 0, 32)
				if err != nil {
					t.Fatal(err)
				}
				bias := uint32(8)
				if c.mode == "Thumb" {
					bias = 4
				}
				return fmt.Sprintf("#%d", int32(uint32(value)-bias))
			})
		}
		if c.text == "b ." {
			text = "b ."
		} // LLVM numeric branch syntax is a displacement, our formatter prints an address.
		rendered[n] = text
	}
	if len(seen) != len(cases) {
		t.Fatalf("only %d/%d generated reference cases executed", len(seen), len(cases))
	}
	// Each section starts at zero, preserving the formatter's address context.
	// Batch native assembly instead of starting thousands of LLVM processes.
	actuals := map[int][]byte{}
	for _, triple := range []string{"armv7-none-eabi", "armebv7-none-eabi", "thumbv7-none-eabi", "thumbebv7-none-eabi"} {
		var source strings.Builder
		source.WriteString(".syntax unified\n")
		lineCases := map[int]int{}
		lineNumber := 1
		for n, c := range cases {
			if c.triple != triple {
				continue
			}
			text := rendered[n]
			mnemonic := strings.Fields(text)[0]
			if c.mode == "Thumb" && strings.HasPrefix(mnemonic, "it") || (strings.HasPrefix(mnemonic, "dmb") || strings.HasPrefix(mnemonic, "dsb")) && strings.HasSuffix(text, "ld") {
				actuals[n] = assemble(c, text)
				continue
			}
			fmt.Fprintf(&source, ".section .text.c%d,\"ax\",%%progbits\n", n)
			if c.mode == "Thumb" {
				source.WriteString(".thumb\n")
			} else {
				source.WriteString(".arm\n")
			}
			fmt.Fprintln(&source, text)
			lineNumber += 3
			lineCases[lineNumber] = n
		}
		cmd := exec.Command(llvm, "-triple="+triple, "-mattr=+ras,+neon,+vfp4,+hwdiv,+hwdiv-arm", "-filetype=obj")
		cmd.Stdin = strings.NewReader(source.String())
		var diagnostics bytes.Buffer
		cmd.Stderr = &diagnostics
		object, err := cmd.Output()
		if err != nil {
			for _, m := range regexp.MustCompile(`(?m)<stdin>:(\d+):\d+: error: ([^\n]+)`).FindAllStringSubmatch(diagnostics.String(), -1) {
				ln, _ := strconv.Atoi(m[1])
				if n, ok := lineCases[ln]; ok {
					t.Logf("native format failure %d %s %x %q -> %q: %s", n, ids[n], cases[n].bytes, cases[n].text, rendered[n], m[2])
				}
			}
			t.Fatalf("native formatted corpus %s: %v\n%s", triple, err, diagnostics.String())
		}
		file, err := elf.NewFile(bytes.NewReader(object))
		if err != nil {
			t.Fatal(err)
		}
		for n, c := range cases {
			if c.triple != triple || actuals[n] != nil {
				continue
			}
			section := file.Section(fmt.Sprintf(".text.c%d", n))
			if section == nil {
				t.Fatal("missing native formatted sample", n)
			}
			data, err := section.Data()
			if err != nil {
				t.Fatal(err)
			}
			actuals[n] = data
		}
		file.Close()
	}
	for n, c := range cases {
		actual := actuals[n]
		if !bytes.Equal(actual, c.bytes) {
			if c.mode == "Arm" && equivalentARMModifiedImmediate(c.bytes, actual, c.endian == "Big") {
				aliases++
				continue
			}
			// ADR's ADD/SUB spellings can describe the same wrapping address,
			// including negative zero. The raw field round trip above stays exact.
			if c.mode == "Arm" && strings.HasPrefix(c.text, "adr") && equivalentARMADR(c.bytes, actual, c.endian == "Big") {
				aliases++
				continue
			}
			if c.mode == "Thumb" && strings.HasPrefix(rendered[n], "adr") && equivalentThumbADRZero(c.bytes, actual, c.endian == "Big") {
				aliases++
				continue
			}
			t.Errorf("LLVM %s %q rendered %q: %x != %x", c.triple, c.text, rendered[n], actual, c.bytes)
		}
	}
	t.Logf("LLVM MC: %d independent A32/Thumb16/Thumb32 raw byte and formatter comparisons, both byte orders, fresh full-corpus Rust generation; %d equivalent modified-immediate/ADR selections", len(cases), aliases)
}

// ADDW Rd, PC, #0 and SUBW Rd, PC, #0 have the same aligned PC target.
// The absolute-address presentation cannot preserve negative zero. Permit
// only these two complete zero-immediate words, with identical destination;
// the exact raw-field encode/decode comparison above still retains every bit.
func equivalentThumbADRZero(a, b []byte, big bool) bool {
	if len(a) != 4 || len(b) != 4 {
		return false
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if big {
		order = binary.BigEndian
	}
	word := func(data []byte) uint32 { return uint32(order.Uint16(data))<<16 | uint32(order.Uint16(data[2:])) }
	x, y := word(a), word(b)
	isZeroADR := func(w uint32) bool { return w&^uint32(0xf00) == 0xf20f0000 || w&^uint32(0xf00) == 0xf2af0000 }
	return isZeroADR(x) && isZeroADR(y) && x&0xf00 == y&0xf00
}

func TestThumbADRZeroAliasBoundary(t *testing.T) {
	for _, big := range []bool{false, true} {
		order := binary.ByteOrder(binary.LittleEndian)
		if big {
			order = binary.BigEndian
		}
		encode := func(word uint32) []byte {
			out := make([]byte, 4)
			order.PutUint16(out, uint16(word>>16))
			order.PutUint16(out[2:], uint16(word))
			return out
		}
		for _, tc := range []struct {
			x, y uint32
			want bool
		}{{0xf20f0100, 0xf2af0100, true}, {0xf20f0100, 0xf2af0200, false}, {0xf20f0100, 0xf2af0101, false}, {0xf20f0100, 0xf20e0100, false}, {0xf20f0100, 0xf24f0100, false}} {
			if got := equivalentThumbADRZero(encode(tc.x), encode(tc.y), big); got != tc.want {
				t.Fatalf("big=%t %08x %08x: %t", big, tc.x, tc.y, got)
			}
		}
		if equivalentThumbADRZero(encode(0xf20f0100)[:2], encode(0xf2af0100), big) {
			t.Fatal("accepted a different instruction width")
		}
	}
}

func equivalentARMADR(a, b []byte, big bool) bool {
	if len(a) != 4 || len(b) != 4 {
		return false
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if big {
		order = binary.BigEndian
	}
	x, y := order.Uint32(a), order.Uint32(b)
	// Only ADD/SUB immediate with PC as input, S=0, identical condition/Rd.
	isADR := func(w uint32) bool { return w&0x0fff0000 == 0x028f0000 || w&0x0fff0000 == 0x024f0000 }
	delta := func(w uint32) uint32 {
		v := bits.RotateLeft32(w&255, -int(w>>8&15)*2)
		if w&0x00f00000 == 0x00400000 {
			return -v
		}
		return v
	}
	return isADR(x) && isADR(y) && x&0xf000f000 == y&0xf000f000 && delta(x) == delta(y)
}

// A32's modified immediate can have several physical representations of the
// same value (e.g. #40, #2 and #10). Both byte strings here were independently
// assembled by LLVM. Only the immediate rotation is normalized; opcode,
// condition, registers and flags must remain bit-identical.
func equivalentARMModifiedImmediate(a, b []byte, big bool) bool {
	if len(a) != 4 || len(b) != 4 {
		return false
	}
	order := binary.ByteOrder(binary.LittleEndian)
	if big {
		order = binary.BigEndian
	}
	x, y := order.Uint32(a), order.Uint32(b)
	if x&0x0e000000 != 0x02000000 || x&^uint32(0xfff) != y&^uint32(0xfff) {
		return false
	}
	expand := func(w uint32) uint32 { return bits.RotateLeft32(w&255, -int((w>>8&15)*2)) }
	return expand(x) == expand(y)
}

func rustReferenceBytes(data []byte) string {
	var out strings.Builder
	out.WriteByte('[')
	for _, b := range data {
		fmt.Fprintf(&out, "%d,", b)
	}
	out.WriteByte(']')
	return out.String()
}
