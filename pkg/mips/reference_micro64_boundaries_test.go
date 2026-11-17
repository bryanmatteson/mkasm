package mips

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/internal/testreference"
	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// The expected operand text comes from unmodified GNU decoder functions. Sweep
// every register/list/index value, integer boundary bits, and the full physical
// position/size product for each of GNU's ten 64-bit bitfield forms.
func TestIndependentGNUMicro64OperandBoundaries(t *testing.T) {
	oracle := os.Getenv("MKASM_MICRO64_ORACLE")
	as := os.Getenv("MKASM_MIPS_AS")
	cli := os.Getenv("MKASM_REFERENCE_CLI")
	if oracle == "" || cli == "" || as == "" {
		t.Skip("set MKASM_MICRO64_ORACLE, MKASM_MIPS_AS and MKASM_REFERENCE_CLI")
	}
	arch := os.Getenv("MKASM_MIPS_AUDIT_ARCH")
	if arch != "micromips64" && arch != "micromips64el" {
		t.Skip("set MKASM_MIPS_AUDIT_ARCH to a microMIPS64 byte order")
	}
	c := compressedCatalog(t, arch)
	type sample struct {
		e   codec.Encoding
		raw []byte
	}
	var cases []sample
	var request strings.Builder
	seen := map[string]bool{}
	for _, e := range c.Encodings {
		if !strings.HasPrefix(e.ID, "GNU_MICRO64_ROW_") {
			continue
		}
		base, err := codec.Encode(&e, referenceOperands(e))
		if err != nil {
			t.Fatal(e.ID, err)
		}
		add := func(raw []byte) {
			key := e.ID + hex.EncodeToString(raw)
			if seen[key] {
				return
			}
			seen[key] = true
			row, err := strconv.Atoi(strings.TrimPrefix(e.ID, "GNU_MICRO64_ROW_"))
			if err != nil {
				t.Fatal(err)
			}
			var order binary.ByteOrder = binary.BigEndian
			if strings.HasSuffix(arch, "el") {
				order = binary.LittleEndian
			}
			word := uint32(order.Uint16(raw[:2]))<<16 | uint32(order.Uint16(raw[2:]))
			fmt.Fprintf(&request, "%d %08x\n", row, word)
			cases = append(cases, sample{e, bytes.Clone(raw)})
		}
		put := func(raw []byte, o codec.Operand, n uint64) {
			for _, b := range o.Bits {
				for j := 0; j < b.Width; j++ {
					p := b.InstructionBit + j
					mask := byte(1 << uint(p%8))
					raw[p/8] = raw[p/8]&^mask | byte((n>>uint(b.ValueBit+j))&1)<<uint(p%8)
				}
			}
		}
		add(base)
		for _, o := range e.Operands {
			width := o.Width()
			max := uint64(1)<<uint(width) - 1
			values := []uint64{0, 1, max, max - 1}
			if width <= 6 {
				values = nil
				for v := uint64(0); v <= max; v++ {
					values = append(values, v)
				}
			} else {
				for b := 0; b < width; b++ {
					values = append(values, 1<<uint(b), (1<<uint(b))-1)
				}
			}
			for _, v := range values {
				raw := bytes.Clone(base)
				put(raw, o, v)
				add(raw)
			}
		}
		for _, o := range e.Operands {
			if o.Class != "GNU_MICRO64_msb" {
				continue
			}
			for _, pos := range e.Operands {
				if pos.Name != "op3" {
					continue
				}
				for p := uint64(0); p < 1<<uint(pos.Width()); p++ {
					for s := uint64(0); s < 1<<uint(o.Width()); s++ {
						raw := bytes.Clone(base)
						put(raw, pos, p)
						put(raw, o, s)
						add(raw)
					}
				}
			}
		}
	}
	cmd := exec.Command(oracle)
	cmd.Stdin = strings.NewReader(request.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("native GNU operand decoder: %v\n%s", err, out)
	}
	texts := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(texts) != len(cases) {
		t.Fatalf("native GNU produced %d/%d operands", len(texts), len(cases))
	}
	// Ask the actual assembler about every raw candidate, including those Go
	// might reject. Filtering candidates with our own decoder would conceal
	// false rejections and leave admission correctness untested.
	var nativeSource strings.Builder
	nativeSource.WriteString(".text\n.set noreorder\n.set noat\n.set insn32\n")
	for _, text := range texts {
		nativeSource.WriteString(text + "\n")
	}
	endian := "-EB"
	if strings.HasSuffix(arch, "el") {
		endian = "-EL"
	}
	cmd = exec.Command(as, "-64", endian, "-march=mips64r5", "-mmicromips", "-mdspr3", "-mmsa", "-mmt", "-mvirt", "-mxpa", "-meva", "-O0", "-o", filepath.Join(t.TempDir(), "native-boundaries.o"))
	cmd.Stdin = strings.NewReader(nativeSource.String())
	diagnostics, nativeErr := cmd.CombinedOutput()
	rejected := map[int]bool{}
	for _, match := range regexp.MustCompile(`(?m)^[^\n]*:(\d+): Error: ([^\n]+)`).FindAllStringSubmatch(string(diagnostics), -1) {
		line, _ := strconv.Atoi(match[1])
		index := line - 5
		if index < 0 || index >= len(cases) {
			t.Fatalf("unexpected GNU error: %s", match[0])
		}
		rejected[index] = true
	}
	if nativeErr != nil && len(rejected) == 0 {
		t.Fatalf("GNU boundary admission: %v\n%s", nativeErr, diagnostics)
	}
	var vectors strings.Builder
	var invalidVectors strings.Builder
	accepted := 0
	unpredictable := 0
	zeroSizeDINS := regexp.MustCompile(`^dins[mu]? \$[0-9]+,\$[0-9]+,0x[0-9a-f]+,0x0$`)
	for i, s := range cases {
		one := &codec.Catalog{Architecture: arch, Encodings: []codec.Encoding{s.e}}
		_, decodeErr := one.Decode(s.raw)
		// GNU 2.44's match_msb_operand tests size<0, admitting zero-size
		// DINS when pos>0. The microMIPS manual defines lsb>msb as
		// UNPREDICTABLE, so retain our rejection and account for this exact
		// native defect rather than silently widening the admitted domain.
		// ISA restriction: microMIPS Volume II-B, DINS/DINSU, MD00594.
		if zeroSizeDINS.MatchString(texts[i]) {
			if decodeErr == nil {
				t.Fatalf("Go admits UNPREDICTABLE zero-size insertion: %s", texts[i])
			}
			unpredictable++
			fmt.Fprintf(&invalidVectors, "%s\t%s\n", s.e.ID, texts[i])
			continue
		}
		if rejected[i] {
			if decodeErr == nil {
				t.Fatalf("Go admits native-invalid %s %x %q", s.e.ID, s.raw, texts[i])
			}
			fmt.Fprintf(&invalidVectors, "%s\t%s\n", s.e.ID, texts[i])
			continue
		}
		if decodeErr != nil {
			t.Fatalf("Go rejects native-valid %s %x %q: %v", s.e.ID, s.raw, texts[i], decodeErr)
		}
		all, err := one.Assemble(texts[i], 0)
		if err != nil || !containsBytes(all, s.raw) {
			t.Fatalf("%s GNU %q: Go %x, native word %x: %v", s.e.ID, texts[i], all, s.raw, err)
		}
		fmt.Fprintf(&vectors, "%s\t%x\t%s\n", s.e.ID, s.raw, texts[i])
		accepted++
	}
	output := os.Getenv("MKASM_MICRO64_BOUNDARY_RUST")
	if output == "" {
		output = t.TempDir()
	} else {
		output = filepath.Join(output, arch)
	}
	cmd = exec.Command(cli, "--arch", arch, "--codegen", "rust", "--output", output, os.Getenv("MKASM_MIPS_TABLEGEN_JSON"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CLI generation: %v\n%s", err, out)
	}
	if err := testreference.StandaloneRust(output); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "tests/gnu_operands.tsv"), []byte(vectors.String()), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "tests/gnu_invalid_operands.tsv"), []byte(invalidVectors.String()), 0644); err != nil {
		t.Fatal(err)
	}
	rust := fmt.Sprintf(`use %s::*;
#[test]fn native_gnu_operands(){let mut count=0;for line in include_str!("gnu_operands.tsv").lines(){
 let mut row=line.splitn(3,'\t');let id=row.next().unwrap();let hex=row.next().unwrap();let text=row.next().unwrap();
 let raw:Vec<u8>=(0..hex.len()).step_by(2).map(|i|u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect();
 let all=assemble_at(text,0).unwrap_or_else(|e|panic!("{id}: {text}: {e:?}"));assert!(all.iter().any(|b|*b==raw),"{id}: {text}");
 let d=decode(&raw).unwrap();let mut rebuilt=[0u8;4];let n=d.encode_into(&mut rebuilt).unwrap();assert_eq!(&rebuilt[..n],raw);count+=1;
}assert_eq!(count,%d);}
#[test]fn native_invalid_operands(){let mut count=0;for line in include_str!("gnu_invalid_operands.tsv").lines(){
 let (id,text)=line.split_once('\t').unwrap();assert!(assemble_at(text,0).is_err(),"{id}: admitted invalid {text}");count+=1;
}assert_eq!(count,%d);}
`, arch, accepted, len(rejected)+unpredictable)
	if err := os.WriteFile(filepath.Join(output, "tests/gnu_operands.rs"), []byte(rust), 0644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("cargo", "test", "--test", "gnu_operands", "--quiet")
	cmd.Dir = output
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh CLI Rust native GNU operands: %v\n%s", err, out)
	}
	t.Logf("%d native GNU operand boundary vectors passed Go and fresh CLI Rust; %d additional raw candidates independently rejected by GNU and Go; %d zero-size DINS patterns admitted by GNU but rejected as architecturally UNPREDICTABLE", accepted, len(rejected), unpredictable)
}

func TestIndependentGNUMicro64RejectedBitfields(t *testing.T) {
	as := os.Getenv("MKASM_MIPS_AS")
	if as == "" {
		t.Skip("set MKASM_MIPS_AS")
	}
	c := compressedCatalog(t, "micromips64el")
	for _, op := range []string{"dext", "dins"} {
		for _, args := range []string{"-1,1", "64,1", "0,0", "0,65", "63,2", "32,33"} {
			text := op + " $2,$3," + args
			if candidates, err := c.Assemble(text, 0); err == nil || len(candidates) != 0 {
				t.Fatal("Go admitted invalid bitfield", text)
			}
			cmd := exec.Command(as, "-64", "-EL", "-march=mips64r5", "-mmicromips", "-o", filepath.Join(t.TempDir(), "invalid.o"))
			cmd.Stdin = strings.NewReader(".text\n.set noreorder\n" + text + "\n")
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("GNU admitted invalid bitfield %s: %s", text, out)
			}
		}
	}
}
