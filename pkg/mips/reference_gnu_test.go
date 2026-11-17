package mips

import (
	"bytes"
	"debug/elf"
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

// LLVM has no microMIPS64 backend and GNU rejects microMIPS with MIPS64r6.
// These selectors combine the microMIPS physical instruction set with a 64-bit
// address context. Compare physical forms against LLVM's actual microMIPS32
// assembler and GNU for five incorrect LLVM DSP records. Separately check GNU's
// real ELF64 microMIPS ABI.
// The reference target is explicit: this does not claim an LLVM64 ISA backend.
func TestIndependentMicroMIPS64Corpus(t *testing.T) {
	arch := os.Getenv("MKASM_MIPS_AUDIT_ARCH")
	if arch != "micromips64" && arch != "micromips64el" {
		t.Skip("set MKASM_MIPS_AUDIT_ARCH to micromips64 or micromips64el")
	}
	reference := strings.Replace(arch, "64", "32", 1)
	t.Logf("physical instruction reference: LLVM %s; target execution context: %s", reference, arch)
	verifyLLVMWholeCorpus(t, arch, reference)
	as := os.Getenv("MKASM_MIPS_AS")
	if as == "" {
		t.Skip("set MKASM_MIPS_AS to GNU MIPS assembler")
	}
	c := corpus(t, arch)
	texts := []string{"addiu $2, $2, 257", "lw $2, 132($3)", "sw $4, 256($sp)", "andi $2, $2, 65534", "lbu $2, -1($3)", "lhu $2, 30($3)", "lw $2, 60($3)", "sb $2, 15($3)", "sh $2, 30($3)", "sw $2, 60($3)", "jr16 $31", "nop"}
	for _, text := range texts {
		data := assembleGNUReference(t, as, arch, text, false)
		candidates, err := c.Assemble(text, 0)
		if err != nil || !containsBytes(candidates, data) {
			t.Fatalf("GNU ELF64 %q: got %x reference %x: %v", text, candidates, data, err)
		}
	}
	t.Logf("GNU ELF64 microMIPS ABI: %d actual assembler vectors", len(texts))
	verifyGNU64SourceCorpus(t, as, arch, c)
}

func verifyGNU64SourceCorpus(t *testing.T, as, arch string, c *codec.Catalog) {
	t.Helper()
	type sample struct {
		id, text string
		data     []byte
	}
	var cases []sample
	r6, derived, physicalOnly := 0, 0, 0
	for _, e := range c.Encodings {
		if e.AssemblyOnly && (strings.HasSuffix(e.ID, "_commuted") || strings.HasSuffix(e.ID, "_generic_spelling")) {
			derived++
			continue
		}
		if has(e.Features, "HasMips32r6") || has(e.Features, "HasMips64r6") {
			r6++
			continue
		}
		if e.ID == "BPOSGE32C_MMR3" {
			physicalOnly++
			continue
		} // GNU has no DSPR3 compact branch in either ABI.
		values := referenceOperands(e)
		data, err := codec.Encode(&e, values)
		if err != nil {
			t.Fatal(e.ID, err)
		}
		text := (&codec.Decoded{Encoding: &e, Values: values, Length: len(data)}).Format(0)
		// GNU's move alias may select OR or a short instruction. Spell the
		// actual DADDU machine operation for this primary 64-bit alias row.
		if e.ID == "GNU_MICRO64_ROW_0015" {
			text = strings.Replace(text, "move ", "daddu ", 1) + ", $0"
		}
		if e.ID == "RDHWR_MM" {
			text = strings.TrimSuffix(text, ", 0")
		}
		if e.ID == "SWSP_MM" {
			text = strings.Replace(text, "swsp ", "sw ", 1)
		}
		if strings.HasPrefix(e.ID, "anonymous_") && strings.HasPrefix(text, "wrdsp ") && !strings.Contains(text, ",") {
			text += ", 31"
		}
		for _, o := range e.Operands {
			if o.Relative && o.PCRegionBits == 0 {
				text = strings.ReplaceAll(text, fmt.Sprintf("0x%x", uint64(o.PCBias)+uint64(values[o.Name])), fmt.Sprintf(".+(%d)", o.PCBias+values[o.Name]))
			}
		}
		cases = append(cases, sample{e.ID, text, data})
	}
	dir := t.TempDir()
	object := filepath.Join(dir, "native64.o")
	endian := "-EB"
	if strings.HasSuffix(arch, "el") {
		endian = "-EL"
	}
	rejected := map[int]string{}
	for attempt := 0; attempt < 3; attempt++ {
		var source strings.Builder
		source.WriteString(".set noreorder\n.set noat\n")
		lines := map[int]int{}
		line := 2
		for n, s := range cases {
			if _, ok := rejected[n]; ok {
				continue
			}
			state := ".set insn32"
			if len(s.data) == 2 || s.id == "BGEZALS_MM" || s.id == "BLTZALS_MM" || s.id == "JALRS_MM" || s.id == "JALS_MM" {
				state = ".set noinsn32"
			}
			fmt.Fprintf(&source, ".section .text.c%d,\"ax\",@progbits\n%s\n.globl c%d,end%d\nc%d:\n%s\nend%d:\n", n, state, n, n, n, s.text, n)
			lines[line+5] = n
			line += 6
		}
		cmd := exec.Command(as, "-64", endian, "-march=mips64r5", "-mmicromips", "-mdspr3", "-mmsa", "-mmt", "-mvirt", "-mxpa", "-meva", "-O0", "-o", object)
		cmd.Stdin = strings.NewReader(source.String())
		out, err := cmd.CombinedOutput()
		if err == nil {
			break
		}
		found := 0
		for _, m := range regexp.MustCompile(`(?m)^[^\n]*:(\d+): Error: ([^\n]+)`).FindAllStringSubmatch(string(out), -1) {
			ln, _ := strconv.Atoi(m[1])
			n, ok := lines[ln]
			if !ok {
				continue
			}
			rejected[n] = m[2]
			found++
		}
		if found == 0 || attempt == 2 {
			t.Fatalf("GNU ELF64 corpus: %v\n%s", err, out)
		}
	}
	// microMIPS local branches retain ELF relocations even within a source
	// section. Resolve them with the real linker before comparing operands.
	linker := os.Getenv("MIPS64_LD")
	if linker == "" {
		t.Fatal("set MIPS64_LD to GNU ld with ELF64 microMIPS relocation support; LLD rejects this ABI")
	}
	linked := filepath.Join(dir, "native64.elf")
	var script strings.Builder
	script.WriteString("SECTIONS {\n")
	for n := range cases {
		fmt.Fprintf(&script, ".text.c%d : { *(.text.c%d) }\n", n, n)
	}
	script.WriteString("}\n")
	scriptPath := filepath.Join(dir, "native64.ld")
	if err := os.WriteFile(scriptPath, []byte(script.String()), 0644); err != nil {
		t.Fatal(err)
	}
	emulation := "elf64btsmip"
	if strings.HasSuffix(arch, "el") {
		emulation = "elf64ltsmip"
	}
	link := exec.Command(linker, "-m", emulation, "-T", scriptPath, "-e", "0", "-o", linked, object)
	if out, err := link.CombinedOutput(); err != nil {
		t.Fatalf("native ELF64 linker: %v\n%s", err, out)
	}
	file, err := elf.Open(linked)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 {
		t.Fatal("native corpus did not use ELF64")
	}
	symbols, err := file.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	ends := map[string]uint64{}
	for _, s := range symbols {
		ends[s.Name] = s.Value
	}
	matched := 0
	var vectors strings.Builder
	for n, s := range cases {
		if diagnostic, ok := rejected[n]; ok {
			t.Logf("GNU64 rejected %s %q: %s", s.id, s.text, diagnostic)
			continue
		}
		section := file.Section(fmt.Sprintf(".text.c%d", n))
		if section == nil {
			t.Fatal("missing native section", s.id)
		}
		data, err := section.Data()
		if err != nil {
			t.Fatal(err)
		}
		end := ends[fmt.Sprintf("end%d", n)] - section.Addr
		if end > uint64(len(data)) {
			t.Fatal("bad native extent", s.id)
		}
		data = data[:end]
		d, err := c.Decode(data)
		if err != nil {
			t.Fatalf("Go native ELF64 decode %s: %v", s.id, err)
		}
		repacked, err := codec.Encode(d.Encoding, d.Values)
		if err != nil || !bytes.Equal(repacked, data) {
			t.Fatalf("Go native ELF64 encode %s: %x != %x: %v", s.id, repacked, data, err)
		}
		fmt.Fprintf(&vectors, "%s\t%s\n", s.id, hex.EncodeToString(data))
		if !bytes.Equal(data, s.data) {
			all, err := c.Assemble(s.text, 0)
			if (strings.HasPrefix(s.id, "anonymous_") || strings.HasPrefix(s.id, "GNU_MICRO64_ROW_")) && err == nil && containsBytes(all, data) {
				matched++
				continue
			}
			t.Errorf("GNU ELF64 %s %q: Go %x GNU %x", s.id, s.text, s.data, data)
		} else {
			matched++
		}
	}
	if len(rejected) != 0 {
		t.Errorf("GNU ELF64 rejected %d/%d r5 corpus forms", len(rejected), len(cases))
	}
	verifyGNU64RustConsumer(t, arch, vectors.String())
	t.Logf("GNU actual linked ELF64: %d r5 source forms matched; %d r6 and %d DSPR3-only forms covered by the explicit LLVM physical-ISA reference; %d derived text variants", matched, r6, physicalOnly, derived)
}

func verifyGNU64RustConsumer(t *testing.T, arch, vectors string) {
	t.Helper()
	cli := os.Getenv("MKASM_REFERENCE_CLI")
	if cli == "" {
		t.Fatal("set MKASM_REFERENCE_CLI for fresh ELF64 Rust consumer")
	}
	output := os.Getenv("MKASM_MIPS64_REFERENCE_RUST")
	if output == "" {
		output = t.TempDir()
	} else {
		output = filepath.Join(output, arch)
	}
	cmd := exec.Command(cli, "--arch", arch, "--codegen", "rust", "--output", output, os.Getenv("MKASM_MIPS_TABLEGEN_JSON"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh CLI ELF64: %v\n%s", err, out)
	}
	if err := testreference.StandaloneRust(output); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "tests/native64.tsv"), []byte(vectors), 0644); err != nil {
		t.Fatal(err)
	}
	rust := fmt.Sprintf(`use %s::*;
#[test]fn native_elf64(){for line in include_str!("native64.tsv").lines(){
 let(id,hex)=line.split_once('\t').unwrap();let raw:Vec<u8>=(0..hex.len()).step_by(2).map(|i|u8::from_str_radix(&hex[i..i+2],16).unwrap()).collect();
 let d=decode(&raw).unwrap_or_else(|e|panic!("{id}: {e:?}"));assert_eq!(d.length,raw.len(),"{id}");
 let mut out=[0u8;4];let n=d.encode_into(&mut out).unwrap();assert_eq!(&out[..n],raw,"{id}");
}}
`, arch)
	if err := os.WriteFile(filepath.Join(output, "tests/native_elf64.rs"), []byte(rust), 0644); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("cargo", "test", "--test", "native_elf64")
	cmd.Dir = output
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh CLI Rust ELF64: %v\n%s", err, out)
	}
}

func assembleGNUReference(t *testing.T, as, arch, text string, force32 bool) []byte {
	t.Helper()
	endian, abi, cpu := "-EB", "-32", "mips32r5"
	if strings.HasSuffix(arch, "el") {
		endian = "-EL"
	}
	if strings.Contains(arch, "64") {
		abi = "-64"
		cpu = "mips64r5"
	}
	path := filepath.Join(t.TempDir(), "reference.o")
	state := ".set noinsn32\n"
	if force32 {
		state = ".set insn32\n"
	}
	cmd := exec.Command(as, abi, endian, "-march="+cpu, "-mmicromips", "-mdspr2", "-O0", "-o", path)
	cmd.Stdin = strings.NewReader(".text\n.set noreorder\n.set noat\n" + state + ".globl reference_begin,reference_end\nreference_begin:\n" + text + "\nreference_end:\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("GNU %s %q: %v\n%s", arch, text, err, out)
	}
	f, err := elf.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	expectedClass := elf.ELFCLASS32
	if abi == "-64" {
		expectedClass = elf.ELFCLASS64
	}
	if f.Class != expectedClass {
		t.Fatal("GNU emitted the wrong ELF ABI", f.Class)
	}
	data, err := f.Section(".text").Data()
	if err != nil {
		t.Fatal(err)
	}
	symbols, err := f.Symbols()
	if err != nil {
		t.Fatal(err)
	}
	var begin, end uint64
	for _, s := range symbols {
		if s.Name == "reference_begin" {
			begin = s.Value
		}
		if s.Name == "reference_end" {
			end = s.Value
		}
	}
	if end <= begin || end > uint64(len(data)) {
		t.Fatalf("GNU instruction extent: %d..%d", begin, end)
	}
	return data[begin:end]
}

func correctedMicroDSP(id string) bool {
	switch id {
	case "CMPGU_EQ_QB_MM", "CMPGU_LT_QB_MM", "CMPGU_LE_QB_MM", "SHLLV_PH_MM", "SHLLV_S_PH_MM":
		return true
	}
	return false
}
