package x86

import (
	"fmt"
	objectapi "github.com/bryanmatteson/mkasm/pkg/object"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/bryanmatteson/mkasm/pkg/semantics"
	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

type rustCodegenData struct {
	DefaultMode           string
	CrateName             string
	Encodings             string
	TextMnemonics         string
	TextMnemonicIndexType string
	Tails                 string
	Operands              string
	Buckets               string
	Candidates            string
}

// GenerateRust emits a standalone, dependency-free x86 codec crate.
func GenerateRust(catalog *Catalog, outputDir string) error {
	return GenerateRustForMode(catalog, outputDir, Mode64)
}

// GenerateRustForMode selects the generated crate's default execution mode.
// Every generated crate retains the explicit APIs for all three execution modes.
func GenerateRustForMode(catalog *Catalog, outputDir string, mode Mode) (generationError error) {
	defer func() {
		if generationError == nil {
			generationError = objectapi.InstallRust(outputDir)
		}
	}()

	if mode != Mode16 && mode != Mode32 && mode != Mode64 {
		return fmt.Errorf("x86 rust codegen: invalid default mode %d", mode)
	}
	decoder, err := NewDecoder(catalog)
	if err != nil {
		return fmt.Errorf("x86 rust codegen: %w", err)
	}
	if outputDir == "" {
		return fmt.Errorf("x86 rust codegen: empty output directory")
	}
	srcDir := filepath.Join(outputDir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		return err
	}
	if err := writeXEDFP16License(catalog, outputDir); err != nil {
		return err
	}
	if err := writeXEDIntegerLicense(catalog, outputDir); err != nil {
		return err
	}
	tmpl, err := template.New("x86-rust").ParseFS(assettemplates.FS, "x86_rust/*.tmpl", "rust/number_text.rs.tmpl")
	if err != nil {
		return fmt.Errorf("parse x86 rust templates: %w", err)
	}
	data := buildRustCodegenData(catalog, decoder)
	data.DefaultMode = fmt.Sprintf("Mode%d", mode)
	data.CrateName = fmt.Sprintf("x86_%d", mode)
	if err := executeRustTemplate(tmpl, "cargo.toml.tmpl", filepath.Join(outputDir, "Cargo.toml"), data); err != nil {
		return err
	}
	if err := executeRustTemplate(tmpl, "lib.rs.tmpl", filepath.Join(srcDir, "lib.rs"), data); err != nil {
		return err
	}
	if err := executeRustTemplate(tmpl, "assemble.rs.tmpl", filepath.Join(srcDir, "assemble.rs"), data); err != nil {
		return err
	}
	if err := executeRustTemplate(tmpl, "block_relocation.rs.tmpl", filepath.Join(srcDir, "block_relocation.rs"), data); err != nil {
		return err
	}
	if err := executeRustTemplate(tmpl, "effects.rs.tmpl", filepath.Join(srcDir, "effects.rs"), rustEffectsData(catalog)); err != nil {
		return err
	}
	if err := writeRustRequirements(srcDir, catalog); err != nil {
		return err
	}
	if err := semantics.WriteRust(srcDir); err != nil {
		return err
	}
	if err := executeRustTemplate(tmpl, "recipes.rs.tmpl", filepath.Join(srcDir, "recipes.rs"), data); err != nil {
		return err
	}

	examplesDir := filepath.Join(outputDir, "examples")
	if err := os.MkdirAll(examplesDir, 0o755); err != nil {
		return err
	}
	if err := executeRustTemplate(tmpl, "decode_bench.rs.tmpl", filepath.Join(examplesDir, "decode_bench.rs"), data); err != nil {
		return err
	}
	if err := executeRustTemplate(tmpl, "asm_check.rs.tmpl", filepath.Join(examplesDir, "asm_check.rs"), data); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outputDir, "LICENSE"), []byte(`MIT License

Copyright (c) 2026 Bryan Matteson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE.
`), 0o644)
}

func buildRustCodegenData(catalog *Catalog, decoder *Decoder) rustCodegenData {
	var encodings, tails, operands, buckets, candidates, textMnemonics strings.Builder
	textIndices := make(map[string]int)
	tailOffset := 0
	operandOffset := 0
	for _, e := range catalog.Encodings {
		text := asciiMnemonic(e.Mnemonic)
		textIndex, exists := textIndices[text]
		if !exists {
			textIndex = len(textIndices)
			textIndices[text] = textIndex
			fmt.Fprintf(&textMnemonics, "%s,\n", rustString(text))
		}
		fmt.Fprintf(&encodings, "    Encoding { id: %s, form_id: %s, mnemonic: %s, text_mnemonic: %d, text_flags: %d, syntax: %s, flow_control: FlowControl::%s, kind: %d, map: %d, opcode: 0x%02x, opcode_plus_reg: %t, mandatory: %d, prefix_mask: %d, prefix_value: %d, modes: %d, w: %d, operand_size: %d, vector_length: %d, reserved_vvvv: %d, evex_mask: %d, evex_value: %d, no_source_dest_match: %t, vector_length_ignored: %t, embedded_rounding: %t, suppress_exceptions: %t, tuple: %s, has_modrm: %t, mod_kind: %d, reg_mask: %d, reg_value: %d, rm_mask: %d, rm_value: %d, tail_start: %d, tail_len: %d, operand_start: %d, operand_len: %d },\n",
			rustString(e.ID), rustString(e.FormID), rustString(e.Mnemonic), textIndex, rustDisplayFlags(e), rustString(e.Syntax),
			classifyFlowControl(e),
			e.Kind, e.Map, e.Opcode, e.OpcodePlusReg, e.MandatoryPrefix,
			e.PrefixMask, e.PrefixValue, e.Modes, e.W, e.OperandSize, e.VectorLength, e.ReservedVVVV, e.EVEXMask, e.EVEXValue, e.NoSourceDestMatch, e.VectorLengthIgnored, e.EmbeddedRounding, e.SuppressExceptions, rustString(e.Tuple),
			e.HasModRM, e.Mod, e.RegMask, e.RegValue, e.RMMask, e.RMValue,
			tailOffset, len(e.Tail), operandOffset, len(e.Operands))
		for _, tail := range e.Tail {
			fmt.Fprintf(&tails, "    %d,\n", tail)
			tailOffset++
		}
		for _, operand := range e.Operands {
			flags := 0
			if operand.Read {
				flags |= 1
			}
			if operand.Write {
				flags |= 2
			}
			if operand.Suppressed {
				flags |= 4
			}
			if operand.Zeroing {
				flags |= 8
			}
			if operand.ConditionalRead {
				flags |= 16
			}
			if operand.ConditionalWrite {
				flags |= 32
			}
			// Suppressed ASZ memory operands (including MASKMOV's DIa) do
			// not use the instruction's ModRM address. Retain their base.
			implicitBase := 0
			if operand.Suppressed && operand.Type == "MEM" {
				for _, address := range operand.AddressRegisters {
					if address.EncodedIn == "ASZ" {
						switch address.Symbol {
						case "BXa":
							implicitBase = 4
						case "SIa":
							implicitBase = 7
						case "DIa":
							implicitBase = 8
						}
					}
				}
			}
			fmt.Fprintf(&operands, "    OperandSpec { kind: %s, symbol: %s, encoded_in: %s, data_type: %s, size: %s, value: %s, flags: %d, implicit_base: %d },\n",
				rustString(operand.Type), rustString(operand.Symbol), rustString(operand.EncodedIn),
				rustString(operand.DataType), rustString(operand.Size), rustString(operand.Value), flags, implicitBase)
			operandOffset++
		}
	}
	for _, bucket := range decoder.buckets {
		fmt.Fprintf(&buckets, "    Bucket { start: %d, count: %d },\n", bucket.start, bucket.count)
	}
	// Resolve specificity at generation time. The runtime still counts every
	// match for Alternatives, but the first match is already the preferred form.
	ordered := append([]uint32(nil), decoder.candidates...)
	for _, bucket := range decoder.buckets {
		ids := ordered[int(bucket.start) : int(bucket.start)+int(bucket.count)]
		sort.SliceStable(ids, func(i, j int) bool {
			return encodingSpecificity(&catalog.Encodings[ids[i]]) > encodingSpecificity(&catalog.Encodings[ids[j]])
		})
	}
	for _, candidate := range ordered {
		fmt.Fprintf(&candidates, "    %d,\n", candidate)
	}
	return rustCodegenData{
		Encodings: encodings.String(), Tails: tails.String(), Operands: operands.String(),
		Buckets: buckets.String(), Candidates: candidates.String(),
		TextMnemonics:         textMnemonics.String(),
		TextMnemonicIndexType: rustMnemonicIndexType(len(textIndices)),
	}
}

func classifyFlowControl(encoding Encoding) string {
	mnemonic := strings.ToUpper(encoding.Mnemonic)
	direct := false
	for _, operand := range encoding.Operands {
		if operand.Suppressed {
			continue
		}
		direct = operand.Type == "REL" || operand.Type == "PTR"
		break
	}
	switch mnemonic {
	case "CALL", "SYSCALL", "SYSENTER", "VMCALL", "VMLAUNCH", "VMRESUME", "VMMCALL", "VMRUN":
		if direct {
			return "Call"
		}
		if mnemonic == "CALL" {
			return "IndirectCall"
		}
		return "Call"
	case "JMP":
		if direct {
			return "UnconditionalBranch"
		}
		return "IndirectBranch"
	case "RET", "RETF", "IRET", "IRETD", "IRETQ", "RSM", "SKINIT", "SYSEXIT", "SYSRET":
		return "Return"
	case "INT", "INT1", "INT3", "INTO":
		return "Interrupt"
	case "UD0", "UD1", "UD2":
		return "Exception"
	case "XBEGIN":
		return "Transactional"
	case "JCXZ", "JECXZ", "JRCXZ", "LOOP", "LOOPE", "LOOPNE", "LOOPNZ", "LOOPZ":
		return "ConditionalBranch"
	}
	if strings.HasPrefix(mnemonic, "J") {
		return "ConditionalBranch"
	}
	return "Next"
}

func executeRustTemplate(tmpl *template.Template, name, path string, data any) error {
	var output strings.Builder
	if err := tmpl.ExecuteTemplate(&output, name, data); err != nil {
		return fmt.Errorf("execute %s: %w", name, err)
	}
	return os.WriteFile(path, []byte(output.String()), 0o644)
}

func rustString(s string) string {
	return fmt.Sprintf("%q", s)
}

// Use existing metadata padding for ordinary catalogs, without imposing a
// limit on imported mnemonic sets.
func rustMnemonicIndexType(count int) string {
	if count <= 1<<16 {
		return "u16"
	}
	return "u32"
}

func asciiMnemonic(text string) string {
	bytes := []byte(text)
	for i, b := range bytes {
		if b >= 'A' && b <= 'Z' {
			bytes[i] = b + ('a' - 'A')
		}
	}
	return string(bytes)
}

// Flags describe immutable formatter behavior; physical aliases still use
// the original mode/prefix-dependent logic in display_mnemonic.
func rustTextFlags(e Encoding) uint8 {
	var flags uint8
	repeatable := false
	if e.Map == 0 {
		switch e.Mnemonic {
		case "CMPSB", "CMPSW", "CMPSD", "CMPSQ", "SCASB", "SCASW", "SCASD", "SCASQ",
			"MOVSB", "MOVSW", "MOVSD", "MOVSQ", "LODSB", "LODSW", "LODSD", "LODSQ",
			"STOSB", "STOSW", "STOSD", "STOSQ", "INSB", "INSW", "INSD", "OUTSB", "OUTSW", "OUTSD":
			repeatable = true
		}
	}
	if repeatable {
		flags |= 1
	}
	if e.Kind == 0 && (e.MandatoryPrefix == 0 || repeatable || strings.HasPrefix(e.Mnemonic, "XCRYPT") || e.Mnemonic == "XSHA1" || e.Mnemonic == "XSHA256" || e.Mnemonic == "XSTORE") {
		flags |= 2
	}
	if strings.Contains(e.Mnemonic, "GATHER") || strings.Contains(e.Mnemonic, "SCATTER") {
		flags |= 4
	}
	dynamic := false
	if e.Kind == 0 && e.Map == 1 {
		switch e.Opcode {
		case 0x18, 0x1e, 0x0d, 0x07:
			dynamic = true
		}
	}
	if e.Kind == 0 && e.Map == 0 {
		switch e.Opcode {
		case 0x60, 0x61, 0x98, 0x99, 0xcf, 0xe3, 0xe1, 0xe0, 0xcb, 0xca:
			dynamic = true
		}
	}
	switch e.Mnemonic {
	case "PCMPESTRI", "PCMPESTRM", "VPCMPESTRI", "VPCMPESTRM", "KMOVW", "FDISI8087_NOP", "FENI8087_NOP", "FSETPM287_NOP", "XCRYPT_CBC", "XCRYPT_CFB", "XCRYPT_CTR", "XCRYPT_ECB", "XCRYPT_OFB":
		dynamic = true
	}
	if dynamic {
		flags |= 8
	}
	return flags
}

// Operand presentation rules depend on the immutable form, except for the
// explicit physical-mode checks retained in the renderer.
func rustOperandTextFlags(e Encoding) uint8 {
	var flags uint8
	switch e.Mnemonic {
	case "CALL", "JMP", "PUSH", "POP":
		flags |= 1
	}
	switch e.Mnemonic {
	case "TPAUSE", "UMWAIT":
		flags |= 2
	}
	switch e.Mnemonic {
	case "CLZERO", "INVLPGA", "VMLOAD", "VMRUN", "VMSAVE":
		flags |= 4
	}
	switch e.Mnemonic {
	case "LEA", "BNDCL", "BNDCN", "BNDCU", "BNDMK":
		flags |= 8
	}
	switch e.Mnemonic {
	case "FLDENV", "FNSTENV":
		flags |= 16
	case "FRSTOR", "FNSAVE":
		flags |= 32
	}
	if e.Map == 1 && e.Opcode == 0x18 {
		flags |= 64
	}
	if e.Map == 0 && e.Opcode == 0xff && (e.RegValue == 3 || e.RegValue == 5) {
		flags |= 128
	}
	return flags
}
func rustMemoryTextSize(e Encoding) uint8 {
	switch e.Mnemonic {
	case "INVLPG", "CLDEMOTE":
		return 0
	case "LGDT", "LIDT", "SGDT", "SIDT", "LDS", "LES", "LFS", "LGS", "LSS":
		return 48
	case "CLFLUSH", "CLFLUSHOPT", "CLWB":
		return 8
	}
	return 255
}

// Keep all immutable presentation metadata in one word. The original mnemonic
// flags occupy bits 0..3, operand flags 4..11 the memory-size selector 12..13, and special instruction guards 14..15.
func rustDisplayFlags(e Encoding) uint16 {
	var memory uint16
	switch rustMemoryTextSize(e) {
	case 0:
		memory = 1
	case 8:
		memory = 2
	case 48:
		memory = 3
	}
	flags := uint16(rustTextFlags(e)) | uint16(rustOperandTextFlags(e))<<4 | memory<<12
	if strings.HasPrefix(strings.ToUpper(e.Mnemonic), "RDSSP") || e.Kind == 0 && e.Map == 1 && e.Opcode == 0x1e {
		flags |= 0x4000
	}
	if strings.EqualFold(e.Mnemonic, "XLAT") {
		flags |= 0x8000
	}
	return flags
}
