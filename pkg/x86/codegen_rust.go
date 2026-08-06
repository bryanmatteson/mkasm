package x86

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	assettemplates "github.com/bryanmatteson/mkasm/templates"
)

type rustCodegenData struct {
	Encodings  string
	Tails      string
	Operands   string
	Buckets    string
	Candidates string
}

// GenerateRust emits a standalone, dependency-free x86 codec crate.
func GenerateRust(catalog *Catalog, outputDir string) error {
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
	tmpl, err := template.New("x86-rust").ParseFS(assettemplates.FS, "x86_rust/*.tmpl")
	if err != nil {
		return fmt.Errorf("parse x86 rust templates: %w", err)
	}
	data := buildRustCodegenData(catalog, decoder)
	if err := executeRustTemplate(tmpl, "cargo.toml.tmpl", filepath.Join(outputDir, "Cargo.toml"), nil); err != nil {
		return err
	}
	if err := executeRustTemplate(tmpl, "lib.rs.tmpl", filepath.Join(srcDir, "lib.rs"), data); err != nil {
		return err
	}
	examplesDir := filepath.Join(outputDir, "examples")
	if err := os.MkdirAll(examplesDir, 0o755); err != nil {
		return err
	}
	if err := executeRustTemplate(tmpl, "decode_bench.rs.tmpl", filepath.Join(examplesDir, "decode_bench.rs"), nil); err != nil {
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
	var encodings, tails, operands, buckets, candidates strings.Builder
	tailOffset := 0
	operandOffset := 0
	for _, e := range catalog.Encodings {
		fmt.Fprintf(&encodings, "    Encoding { id: %s, form_id: %s, mnemonic: %s, syntax: %s, flow_control: FlowControl::%s, kind: %d, map: %d, opcode: 0x%02x, opcode_plus_reg: %t, mandatory: %d, prefix_mask: %d, prefix_value: %d, modes: %d, w: %d, operand_size: %d, vector_length: %d, tuple: %s, has_modrm: %t, mod_kind: %d, reg_mask: %d, reg_value: %d, rm_mask: %d, rm_value: %d, tail_start: %d, tail_len: %d, operand_start: %d, operand_len: %d },\n",
			rustString(e.ID), rustString(e.FormID), rustString(e.Mnemonic), rustString(e.Syntax),
			classifyFlowControl(e),
			e.Kind, e.Map, e.Opcode, e.OpcodePlusReg, e.MandatoryPrefix,
			e.PrefixMask, e.PrefixValue, e.Modes, e.W, e.OperandSize, e.VectorLength, rustString(e.Tuple),
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
			fmt.Fprintf(&operands, "    OperandSpec { kind: %s, symbol: %s, encoded_in: %s, data_type: %s, size: %s, value: %s, flags: %d },\n",
				rustString(operand.Type), rustString(operand.Symbol), rustString(operand.EncodedIn),
				rustString(operand.DataType), rustString(operand.Size), rustString(operand.Value), flags)
			operandOffset++
		}
	}
	for _, bucket := range decoder.buckets {
		fmt.Fprintf(&buckets, "    Bucket { start: %d, count: %d },\n", bucket.start, bucket.count)
	}
	for _, candidate := range decoder.candidates {
		fmt.Fprintf(&candidates, "    %d,\n", candidate)
	}
	return rustCodegenData{
		Encodings: encodings.String(), Tails: tails.String(), Operands: operands.String(),
		Buckets: buckets.String(), Candidates: candidates.String(),
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
