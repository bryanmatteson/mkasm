package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"mkasm/pkg/arm"
	"mkasm/pkg/ir"
)

type jsonDocument struct {
	Schema       string            `json:"schema"`
	Architecture string            `json:"architecture"`
	Instructions []jsonInstruction `json:"instructions"`
}

type jsonInstruction struct {
	EncodingID  string        `json:"encoding_id"`
	Mnemonic    string        `json:"mnemonic"`
	AsmMnemonic string        `json:"asm_mnemonic,omitempty"`
	Class       string        `json:"class"`
	IFormFile   string        `json:"iform_file"`
	BitPattern  string        `json:"bit_pattern"`
	FixedWord   string        `json:"fixed_word,omitempty"`
	Asm         string        `json:"asm,omitempty"`
	AliasOf     string        `json:"alias_of,omitempty"`
	BitDiffs    string        `json:"bit_diffs,omitempty"`
	Fields      []jsonField   `json:"fields,omitempty"`
	Operands    []jsonOperand `json:"operands,omitempty"`
	Features    []string      `json:"features,omitempty"`
}

type jsonField struct {
	Name   string  `json:"name"`
	Start  int     `json:"start"`
	End    int     `json:"end"`
	Fixed  *uint64 `json:"fixed,omitempty"`
	Source string  `json:"source,omitempty"`
}

type jsonOperand struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"display_name,omitempty"`
	Type        ir.OperandType  `json:"type"`
	Usage       ir.OperandUsage `json:"usage"`
	Start       int             `json:"start"`
	End         int             `json:"end"`
}

func writeIRJSON(w io.Writer, registry *arm.InstructionRegistry) error {
	instructions := registry.GetAll()
	sort.Slice(instructions, func(i, j int) bool {
		return instructions[i].EncodingID < instructions[j].EncodingID
	})

	document := jsonDocument{
		Schema:       "mkasm.ir.v1",
		Architecture: string(arm.ArchAArch64),
		Instructions: make([]jsonInstruction, 0, len(instructions)),
	}
	for _, instruction := range instructions {
		if instruction == nil {
			continue
		}
		item := jsonInstruction{
			EncodingID:  instruction.EncodingID,
			Mnemonic:    instruction.Mnemonic,
			AsmMnemonic: instruction.AsmMnemonic,
			Class:       instruction.IClass,
			IFormFile:   instruction.IFormFile,
			BitPattern:  instruction.BitPattern,
			Asm:         instruction.Asm.Raw,
			AliasOf:     instruction.AliasOf,
			BitDiffs:    instruction.BitDiffs,
			Fields:      make([]jsonField, 0, len(instruction.Encoding.Fields)),
			Operands:    make([]jsonOperand, 0, len(instruction.Operands)),
			Features:    make([]string, 0, len(instruction.Features.Tags)),
		}
		if word, ok := ir.FixedWord(instruction); ok {
			item.FixedWord = fmt.Sprintf("0x%08X", word)
		}
		for _, field := range instruction.Encoding.Fields {
			item.Fields = append(item.Fields, jsonField{
				Name: field.Name, Start: field.Start, End: field.End,
				Fixed: field.Fixed, Source: field.Source,
			})
		}
		for _, operand := range instruction.Operands {
			item.Operands = append(item.Operands, jsonOperand{
				Name: operand.Name, DisplayName: operand.DisplayName,
				Type: operand.Type, Usage: operand.Usage,
				Start: operand.BitRange.Start, End: operand.BitRange.End,
			})
		}
		for _, feature := range instruction.Features.Tags {
			item.Features = append(item.Features, feature.Name)
		}
		document.Instructions = append(document.Instructions, item)
	}

	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(document)
}
