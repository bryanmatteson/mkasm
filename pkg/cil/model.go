// Package cil imports .NET's public CIL instruction definitions and provides
// lossless instruction streams and ECMA-335 method-body codecs.
package cil

import (
	"encoding/json"
	"errors"
	"io"
)

const Schema = "mkasm.cil.v1"
const RuntimeRevision = "60629d14374c56f1cb51819049ad1fa529307f8d"

var ErrTruncated = errors.New("truncated CIL data")
var ErrMalformed = errors.New("malformed CIL data")
var ErrReserved = errors.New("reserved CIL opcode")
var ErrUnsupported = errors.New("unsupported CIL section")

type Catalog struct {
	Schema       string            `json:"schema"`
	Architecture string            `json:"architecture"`
	Source       string            `json:"source"`
	Definitions  []Definition      `json:"definitions"`
	Aliases      map[string]uint16 `json:"aliases"`
}
type Definition struct {
	ID          string `json:"id"`
	Opcode      uint16 `json:"opcode"`
	Mnemonic    string `json:"mnemonic"`
	Size        int    `json:"opcode_bytes"`
	Operand     string `json:"source_operand"`
	OperandKind string `json:"operand_kind"`
	Pop         string `json:"source_pop"`
	Push        string `json:"source_push"`
	PopCount    int    `json:"pop_count"`
	PushCount   int    `json:"push_count"`
	Kind        string `json:"source_kind"`
	Flow        string `json:"flow"`
	Prefix      bool   `json:"prefix,omitempty"`
}

// Operand stores branches and switch entries as displacements from the END of
// the entire instruction. Floating point values use exact IEEE bit patterns.
// Value holds signed integers, variable indices, metadata tokens or branches.
type Operand struct {
	Kind    string  `json:"kind"`
	Value   int64   `json:"value,omitempty"`
	Bits    uint64  `json:"bits,omitempty"`
	Targets []int32 `json:"targets,omitempty"`
}
type Instruction struct {
	Opcode   uint16   `json:"opcode"`
	Mnemonic string   `json:"mnemonic"`
	Offset   uint32   `json:"offset"`
	Length   int      `json:"length"`
	Operand  *Operand `json:"operand,omitempty"`
}
type ExceptionClause struct {
	Flags                    uint32 `json:"flags"` // 0 catch, 1 filter, 2 finally, 4 fault
	TryOffset                uint32 `json:"try_offset"`
	TryLength                uint32 `json:"try_length"`
	HandlerOffset            uint32 `json:"handler_offset"`
	HandlerLength            uint32 `json:"handler_length"`
	ClassTokenOrFilterOffset uint32 `json:"class_token_or_filter_offset"`
}
type ExceptionSection struct {
	Fat     bool              `json:"fat"`
	Clauses []ExceptionClause `json:"clauses"`
}
type MethodBody struct {
	Tiny                bool   `json:"tiny"`
	MaxStack            uint16 `json:"max_stack"`
	InitLocals          bool   `json:"init_locals"`
	LocalSignatureToken uint32 `json:"local_signature_token"`
	Code                []byte `json:"code"`
	// Instructions is authoritative when non-nil. Code is used otherwise.
	Instructions []Instruction      `json:"instructions"`
	Sections     []ExceptionSection `json:"sections,omitempty"`
	Padding      []byte             `json:"alignment_padding,omitempty"`
	Length       int                `json:"length"`
}

func (c *Catalog) WriteJSON(w io.Writer) error { return json.NewEncoder(w).Encode(c) }
func (c *Catalog) Definition(op uint16) *Definition {
	for i := range c.Definitions {
		if c.Definitions[i].Opcode == op {
			return &c.Definitions[i]
		}
	}
	return nil
}
func (c *Catalog) Lookup(name string) *Definition {
	for i := range c.Definitions {
		if c.Definitions[i].Mnemonic == name || c.Definitions[i].ID == name {
			return &c.Definitions[i]
		}
	}
	if op, ok := c.Aliases[name]; ok {
		return c.Definition(op)
	}
	return nil
}
