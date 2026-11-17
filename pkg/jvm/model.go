// Package jvm imports OpenJDK's complete Java bytecode definitions and encodes
// class-file instruction streams. It does not perform JVM type/stack verification.
package jvm

import (
	"encoding/json"
	"errors"
	"io"
)

const Schema = "mkasm.jvm.v1"

var ErrTruncated = errors.New("truncated JVM instruction")
var ErrMalformed = errors.New("malformed JVM instruction")
var ErrReserved = errors.New("reserved JVM opcode")

type Catalog struct {
	Schema       string       `json:"schema"`
	Architecture string       `json:"architecture"`
	Source       string       `json:"source"`
	Instructions []Definition `json:"instructions"`
}
type Definition struct {
	Opcode     byte                `json:"opcode"`
	Mnemonic   string              `json:"mnemonic"`
	Format     string              `json:"source_format"`
	WideFormat string              `json:"source_wide_format,omitempty"`
	Operands   []OperandDefinition `json:"operands,omitempty"`
	Reserved   bool                `json:"reserved,omitempty"`
}
type OperandDefinition struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Bytes  int    `json:"bytes"`
	Signed bool   `json:"signed,omitempty"`
}
type Operand struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Value int64  `json:"value"`
}

// Instruction stores branch operands and switch targets as signed displacements
// from the instruction's opcode. Wide is one instruction, including its prefix.
type Instruction struct {
	Opcode   byte      `json:"opcode"`
	Mnemonic string    `json:"mnemonic"`
	Offset   uint32    `json:"offset"`
	Length   int       `json:"length"`
	Wide     bool      `json:"wide,omitempty"`
	Operands []Operand `json:"operands,omitempty"`
	Switch   *Switch   `json:"switch,omitempty"`
}
type Switch struct {
	Default int32        `json:"default"`
	Low     int32        `json:"low,omitempty"`
	Targets []int32      `json:"targets,omitempty"`
	Pairs   []LookupPair `json:"pairs,omitempty"`
}
type LookupPair struct {
	Match  int32 `json:"match"`
	Target int32 `json:"target"`
}

func (c *Catalog) WriteJSON(w io.Writer) error { return json.NewEncoder(w).Encode(c) }
func (c *Catalog) definition(op byte) *Definition {
	for i := range c.Instructions {
		if c.Instructions[i].Opcode == op {
			return &c.Instructions[i]
		}
	}
	return nil
}
