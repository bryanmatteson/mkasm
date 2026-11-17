// Package dex imports AOSP's Dalvik opcode definitions and implements standard
// DEX instruction streams. Offsets and branch displacements use 16-bit code units.
package dex

import (
	"encoding/json"
	"errors"
	"io"
)

const Schema = "mkasm.dex.v1"
const LatestVersion = 41

var ErrTruncated = errors.New("truncated DEX instruction")
var ErrMalformed = errors.New("malformed DEX instruction")
var ErrReserved = errors.New("reserved DEX opcode")
var ErrVersion = errors.New("DEX opcode requires a newer version")

type Catalog struct {
	Schema       string       `json:"schema"`
	Architecture string       `json:"architecture"`
	Source       string       `json:"source"`
	Instructions []Definition `json:"instructions"`
}
type Definition struct {
	Opcode     uint16  `json:"opcode"`
	Mnemonic   string  `json:"mnemonic"`
	Format     string  `json:"format"`
	IndexKind  string  `json:"index_kind,omitempty"`
	Flags      string  `json:"flags"`
	Verify     string  `json:"verify"`
	MinVersion int     `json:"min_version"`
	Reserved   bool    `json:"reserved,omitempty"`
	Fields     []Field `json:"fields,omitempty"`
}
type Field struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Bit    int    `json:"bit"`
	Width  int    `json:"width"`
	Signed bool   `json:"signed,omitempty"`
	Shift  int    `json:"shift,omitempty"`
	Wide   bool   `json:"wide,omitempty"`
}

// Instruction scalar values are named by Definition.Fields. Registers holds
// explicit invoke arguments. Range holds invoke-range arguments. Branch targets
// remain signed displacements from the instruction, in code units. Length is bytes.
type Instruction struct {
	Opcode    uint16           `json:"opcode"`
	Mnemonic  string           `json:"mnemonic"`
	Offset    uint32           `json:"offset"`
	Length    int              `json:"length"`
	Values    map[string]int64 `json:"values,omitempty"`
	Registers []uint16         `json:"registers,omitempty"`
	Range     *RegisterRange   `json:"range,omitempty"`
	Payload   *Payload         `json:"payload,omitempty"`
}
type RegisterRange struct {
	Start uint16 `json:"start"`
	Count uint16 `json:"count"`
}

// Switch targets are relative to the referring switch opcode, rather than the
// payload. Array data preserves little endian element bytes without interpretation.
type Payload struct {
	FirstKey     int32   `json:"first_key,omitempty"`
	Keys         []int32 `json:"keys,omitempty"`
	Targets      []int32 `json:"targets,omitempty"`
	ElementWidth uint16  `json:"element_width,omitempty"`
	Data         []byte  `json:"data,omitempty"`
}

func (c *Catalog) WriteJSON(w io.Writer) error { return json.NewEncoder(w).Encode(c) }
func (c *Catalog) definition(op uint16) *Definition {
	if int(op) < len(c.Instructions) && c.Instructions[op].Opcode == op {
		return &c.Instructions[op]
	}
	for i := range c.Instructions {
		if c.Instructions[i].Opcode == op {
			return &c.Instructions[i]
		}
	}
	return nil
}
func validVersion(v int) bool { return v == 35 || v == 37 || v == 38 || v == 39 || v == 40 || v == 41 }
