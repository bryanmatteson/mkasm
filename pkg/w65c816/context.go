package w65c816

import (
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// ExecutionContext is the state at an instruction boundary. Emulation forces
// M=X=1. After PLP, RTI or XCE, supply the actual restored state at the next
// boundary; bytes alone cannot determine it.
type ExecutionContext struct {
	PC           uint32 `json:"pc"`
	Emulation    bool   `json:"emulation"`
	Accumulator8 bool   `json:"accumulator8"`
	Index8       bool   `json:"index8"`
}

func (x ExecutionContext) Profile() string {
	m, i := 16, 16
	if x.Emulation || x.Accumulator8 {
		m = 8
	}
	if x.Emulation || x.Index8 {
		i = 8
	}
	return fmt.Sprintf("m%dx%d", m, i)
}
func (c *Catalog) DecodeWithContext(b []byte, x ExecutionContext) (*codec.Decoded, error) {
	if x.PC > 0xffffff {
		return nil, fmt.Errorf("65816 PC exceeds 24 bits")
	}
	return c.Catalog.DecodeWithFeatures(b, c.FeatureSets[x.Profile()])
}
func (c *Catalog) Decode(b []byte) (*codec.Decoded, error) {
	return c.DecodeWithContext(b, ExecutionContext{Emulation: true})
}
func (c *Catalog) AssembleWithContext(text string, x ExecutionContext) ([][]byte, error) {
	if x.PC > 0xffffff {
		return nil, fmt.Errorf("65816 PC exceeds 24 bits")
	}
	return c.Catalog.AssembleWithFeatures(text, uint64(x.PC), c.FeatureSets[x.Profile()])
}

// Next advances a sequential PC without carrying into PBR and tracks REP/SEP.
// Control-flow destinations are available through Decoded.BranchTarget instead.
func (x ExecutionContext) Next(d *codec.Decoded) (ExecutionContext, error) {
	if d == nil || d.Encoding == nil {
		return x, fmt.Errorf("missing 65816 instruction")
	}
	if x.PC > 0xffffff {
		return x, fmt.Errorf("65816 PC exceeds 24 bits")
	}
	switch d.Encoding.Mnemonic {
	case "plp", "rti", "xce":
		return x, fmt.Errorf("%s requires actual next E/M/X state", d.Encoding.Mnemonic)
	case "rep", "sep":
		v := d.Values["value"]
		set := d.Encoding.Mnemonic == "sep"
		if v&32 != 0 {
			x.Accumulator8 = set
		}
		if v&16 != 0 {
			x.Index8 = set
		}
	}
	if x.Emulation {
		x.Accumulator8 = true
		x.Index8 = true
	}
	x.PC = x.PC&0xff0000 | uint32(uint16(x.PC+uint32(d.Length)))
	return x, nil
}
