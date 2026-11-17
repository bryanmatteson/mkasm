package xtensa

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed testdata/gnu.json
var gnuData []byte

type gnuCorpus struct {
	Formats []Format  `json:"formats"`
	Forms   []gnuForm `json:"forms"`
}
type Format struct {
	Name   string `json:"name"`
	Length int    `json:"length"`
	Slots  []int  `json:"slots"`
	Mask   []byte `json:"mask,omitempty"`
	Value  []byte `json:"value,omitempty"`
	Scalar bool   `json:"scalar,omitempty"`
}
type gnuForm struct {
	Name                string
	Slot, Format, Flags int
	Mask, Value         []byte
	Operands            []gnuOperand
}
type gnuOperand struct {
	Name, Prefix            string
	Flags, Registers, Width int
	Bits                    [][2]int
	Samples                 [][2]int64
	PCBases                 []uint64 `json:"pcbases"`
}
type SlotMeta struct {
	Slot, Format int
	Mask         []byte
}

func importGNU(c *Catalog) error {
	var corpus gnuCorpus
	if err := json.Unmarshal(gnuData, &corpus); err != nil {
		return err
	}
	c.Formats = corpus.Formats
	for i := range c.Formats {
		f := &c.Formats[i]
		f.Scalar = i < 3
		if i >= 3 && c.Architecture != "xtensaeb" {
			f.Mask = make([]byte, f.Length)
			f.Value = make([]byte, f.Length)
			f.Mask[0] = 15
			f.Value[0] = byte(14 + i - 3)
			if i == 4 {
				f.Mask[7] = 128
			}
		}
	}
	known := map[string]codec.Encoding{}
	knownNames := map[string]bool{}
	for _, e := range c.Core.Encodings {
		if !e.AssemblyOnly {
			known[strings.ToLower(e.Mnemonic)] = e
			for _, o := range e.Operands {
				if o.Class == "SR" || o.Class == "UR" {
					for _, name := range o.Names {
						if name != "" {
							knownNames[name] = true
						}
					}
				}
			}
		}
	}
	for _, f := range corpus.Forms {
		if f.Format < 3 {
			if _, ok := known[f.Name]; ok {
				continue
			}
		} else if c.Core.Architecture == "xtensaeb" {
			continue
		}
		e := codec.Encoding{ID: fmt.Sprintf("GNU_%d_%s", f.Slot, f.Name), Mnemonic: f.Name, Syntax: f.Name, Mask: append([]byte(nil), f.Mask...), Value: append([]byte(nil), f.Value...), FlowControl: "next"}
		var words []string
		var prior []gnuOperand
		for i, a := range f.Operands {
			if a.Flags&4 != 0 {
				continue
			}
			duplicate := false
			for _, p := range prior {
				if reflect.DeepEqual(a.Bits, p.Bits) {
					duplicate = true
				}
			}
			if duplicate {
				continue
			}
			prior = append(prior, a)
			name := fmt.Sprintf("o%d", i)
			if len(a.Bits) == 0 {
				v := int64(0)
				if len(a.Samples) > 0 {
					v = a.Samples[0][1]
				}
				if a.Flags&1 != 0 {
					words = append(words, fmt.Sprintf("%s%d", a.Prefix, v))
				} else {
					words = append(words, fmt.Sprint(v))
				}
				continue
			}
			o := codec.Operand{Name: name, Class: a.Name, Kind: "immediate"}
			for _, b := range a.Bits {
				o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: b[0], ValueBit: b[1], Width: 1})
			}
			// Infer affine and signed-affine transforms from all small-domain source
			// samples, using a numeric lookup for genuinely non-linear operand classes.
			bias := a.Samples[0][1]
			scale := int64(1)
			if len(a.Samples) > 1 {
				scale = a.Samples[1][1] - bias
			}
			signed := false
			if a.Width > 0 {
				for _, s := range a.Samples {
					raw := s[0]
					if raw == int64(1)<<uint(a.Width-1) && s[1] == bias-(int64(1)<<uint(a.Width-1))*scale {
						signed = true
					}
				}
			}
			linear := scale > 0
			for _, s := range a.Samples {
				raw := s[0]
				if signed && raw&(int64(1)<<uint(a.Width-1)) != 0 {
					raw -= int64(1) << uint(a.Width)
				}
				if raw*scale+bias != s[1] {
					linear = false
				}
			}
			if linear {
				o.Scale = scale
				o.Bias = bias
				o.Signed = signed
			} else {
				if len(a.Samples) != (1 << uint(a.Width)) {
					return fmt.Errorf("GNU %s unrepresentable transform %s", f.Name, a.Name)
				}
				for _, s := range a.Samples {
					o.Lookup = append(o.Lookup, s[1])
				}
			}
			if a.Flags&1 != 0 {
				o.Kind = "register"
				o.Names = make([]string, 1<<uint(a.Width))
				o.Scale = 0
				o.Bias = 0
				o.Signed = false
				o.Lookup = nil
				for _, s := range a.Samples {
					o.Names[s[0]] = fmt.Sprintf("%s%d", a.Prefix, s[1])
				}
				if a.Prefix == "a" {
					o.RegisterAliases = map[string]int64{"sp": 1}
				}
			}
			if a.Flags&2 != 0 {
				o.Kind = "displacement"
				o.Relative = true
				o.PCWrapBits = 32
				if a.PCBases[1] == 4096 {
					o.PCAlignBits = 2
				} else if a.PCBases[0] == 4096 && a.PCBases[1] == 4100 {
					o.PCAlignBits = 2
					o.PCPreAlignBias = 3
				}
			}
			if a.Name == "msalp32" {
				o.Names = make([]string, 32)
				for j := 1; j < 32; j++ {
					o.Names[j] = fmt.Sprint(32 - j)
				}
			}
			e.Operands = append(e.Operands, o)
			words = append(words, "{"+name+"}")
		}
		if f.Name == "extui" {
			e.Constraints = append(e.Constraints, codec.Constraint{Kind: "sum_le", Left: "o2", Right: "o3", Limit: 32})
		}
		if len(words) > 0 {
			e.Syntax += " " + strings.Join(words, ", ")
		}
		if f.Flags&8 != 0 {
			e.FlowControl = "call"
		} else if f.Flags&2 != 0 {
			e.FlowControl = "branch"
		} else if f.Flags&5 != 0 {
			e.FlowControl = "conditional_branch"
		}
		if strings.HasPrefix(f.Name, "ret") || strings.HasPrefix(f.Name, "rf") {
			e.FlowControl = "return"
		}
		if strings.HasPrefix(f.Name, "break") || f.Name == "ill" || f.Name == "ill.n" || f.Name == "syscall" {
			e.FlowControl = "trap"
		}
		if f.Format < 3 {
			e.Features = supplementFeatures(f.Name)
			for _, prefix := range []string{"rsr.", "wsr.", "xsr.", "rur.", "wur."} {
				if strings.HasPrefix(f.Name, prefix) {
					name := strings.TrimPrefix(f.Name, prefix)
					feature, valid := registerFeature(name, strings.TrimSuffix(prefix, "."))
					if !valid {
						continue
					}
					if _, knownReg := known[strings.TrimSuffix(prefix, ".")]; knownReg && valid && knownNames[name] {
						e.Features = nil
						if feature != "" {
							e.Features = []string{feature}
						}
					}
				}
			}
			if c.Core.Architecture == "xtensaeb" {
				layout := record{"!superclasses": []any{"RRR_Inst"}}
				if strings.HasPrefix(f.Name, "rsr.") || strings.HasPrefix(f.Name, "wsr.") || strings.HasPrefix(f.Name, "xsr.") {
					layout["!superclasses"] = []any{"RSR_Inst"}
				}
				for _, o := range e.Operands {
					if o.Class == "uimm8" || o.Class == "uimm8x4" || o.Class == "uimm8x2" || o.Class == "cimm8x4" {
						layout["!superclasses"] = []any{"RRI8_Inst"}
					}
				}
				bigEndian(&e, layout)
			}
			c.Core.Encodings = append(c.Core.Encodings, e)
			continue
		}
		meta := SlotMeta{Slot: f.Slot, Format: f.Format, Mask: make([]byte, 8)}
		copy(meta.Mask, e.Mask)
		for _, o := range e.Operands {
			for _, b := range o.Bits {
				meta.Mask[b.InstructionBit/8] |= 1 << uint(b.InstructionBit%8)
			}
		}
		for j := range e.Mask {
			e.Value[j] &= e.Mask[j]
			e.Mask[j] |= ^meta.Mask[j]
		}
		e.Features = []string{"HasFLIX"}
		c.Slots.Encodings = append(c.Slots.Encodings, e)
		c.Metadata[e.ID] = meta
	}
	c.Core.Unsupported = append(c.Core.Unsupported, codec.Unsupported{ID: "designer-custom-opcodes", Reason: "CUST0/CUST1 opcode meanings and arbitrary TIE extensions require the processor's generated ISA configuration; Parse also accepts complete mkasm.xtensa.v1 configuration JSON"})
	if c.Core.Architecture == "xtensaeb" {
		c.Core.Unsupported = append(c.Core.Unsupported, codec.Unsupported{ID: "GNU-FLIX-big-endian", Reason: "GNU's supplied FLIX configuration is little-endian only; no corresponding big-endian slot layout is supplied"})
	}
	c.Core.FeatureSets["gnu-config"] = []string{"HasGNUConfig", "HasFLIX", "HasDensity", "HasDataCache", "HasInstructionCache", "HasBoolean", "HasMAC16", "HasLoop", "HasWindowed", "HasSingleFloat", "HasS32C1I", "HasS32RI", "HasMul16", "HasMul32", "HasMul32High", "HasDiv32", "HasNSA", "HasSEXT", "HasMINMAX", "HasCLAMPS", "HasException", "HasDebug", "HasInterrupt", "HasHighPriInterrupts", "HasCoprocessor", "HasRegionProtection"}
	for _, e := range c.Core.Encodings {
		if strings.HasPrefix(e.ID, "GNU_") {
			c.Core.FeatureSets["gnu-config"] = append(c.Core.FeatureSets["gnu-config"], e.Features...)
		}
	}
	c.Core.FeatureSets["all"] = append(c.Core.FeatureSets["all"], "HasGNUConfig", "HasFLIX", "HasInstructionCache")
	for name, features := range c.Core.FeatureSets {
		c.Core.FeatureSets[name] = expandProfile(features)
	}
	return c.Core.Validate()
}
func supplementFeatures(name string) []string {
	if strings.HasPrefix(name, "rsr.") || strings.HasPrefix(name, "wsr.") || strings.HasPrefix(name, "xsr.") {
		return []string{"HasGNUConfig"}
	}
	for _, p := range []string{"dhi", "dhu", "dhwb", "dii", "diu", "diwb", "dpf", "dpfl", "dpfr", "dpfw", "l32ai", "s32ri", "sdct", "ldct"} {
		if strings.HasPrefix(name, p) {
			return []string{"HasDataCache"}
		}
	}
	for _, p := range []string{"ihi", "ihu", "iii", "iiu", "ipf", "lict", "licw", "sict", "sicw"} {
		if strings.HasPrefix(name, p) {
			return []string{"HasInstructionCache"}
		}
	}
	return []string{"HasGNUConfig"}
}
