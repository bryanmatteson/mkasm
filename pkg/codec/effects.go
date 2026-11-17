package codec

import _ "embed"

// EffectKnowledge distinguishes absent facts from proved preservation. Complete
// applies only to the category carrying it; Partial facts are still useful.
type EffectKnowledge string

const (
	EffectsUnknown  EffectKnowledge = "unknown"
	EffectsPartial  EffectKnowledge = "partial"
	EffectsComplete EffectKnowledge = "complete"
)

// EffectSpec retains source facts without guessing architecture semantics from
// instruction names. Empty metadata means unknown, never no effects.
type EffectSpec struct {
	Knowledge          EffectKnowledge      `json:"knowledge,omitempty"`
	RegistersKnowledge EffectKnowledge      `json:"registers_knowledge,omitempty"`
	FlagsKnowledge     EffectKnowledge      `json:"flags_knowledge,omitempty"`
	MemoryKnowledge    EffectKnowledge      `json:"memory_knowledge,omitempty"`
	Registers          []RegisterEffectSpec `json:"registers,omitempty"`
	Flags              []FlagEffectSpec     `json:"flags,omitempty"`
	Memory             []MemoryEffectSpec   `json:"memory,omitempty"`
	MayLoad            *bool                `json:"may_load,omitempty"`
	MayStore           *bool                `json:"may_store,omitempty"`
	HasSideEffects     *bool                `json:"has_side_effects,omitempty"`
}

type RegisterEffectSpec struct {
	Operand       string `json:"operand,omitempty"`
	Bank          string `json:"bank,omitempty"`
	Name          string `json:"name,omitempty"`
	Offset        uint16 `json:"offset,omitempty"`
	Width         uint16 `json:"width,omitempty"`
	Read          bool   `json:"read,omitempty"`
	Write         bool   `json:"write,omitempty"`
	Conditional   bool   `json:"conditional,omitempty"`
	Implicit      bool   `json:"implicit,omitempty"`
	Address       bool   `json:"address,omitempty"`
	WriteBehavior string `json:"write_behavior,omitempty"`
}

type FlagEffectSpec struct {
	Name        string `json:"name"`
	Read        bool   `json:"read,omitempty"`
	Action      string `json:"action,omitempty"` // unknown, preserve, write, clear, set, undefined
	Conditional bool   `json:"conditional,omitempty"`
}

type MemoryEffectSpec struct {
	Operand     string `json:"operand,omitempty"`
	Read        bool   `json:"read,omitempty"`
	Write       bool   `json:"write,omitempty"`
	Conditional bool   `json:"conditional,omitempty"`
	Width       uint16 `json:"width,omitempty"`
	Ordering    string `json:"ordering,omitempty"`
	Atomicity   string `json:"atomicity,omitempty"`
	Writeback   string `json:"writeback,omitempty"`
}

//go:embed effects_types.rs.tmpl
var rustEffectTypes string

// RustEffectTypes is shared verbatim by generated backends so consumers can use
// a single vocabulary without bringing in any dependency.
func RustEffectTypes() string { return rustEffectTypes }

// ResolvedRegisterEffect preserves register identity even when the source only
// names an implicit register and supplies no numeric bank or slice width.
type ResolvedRegisterEffect struct {
	RegisterEffectSpec
	Number *int64 `json:"number,omitempty"`
}
type ResolvedEffects struct {
	Metadata  EffectSpec               `json:"metadata"`
	Registers []ResolvedRegisterEffect `json:"registers,omitempty"`
}

// Effects resolves architectural register references against decoded operands.
// An operand appearing in an LLVM DAG is not necessarily a register: adapters
// assign Kind, so immediate/address entries are deliberately excluded here.
func (d *Decoded) Effects() ResolvedEffects {
	out := ResolvedEffects{Metadata: d.Encoding.Effects}
	for _, r := range d.Encoding.Effects.Registers {
		next := ResolvedRegisterEffect{RegisterEffectSpec: r}
		if r.Operand != "" {
			found := false
			for _, o := range d.Encoding.Operands {
				if o.Name == r.Operand && o.Kind == "register" {
					n, ok := d.Values[o.Name]
					if ok {
						next.Number = &n
					}
					next.Bank = o.Class
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		out.Registers = append(out.Registers, next)
	}
	return out
}
