package codec

import (
	"fmt"
	"strings"
)

func effectVariant(value string, allowed ...string) string {
	for _, s := range allowed {
		if strings.EqualFold(strings.ReplaceAll(value, "_", ""), s) {
			return s
		}
	}
	return "Unknown"
}
func effectKnowledge(value EffectKnowledge) string {
	return effectVariant(string(value), "Complete", "Partial")
}
func effectWidth(width uint16) string {
	if width == 0 {
		return "None"
	}
	return fmt.Sprintf("Some(%d)", width)
}

// RustEffectInitializer renders source-proven metadata. operandIndex/number are
// expressions supplied by the architecture adapter, not inferred from syntax.
func RustEffectInitializer(spec EffectSpec, operandIndex func(string) string, number func(string) string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "out.knowledge=EffectKnowledge::%s;out.registers_knowledge=EffectKnowledge::%s;out.flags_knowledge=EffectKnowledge::%s;out.memory_knowledge=EffectKnowledge::%s;\n", effectKnowledge(spec.Knowledge), effectKnowledge(spec.RegistersKnowledge), effectKnowledge(spec.FlagsKnowledge), effectKnowledge(spec.MemoryKnowledge))
	if spec.MayLoad != nil {
		fmt.Fprintf(&b, "out.memory_may_read=Some(%t);\n", *spec.MayLoad)
	}
	if spec.MayStore != nil {
		fmt.Fprintf(&b, "out.memory_may_write=Some(%t);\n", *spec.MayStore)
	}
	if spec.HasSideEffects != nil {
		fmt.Fprintf(&b, "out.other_side_effects_possible=Some(%t);\n", *spec.HasSideEffects)
	}
	// Only explicit source hasSideEffects=false proves absence of other effects.
	if spec.HasSideEffects != nil && !*spec.HasSideEffects {
		b.WriteString("out.other_side_effects=EffectKnowledge::Complete;\n")
	}
	for _, r := range spec.Registers {
		num := "None"
		if r.Operand != "" {
			num = number(r.Operand)
		}
		fmt.Fprintf(&b, "out.registers.push(RegisterEffect{register:RegisterSlice{bank:%s,number:%s,name:%s,offset:%d,width:%s},read:%t,write:%t,conditional:%t,implicit:%t,address:%t,write_behavior:WriteBehavior::%s});\n", rustQuote(r.Bank), num, rustQuote(r.Name), r.Offset, effectWidth(r.Width), r.Read, r.Write, r.Conditional, r.Implicit, r.Address, effectVariant(r.WriteBehavior, "PreserveUpper", "Replace", "ZeroUpper"))
	}
	for _, f := range spec.Flags {
		fmt.Fprintf(&b, "out.flags.push(FlagEffect{name:%s,read:%t,action:FlagAction::%s,conditional:%t});\n", rustQuote(f.Name), f.Read, effectVariant(f.Action, "Preserve", "Write", "Clear", "Set", "Undefined"), f.Conditional)
	}
	for _, m := range spec.Memory {
		index := "None"
		if m.Operand != "" {
			index = operandIndex(m.Operand)
		}
		fmt.Fprintf(&b, "out.memory.push(MemoryEffect{operand:%s,read:%t,write:%t,conditional:%t,implicit:%t,width_bits:%s,ordering:MemoryOrdering::%s,atomicity:Atomicity::%s,writeback:Writeback::%s});\n", index, m.Read, m.Write, m.Conditional, m.Operand == "", effectWidth(m.Width), effectVariant(m.Ordering, "Relaxed", "Acquire", "Release", "AcquireRelease", "Sequential"), effectVariant(m.Atomicity, "NonAtomic", "Atomic"), effectVariant(m.Writeback, "None", "Before", "After"))
	}
	return b.String()
}

func (c *Catalog) rustEffects() string {
	var b strings.Builder
	b.WriteString("use super::*;\n")
	b.WriteString(RustEffectTypes())
	target := "Decoded"
	switch c.Architecture {
	case "hexagon":
		target = "DecodedWord"
	case "xtensa", "xtensaeb":
		target = "DecodedField"
	}
	b.WriteString("impl " + target + " { pub fn effects(&self)->EffectSummary { let mut out=EffectSummary::default();match self.encoding().id {\n")
	hasInitializer := false
	emitted := 0
	for _, e := range c.Encodings {
		spec := e.Effects
		// LLVM DAG operand types include immediates. Resolve after each adapter has
		// assigned actual operand kinds, retaining only architectural registers.
		spec.Registers = nil
		for _, r := range e.Effects.Registers {
			if r.Operand != "" {
				found := false
				for _, o := range e.Operands {
					if o.Name == r.Operand && o.Kind == "register" {
						found = true
						r.Bank = o.Class
						break
					}
				}
				if !found {
					continue
				}
			}
			spec.Registers = append(spec.Registers, r)
		}
		if len(spec.Registers) == 0 && len(spec.Flags) == 0 && len(spec.Memory) == 0 && spec.Knowledge == "" && spec.RegistersKnowledge == "" && spec.FlagsKnowledge == "" && spec.MemoryKnowledge == "" && spec.HasSideEffects == nil && spec.MayLoad == nil && spec.MayStore == nil {
			continue
		}
		emitted++
		fmt.Fprintf(&b, "%s=>{\n", rustQuote(e.ID))
		idx := func(name string) string {
			for i, o := range e.Operands {
				if o.Name == name {
					return fmt.Sprintf("Some(%d)", i)
				}
			}
			return "None"
		}
		num := func(name string) string {
			for i, o := range e.Operands {
				if o.Name == name {
					return fmt.Sprintf("u16::try_from(self.values[%d]).ok()", i)
				}
			}
			return "None"
		}
		initializer := RustEffectInitializer(spec, idx, num)
		hasInitializer = hasInitializer || initializer != ""
		b.WriteString(initializer)
		b.WriteString("},\n")
	}
	b.WriteString("_=>{} } out } }\n")
	switch c.Architecture {
	case "hexagon":
		b.WriteString("impl Packet { /// Source effect summaries in packet word/subinstruction order. Packet dependency resolution is not inferred.\n pub fn effects(&self)->Vec<EffectSummary> {self.words.iter().flat_map(|w|w.instructions.iter()).map(|i|i.decoded.effects()).collect()} }\n")
	case "xtensa", "xtensaeb":
		b.WriteString("impl Decoded { /// Source effect summaries in decoded slot order.\n pub fn effects(&self)->Vec<EffectSummary> {self.instructions.iter().map(|i|i.effects()).collect()} }\n")
	}
	result := b.String()
	if !hasInitializer {
		result = strings.Replace(result, "let mut out=", "let out=", 1)
	}
	return result
}
