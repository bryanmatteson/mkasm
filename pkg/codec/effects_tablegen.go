package codec

// TableGen Defs/Uses are retained even when no bits encode the register. Operand
// classes are identities from the source, not assumed register widths/banks.
func tableGenEffects(record map[string]any) EffectSpec {
	e := EffectSpec{Knowledge: EffectsPartial, RegistersKnowledge: EffectsPartial}
	for _, x := range []struct {
		key         string
		read, write bool
	}{{"OutOperandList", false, true}, {"InOperandList", true, false}} {
		dag, _ := record[x.key].(map[string]any)
		args, _ := dag["args"].([]any)
		for _, arg := range args {
			pair, ok := arg.([]any)
			if !ok || len(pair) != 2 {
				continue
			}
			name, _ := pair[1].(string)
			if name != "" {
				e.Registers = append(e.Registers, RegisterEffectSpec{Operand: name, Bank: defName(pair[0]), Read: x.read, Write: x.write})
			}
		}
	}
	for _, x := range []struct {
		key         string
		read, write bool
	}{{"Uses", true, false}, {"Defs", false, true}} {
		items, _ := record[x.key].([]any)
		for _, item := range items {
			if name := defName(item); name != "" {
				e.Registers = append(e.Registers, RegisterEffectSpec{Name: name, Read: x.read, Write: x.write, Implicit: true})
			}
		}
	}
	for key, dest := range map[string]**bool{"mayLoad": &e.MayLoad, "mayStore": &e.MayStore, "hasSideEffects": &e.HasSideEffects} {
		if value, ok := record[key]; ok {
			if n, ok := value.(float64); ok && (n == 0 || n == 1) {
				b := n == 1
				*dest = &b
			}
		}
	}
	if e.MayLoad != nil || e.MayStore != nil {
		e.MemoryKnowledge = EffectsPartial
		read := e.MayLoad != nil && *e.MayLoad
		write := e.MayStore != nil && *e.MayStore
		if read || write {
			e.Memory = append(e.Memory, MemoryEffectSpec{Read: read, Write: write, Conditional: true})
		}
		if e.MayLoad != nil && e.MayStore != nil && !read && !write {
			e.MemoryKnowledge = EffectsComplete
		}
	}
	if len(e.Registers) == 0 && e.MayLoad == nil && e.MayStore == nil && e.HasSideEffects == nil {
		e.Knowledge = EffectsUnknown
		e.RegistersKnowledge = EffectsUnknown
	}
	return e
}
