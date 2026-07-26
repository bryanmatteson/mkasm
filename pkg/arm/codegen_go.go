package arm

import (
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"mkasm/pkg/ir"
)

// --- Go master encoder (templates/go/master_encoder.tmpl) ---

type fixedWordRow struct {
	ID   string
	Word uint32
}

type fieldMapRow struct {
	ID     string
	Fields []CatalogField
}

type masterEncoderTmplData struct {
	Classes    []ClassEncoderRef
	Dispatches []MasterDispatchEntry
	FixedWords []fixedWordRow
	FieldMaps  []fieldMapRow
}

func emitMasterEncoderSource(classes []ClassEncoderRef, dispatches []MasterDispatchEntry, instrs []*ir.InstructionIR) string {
	sort.Slice(instrs, func(i, j int) bool {
		return instrs[i].EncodingID < instrs[j].EncodingID
	})
	var fixed []fixedWordRow
	var fieldMaps []fieldMapRow
	for _, instr := range instrs {
		if instr == nil || instr.EncodingID == "" {
			continue
		}
		if w, ok := ir.FixedWord(instr); ok {
			fixed = append(fixed, fixedWordRow{ID: instr.EncodingID, Word: w})
		}
		fixedMask, _ := ir.FixedBitsFromPattern(instr.BitPattern)
		var fields []CatalogField
		for _, f := range instr.Encoding.Fields {
			if f.Name == "" || f.Fixed != nil || f.Start < 0 || f.End < f.Start {
				continue
			}
			fields = append(fields, CatalogField{
				Name: f.Name, Start: f.Start, End: f.End,
				Free: fieldRangeMask(f.Start, f.End) &^ fixedMask,
			})
		}
		if len(fields) > 0 {
			fieldMaps = append(fieldMaps, fieldMapRow{ID: instr.EncodingID, Fields: fields})
		}
	}
	data := masterEncoderTmplData{
		Classes: classes, Dispatches: dispatches,
		FixedWords: fixed, FieldMaps: fieldMaps,
	}
	return mustExecGoTemplate("master_encoder.tmpl", data)
}

// fieldRangeMask returns the bit mask covering [start,end] inclusive.
func fieldRangeMask(start, end int) uint32 {
	if start < 0 || end < start || end > 31 {
		return 0
	}
	width := uint(end - start + 1)
	if width >= 32 {
		return ^uint32(0)
	}
	return uint32((uint64(1)<<width)-1) << uint(start)
}

func writeFixedRoundTripTest(outputDir string, instrs []*ir.InstructionIR) error {
	type sample struct {
		ID   string
		Word uint32
	}
	var samples []sample
	for _, instr := range instrs {
		if instr == nil {
			continue
		}
		w, ok := ir.FixedWord(instr)
		if !ok {
			continue
		}
		samples = append(samples, sample{instr.EncodingID, w})
		if len(samples) >= 64 {
			break
		}
	}
	src := mustExecGoTemplate("fixed_roundtrip_test.tmpl", struct{ Samples []sample }{samples})
	formatted, err := format.Source([]byte(src))
	if err != nil {
		formatted = []byte(src)
	}
	return os.WriteFile(filepath.Join(outputDir, "fixed_roundtrip_test.go"), formatted, 0644)
}

// --- Go decoder (templates/go/decoder.tmpl) ---

func emitDecoderSource(instructions []*ir.InstructionIR, tree *ir.DecoderTree, leaves, nodes int) string {
	sorted := append([]*ir.InstructionIR(nil), instructions...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].EncodingID < sorted[j].EncodingID
	})

	idIndex := make(map[string]int, len(sorted))
	type fieldDef struct {
		name       string
		start, end int
		fixed      bool
	}
	type entry struct {
		mask, value              uint32
		mnemonic, id, class, pat string
		aliasOf                  string
		fields                   []fieldDef
		bd                       *ir.BitDiffNode
	}
	entries := make([]entry, 0, len(sorted))
	for _, instr := range sorted {
		if instr == nil {
			continue
		}
		pat := instr.BitPattern
		if pat == "" || !strings.ContainsAny(pat, "01") {
			pat = ir.PatternFromEncoding(instr.Encoding)
		}
		mask, value := ir.FixedBitsFromPattern(pat)
		if mask == 0 {
			mask, value = ir.FixedBitsFromEncoding(instr.Encoding)
		}
		var fields []fieldDef
		for _, f := range instr.Encoding.Fields {
			if f.Name == "" || f.Start < 0 || f.End < f.Start {
				continue
			}
			fields = append(fields, fieldDef{
				name: f.Name, start: f.Start, end: f.End, fixed: f.Fixed != nil,
			})
		}
		idIndex[instr.EncodingID] = len(entries)
		entries = append(entries, entry{
			mask: mask, value: value,
			mnemonic: instr.Mnemonic, id: instr.EncodingID,
			class: instr.IClass, pat: pat, aliasOf: instr.AliasOf,
			fields: fields, bd: instr.BitDiffsTree,
		})
	}

	type flatNode struct {
		mask        uint32
		bitStart    int
		bitEnd      int
		useBitRange bool
		childVals   []uint32
		childIdx    []int
		leaf        int
		ambig       []int
	}
	var flats []flatNode
	covered := make([]bool, len(entries))
	var flatten func(n *ir.DecoderNode) int
	flatten = func(n *ir.DecoderNode) int {
		if n == nil {
			return -1
		}
		idx := len(flats)
		flats = append(flats, flatNode{leaf: -1})
		fn := flatNode{
			mask: n.Mask, bitStart: n.BitRange.Start, bitEnd: n.BitRange.End, leaf: -1,
		}
		if n.Mask == 0 && n.BitRange.End >= n.BitRange.Start && n.BitRange.Start >= 0 {
			fn.useBitRange = true
		}
		if n.Instruction != nil {
			if i, ok := idIndex[n.Instruction.EncodingID]; ok {
				fn.leaf = i
				covered[i] = true
			}
		}
		for _, a := range n.Ambiguous {
			if a == nil {
				continue
			}
			if i, ok := idIndex[a.EncodingID]; ok {
				fn.ambig = append(fn.ambig, i)
				covered[i] = true
			}
		}
		type cv struct {
			v uint32
			c *ir.DecoderNode
		}
		var kids []cv
		for _, c := range n.Children {
			if c != nil {
				kids = append(kids, cv{v: c.Value, c: c})
			}
		}
		sort.Slice(kids, func(i, j int) bool { return kids[i].v < kids[j].v })
		for _, k := range kids {
			ci := flatten(k.c)
			if ci < 0 {
				continue
			}
			fn.childVals = append(fn.childVals, k.v)
			fn.childIdx = append(fn.childIdx, ci)
		}
		flats[idx] = fn
		return idx
	}
	rootIdx := -1
	if tree != nil && tree.Root != nil {
		rootIdx = flatten(tree.Root)
	}

	var tableLit strings.Builder
	tableLit.WriteString("var table = []decodeEntry{\n")
	for _, e := range entries {
		fmt.Fprintf(&tableLit, "\t{0x%08X, 0x%08X, %q, %q, %q, %q, %q, []FieldDef{",
			e.mask, e.value, e.mnemonic, e.id, e.class, e.pat, e.aliasOf)
		for i, f := range e.fields {
			if i > 0 {
				tableLit.WriteString(", ")
			}
			fmt.Fprintf(&tableLit, "{%q, %d, %d, %v}", f.name, f.start, f.end, f.fixed)
		}
		tableLit.WriteString("}, ")
		tableLit.WriteString(emitBitDiffGo(e.bd))
		tableLit.WriteString("},\n")
	}
	tableLit.WriteString("}")

	var nodesLit strings.Builder
	nodesLit.WriteString("var nodes = []treeNode{\n")
	for _, fn := range flats {
		fmt.Fprintf(&nodesLit, "\t{0x%08X, %d, %d, %v, ", fn.mask, fn.bitStart, fn.bitEnd, fn.useBitRange)
		nodesLit.WriteString("[]uint32{")
		for i, v := range fn.childVals {
			if i > 0 {
				nodesLit.WriteString(", ")
			}
			fmt.Fprintf(&nodesLit, "0x%X", v)
		}
		nodesLit.WriteString("}, []int{")
		for i, v := range fn.childIdx {
			if i > 0 {
				nodesLit.WriteString(", ")
			}
			fmt.Fprintf(&nodesLit, "%d", v)
		}
		fmt.Fprintf(&nodesLit, "}, %d, []int{", fn.leaf)
		for i, v := range fn.ambig {
			if i > 0 {
				nodesLit.WriteString(", ")
			}
			fmt.Fprintf(&nodesLit, "%d", v)
		}
		nodesLit.WriteString("}},\n")
	}
	nodesLit.WriteString("}")

	// BuildTree drops encodings with no usable bitfields, so the table can be a
	// superset of what the tree indexes. The walker has to know which entries
	// those are or a tree leaf would claim uniqueness the table disproves.
	var untreedLit strings.Builder
	untreedLit.WriteString("var untreed = []int{")
	first := true
	for i, ok := range covered {
		if ok {
			continue
		}
		if !first {
			untreedLit.WriteString(", ")
		}
		first = false
		fmt.Fprintf(&untreedLit, "%d", i)
	}
	untreedLit.WriteString("}")

	return mustExecGoTemplate("decoder.tmpl", struct {
		InstrCount, NodeCount, LeafCount, Root int
		TableLit, NodesLit, UntreedLit         string
	}{
		InstrCount: len(entries),
		NodeCount:  nodes,
		LeafCount:  leaves,
		Root:       rootIdx,
		TableLit:   tableLit.String(),
		NodesLit:   nodesLit.String(),
		UntreedLit: untreedLit.String(),
	})
}

// emitBitDiffGo renders an ir.BitDiffNode as a generated *bdNode literal.
func emitBitDiffGo(n *ir.BitDiffNode) string {
	if n == nil {
		return "nil"
	}
	switch n.Kind {
	case ir.BitDiffAnd:
		var b strings.Builder
		b.WriteString("&bdNode{kind: 1, kids: []*bdNode{")
		for i, k := range n.Kids {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(emitBitDiffGo(k))
		}
		b.WriteString("}}")
		return b.String()
	case ir.BitDiffNot:
		var b strings.Builder
		b.WriteString("&bdNode{kind: 2, kids: []*bdNode{")
		if len(n.Kids) > 0 {
			b.WriteString(emitBitDiffGo(n.Kids[0]))
		}
		b.WriteString("}}")
		return b.String()
	default:
		if n.Atom == nil {
			return "nil"
		}
		a := n.Atom
		op := byte(0)
		switch a.Op {
		case ir.BitDiffNe:
			op = 1
		case ir.BitDiffIn:
			op = 2
		}
		var b strings.Builder
		fmt.Fprintf(&b, "&bdNode{kind: 0, start: %d, end: %d, op: %d, bits: %q, alts: []string{",
			a.Start, a.End, op, a.Bits)
		for i, alt := range a.Alts {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", alt)
		}
		b.WriteString("}}")
		return b.String()
	}
}

// --- Go registry (templates/go/registry.tmpl) ---

func emitRegistrySource(instructions []*ir.InstructionIR) string {
	cat := BuildCatalog(instructions)
	type row struct {
		EncodingID, Mnemonic, Class, Pattern, IFormFile, Asm, AliasOf string
		FixedWord                                                     uint32
		HasFixed                                                      bool
	}
	rows := make([]row, 0, len(cat.Entries))
	for _, e := range cat.Entries {
		rows = append(rows, row{
			EncodingID: e.EncodingID, Mnemonic: e.Mnemonic, Class: e.Class,
			Pattern: e.Pattern, FixedWord: e.FixedWord, HasFixed: e.HasFixed,
			IFormFile: e.IFormFile, Asm: e.Asm, AliasOf: e.AliasOf,
		})
	}
	return mustExecGoTemplate("registry.tmpl", struct {
		Count   int
		Entries []row
	}{Count: len(rows), Entries: rows})
}

func writeGoldenDecoderTest(decoderDir string, instructions []*ir.InstructionIR) error {
	type gold struct {
		Word uint32
		ID   string
	}
	// Every word here was disassembled with LLVM (clang -c + objdump -d) to
	// confirm which encoding it really is. Entries absent from the generate set
	// are skipped, so -max-iforms smoke runs still work.
	want := []gold{
		{0xD5033F5F, "CLREX_BN_barriers"},  // clrex
		{0xD50330BF, "DMB_BO_barriers"},    // dmb #0
		{0xD50330DF, "ISB_BI_barriers"},    // isb #0
		{0xD5033F9F, "DSB_BO_barriers"},    // dsb sy
		{0xD503323F, "DSB_BOn_barriers"},   // dsb oshnxs — the nXS variant, op2=001
		{0x74C08000, "CBBEQ_8_regs"},       // cbbeq w0, w0, .
		{0x74208000, "CBBGE_8_regs"},       // cbbge w0, w0, .
		{0xD65F03C0, "RET_64R_branch_reg"}, // ret
		{0x52800020, "MOVZ_32_movewide"},   // mov w0, #1
		{0xDAC11020, "AUTIA_64P_dp_1src"},  // autia x0, x1
		{0xDAC133E0, "AUTIZA_64Z_dp_1src"}, // autiza x0
		// Scalar and vector forms share an iform file but not a diagram: these
		// two catch an encoding being bound to the wrong <iclass> regdiagram.
		{0x5EE0B820, "ABS_asisdmisc_R"},         // abs d0, d1
		{0x0E20B820, "ABS_asimdmisc_R"},         // abs v0.8b, v1.8b
		{0x5EE09820, "CMEQ_asisdmisc_Z"},        // cmeq d0, d1, #0
		{0x7EC21420, "FABD_asisdsamefp16_only"}, // fabd h0, h1, h2
		// One file, three addressing forms: these catch per-encoding <box>
		// overrides being dropped, which collapsed all three into one pattern.
		{0xB8404420, "LDR_32_ldst_immpost"}, // ldr w0, [x1], #4
		{0xB8404C20, "LDR_32_ldst_immpre"},  // ldr w0, [x1, #4]!
		{0xF9400420, "LDR_64_ldst_pos"},     // ldr x0, [x1, #8]
	}
	have := map[string]bool{}
	for _, instr := range instructions {
		if instr != nil {
			have[instr.EncodingID] = true
		}
	}
	var cases []gold
	for _, g := range want {
		if have[g.ID] {
			cases = append(cases, g)
		}
	}
	src := mustExecGoTemplate("golden_test.tmpl", struct{ Cases []gold }{cases})
	formatted, err := format.Source([]byte(src))
	if err != nil {
		formatted = []byte(src)
	}
	return os.WriteFile(filepath.Join(decoderDir, "golden_test.go"), formatted, 0644)
}

func mustExecGoTemplate(name string, data any) string {
	tmpl := loadTemplates()
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, name, data); err != nil {
		panic(fmt.Sprintf("template %s: %v", name, err))
	}
	return b.String()
}
