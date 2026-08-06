package arm

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"github.com/bryanmatteson/mkasm/pkg/decoder"
	"github.com/bryanmatteson/mkasm/pkg/ir"
	"github.com/bryanmatteson/mkasm/templates"
)

// GenerateRust emits a Rust crate for catalog under outputDir.
func (cg *CodeGenerator) GenerateRust(catalog *Catalog) error {
	if catalog == nil || len(catalog.Entries) == 0 {
		return fmt.Errorf("rust codegen: empty catalog")
	}
	srcDir := filepath.Join(cg.outputDir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		return err
	}

	tmpl, err := template.New("rust").Funcs(template.FuncMap{
		"rustStr": rustStringLiteral,
	}).ParseFS(templates.FS, "rust/*.tmpl")
	if err != nil {
		return fmt.Errorf("parse rust templates: %w", err)
	}

	cargoData := struct{ CrateName string }{CrateName: cg.arch.ArtifactName()}
	if err := execTmplWrite(tmpl, "cargo.toml.tmpl", filepath.Join(cg.outputDir, "Cargo.toml"), cargoData); err != nil {
		return err
	}
	if err := writeLicense(cg.outputDir); err != nil {
		return err
	}
	if err := execTmplWrite(tmpl, "lib.rs.tmpl", filepath.Join(srcDir, "lib.rs"), nil); err != nil {
		return err
	}

	encData := struct {
		FixedTable  string
		FieldsTable string
		ClassTable  string
	}{
		FixedTable:  emitRustFixedTable(catalog),
		FieldsTable: emitRustFieldsTable(catalog),
		ClassTable:  emitRustClassTable(catalog),
	}
	if err := execTmplWrite(tmpl, "encoders.rs.tmpl", filepath.Join(srcDir, "encoders.rs"), encData); err != nil {
		return err
	}

	decData, err := buildRustDecoderData(catalog)
	if err != nil {
		return err
	}
	if err := execTmplWrite(tmpl, "decoders.rs.tmpl", filepath.Join(srcDir, "decoders.rs"), decData); err != nil {
		return err
	}
	disasm := cg.disasm
	if disasm == nil {
		disasm = &DisasmSurface{}
	}
	disasmData, err := buildRustDisasmData(catalog, disasm)
	if err != nil {
		return err
	}
	if err := execTmplWrite(tmpl, "formatters.rs.tmpl", filepath.Join(srcDir, "formatters.rs"), disasmData); err != nil {
		return err
	}

	regData := struct{ AllTable string }{AllTable: emitRustRegistryTable(catalog)}
	if err := execTmplWrite(tmpl, "registry.rs.tmpl", filepath.Join(srcDir, "registry.rs"), regData); err != nil {
		return err
	}

	exDir := filepath.Join(cg.outputDir, "examples")
	if err := os.MkdirAll(exDir, 0755); err != nil {
		return err
	}
	// The worked example names specific instructions, so it is only emitted when
	// this generate actually produced them: a -max-iforms smoke run resolves a
	// handful of encodings and would not compile against it.
	example := "example_minimal.rs.tmpl"
	if cg.surfaceHasAll("mov", "add", "movz", "ldr", "str", "bl", "b_cond", "b", "nop", "ret") {
		example = "example.rs.tmpl"
	}
	if err := execTmplWrite(tmpl, example, filepath.Join(exDir, "hello.rs"), cargoData); err != nil {
		return err
	}
	if err := execTmplWrite(tmpl, "decode_bench.rs.tmpl", filepath.Join(exDir, "decode_bench.rs"), cargoData); err != nil {
		return err
	}
	// Operand placement checked against LLVM's assembler. The round-trip tests
	// confirm each word decodes to the right encoding, which does not prove an
	// operand's bits landed where they belong — a split immediate would decode
	// to the correct instruction with the value mangled. These words come from
	// clang, so they check the placements the decoder cannot.
	// Base mnemonics only: the arity-suffixed variants the example calls
	// (movi_amount, ptrue_pattern) are named during emission, not in the surface.
	if cg.surfaceHasAll("adr", "movi", "st1", "umov", "ld1b", "ptrue", "scvtf",
		"st1_asisdlso_h1_1h", "ld1b_mzx_p_br_2x8") {
		if err := execTmplWrite(tmpl, "example_llvm.rs.tmpl", filepath.Join(exDir, "llvm_check.rs"), cargoData); err != nil {
			return err
		}
	}

	// The typed assembler surface: operand types, then one method per mnemonic.
	if err := execTmplWrite(tmpl, "asm_support.rs.tmpl", filepath.Join(srcDir, "asm_support.rs"), nil); err != nil {
		return err
	}
	if cg.surface != nil {
		if err := os.WriteFile(filepath.Join(srcDir, "insns.rs"), []byte(emitRustInsns(cg.surface)), 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(srcDir, "encodings.rs"), []byte(emitRustExact(cg.surface)), 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(srcDir, "raw.rs"), []byte(emitRustRaw(cg.surface)), 0644); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(srcDir, "insns_test.rs"), []byte(emitRustInsnTests(cg.surface)), 0644); err != nil {
			return err
		}
		testDir := filepath.Join(cg.outputDir, "tests")
		if err := os.MkdirAll(testDir, 0755); err != nil {
			return err
		}
		conformance, cases := EmitRustConformanceTest(cg.arch.ArtifactName(), cg.surface)
		if len(cases) == 0 {
			return fmt.Errorf("rust codegen: no typed conformance calls")
		}
		if err := os.WriteFile(filepath.Join(testDir, "conformance.rs"), []byte(conformance), 0644); err != nil {
			return err
		}
		exactConformance, exactCases := EmitRustExactConformanceTestFor(
			cg.arch.ArtifactName(), cg.surface, cg.disasm,
		)
		if len(exactCases) != len(cg.surface.Exact) {
			return fmt.Errorf("rust codegen: exact conformance calls %d, exact encoders %d",
				len(exactCases), len(cg.surface.Exact))
		}
		if err := os.WriteFile(filepath.Join(testDir, "exact_conformance.rs"), []byte(exactConformance), 0644); err != nil {
			return err
		}
	}
	return nil
}

func execTmplWrite(tmpl *template.Template, name, path string, data any) error {
	var b strings.Builder
	if err := tmpl.ExecuteTemplate(&b, name, data); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func rustStringLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u{%x}`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func emitRustFixedTable(c *Catalog) string {
	var b strings.Builder
	b.WriteString("// encoding_id → fixed word (sorted for binary search)\n")
	b.WriteString("static FIXED: &[(&str, u32)] = &[\n")
	for _, e := range c.Entries {
		if !e.HasFixed {
			continue
		}
		fmt.Fprintf(&b, "    (%s, 0x%08X),\n", rustStringLiteral(e.EncodingID), e.FixedWord)
	}
	b.WriteString("];\n")
	return b.String()
}

func emitRustFieldsTable(c *Catalog) string {
	var b strings.Builder
	b.WriteString("// encoding_id → variable field layouts (sorted)\n")
	b.WriteString("static FIELDS: &[(&str, &[(&str, FieldLayout)])] = &[\n")
	for _, e := range c.Entries {
		var parts []string
		for _, f := range e.Fields {
			if f.Fixed || f.Name == "" {
				continue
			}
			parts = append(parts, fmt.Sprintf("(%s, FieldLayout { start: %d, end: %d, free: 0x%08X })",
				rustStringLiteral(f.Name), f.Start, f.End, f.Free))
		}
		if len(parts) == 0 {
			continue
		}
		fmt.Fprintf(&b, "    (%s, &[%s]),\n", rustStringLiteral(e.EncodingID), strings.Join(parts, ", "))
	}
	b.WriteString("];\n")
	return b.String()
}

func emitRustClassTable(c *Catalog) string {
	var b strings.Builder
	b.WriteString("// encoding_id → iclass (sorted)\n")
	b.WriteString("static ENCODING_CLASS: &[(&str, &str)] = &[\n")
	for _, e := range c.Entries {
		fmt.Fprintf(&b, "    (%s, %s),\n", rustStringLiteral(e.EncodingID), rustStringLiteral(e.Class))
	}
	b.WriteString("];\n")
	return b.String()
}

func emitRustDecodeTable(c *Catalog) string {
	var b strings.Builder
	b.WriteString("static TABLE: &[Entry] = &[\n")
	for _, e := range c.Entries {
		var fields []string
		for _, f := range e.Fields {
			fields = append(fields, fmt.Sprintf(
				"FieldDef { name: %s, start: %d, end: %d }",
				rustStringLiteral(f.Name), f.Start, f.End))
		}
		fieldLit := "&[]"
		if len(fields) > 0 {
			fieldLit = "&[" + strings.Join(fields, ", ") + "]"
		}
		fmt.Fprintf(&b,
			"    Entry { mask: 0x%08X, value: 0x%08X, mnemonic: %s, encoding_id: %s, class: %s, alias_of: %s, fields: %s, bitdiff: %s },\n",
			e.Mask, e.Value,
			rustStringLiteral(e.Mnemonic),
			rustStringLiteral(e.EncodingID),
			rustStringLiteral(e.Class),
			rustStringLiteral(e.AliasOf),
			fieldLit,
			emitRustBitDiff(e.BitDiffs),
		)
	}
	b.WriteString("];\n")
	return b.String()
}

type rustDecoderData struct {
	Table      string
	Nodes      string
	Edges      string
	Candidates string
	Untreed    string
	Root       string
}

type rustFlatNode struct {
	mask       uint32
	edges      []rustEdge
	candidates []uint16
}

type rustEdge struct {
	value uint32
	node  uint32
}

// buildRustDecoderData emits the same wildcard-aware decision tree used by the
// generated Go decoder. Rust used to ignore this tree and linearly scan the
// complete catalog while allocating a Vec and BTreeMap for every instruction.
func buildRustDecoderData(c *Catalog) (rustDecoderData, error) {
	if c == nil || len(c.Entries) == 0 {
		return rustDecoderData{}, fmt.Errorf("rust decoder: empty catalog")
	}
	if len(c.Entries) > int(^uint16(0)) {
		return rustDecoderData{}, fmt.Errorf("rust decoder: %d encodings exceed u16 index capacity", len(c.Entries))
	}

	instructions := make([]*ir.InstructionIR, 0, len(c.Entries))
	for _, e := range c.Entries {
		fields := make([]ir.BitField, 0, len(e.Fields))
		for _, f := range e.Fields {
			var fixed *uint64
			if f.Fixed {
				value := uint64(0)
				fixed = &value
			}
			fields = append(fields, ir.BitField{
				Name: f.Name, Start: f.Start, End: f.End, Fixed: fixed,
			})
		}
		instructions = append(instructions, &ir.InstructionIR{
			Mnemonic: e.Mnemonic, EncodingID: e.EncodingID, IClass: e.Class,
			BitPattern: e.Pattern, AliasOf: e.AliasOf, BitDiffsTree: e.BitDiffs,
			Encoding: ir.EncodingMask{Width: 32, Fields: fields},
		})
	}

	tree := (&decoder.DecoderTreeBuilder{}).BuildTree(instructions, nil)
	idIndex := make(map[string]uint16, len(c.Entries))
	for i, e := range c.Entries {
		idIndex[e.EncodingID] = uint16(i)
	}

	covered := make([]bool, len(c.Entries))
	var nodes []rustFlatNode
	var flatten func(*ir.DecoderNode) uint32
	flatten = func(n *ir.DecoderNode) uint32 {
		idx := uint32(len(nodes))
		nodes = append(nodes, rustFlatNode{})
		flat := rustFlatNode{mask: n.Mask}
		if n.Instruction != nil {
			if entry, ok := idIndex[n.Instruction.EncodingID]; ok {
				flat.candidates = append(flat.candidates, entry)
				covered[entry] = true
			}
		}
		for _, candidate := range n.Ambiguous {
			if candidate == nil {
				continue
			}
			if entry, ok := idIndex[candidate.EncodingID]; ok {
				flat.candidates = append(flat.candidates, entry)
				covered[entry] = true
			}
		}
		type child struct {
			value uint32
			node  *ir.DecoderNode
		}
		children := make([]child, 0, len(n.Children))
		for _, c := range n.Children {
			if c != nil {
				children = append(children, child{value: c.Value, node: c})
			}
		}
		sort.Slice(children, func(i, j int) bool { return children[i].value < children[j].value })
		for _, c := range children {
			flat.edges = append(flat.edges, rustEdge{value: c.value, node: flatten(c.node)})
		}
		nodes[idx] = flat
		return idx
	}

	root := "None"
	if tree != nil && tree.Root != nil {
		root = fmt.Sprintf("Some(%d)", flatten(tree.Root))
	}

	var edges []rustEdge
	var candidates []uint16
	var nodesLit strings.Builder
	nodesLit.WriteString("static NODES: &[Node] = &[\n")
	for _, node := range nodes {
		edgeStart := len(edges)
		candidateStart := len(candidates)
		edges = append(edges, node.edges...)
		candidates = append(candidates, node.candidates...)
		fmt.Fprintf(&nodesLit,
			"    Node { mask: 0x%08X, edge_start: %d, edge_len: %d, candidate_start: %d, candidate_len: %d },\n",
			node.mask, edgeStart, len(node.edges), candidateStart, len(node.candidates))
	}
	nodesLit.WriteString("];\n")

	var edgesLit strings.Builder
	edgesLit.WriteString("static EDGES: &[Edge] = &[\n")
	for _, edge := range edges {
		fmt.Fprintf(&edgesLit, "    Edge { value: 0x%08X, node: %d },\n", edge.value, edge.node)
	}
	edgesLit.WriteString("];\n")

	var candidatesLit strings.Builder
	candidatesLit.WriteString("static CANDIDATES: &[u16] = &[")
	for i, candidate := range candidates {
		if i > 0 {
			candidatesLit.WriteString(", ")
		}
		fmt.Fprintf(&candidatesLit, "%d", candidate)
	}
	candidatesLit.WriteString("];\n")

	var untreedLit strings.Builder
	untreedLit.WriteString("static UNTRED: &[u16] = &[")
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
	untreedLit.WriteString("];\n")

	return rustDecoderData{
		Table:      emitRustDecodeTable(c),
		Nodes:      nodesLit.String(),
		Edges:      edgesLit.String(),
		Candidates: candidatesLit.String(),
		Untreed:    untreedLit.String(),
		Root:       root,
	}, nil
}

func emitRustBitDiff(n *ir.BitDiffNode) string {
	if n == nil {
		return "None"
	}
	return "Some(&" + emitRustBitDiffNode(n) + ")"
}

func emitRustBitDiffNode(n *ir.BitDiffNode) string {
	if n == nil {
		return "BitDiff::Always"
	}
	switch n.Kind {
	case ir.BitDiffAnd:
		parts := make([]string, 0, len(n.Kids))
		for _, child := range n.Kids {
			parts = append(parts, emitRustBitDiffNode(child))
		}
		return "BitDiff::And(&[" + strings.Join(parts, ", ") + "])"
	case ir.BitDiffNot:
		if len(n.Kids) == 0 {
			return "BitDiff::Always"
		}
		return "BitDiff::Not(&" + emitRustBitDiffNode(n.Kids[0]) + ")"
	default:
		if n.Atom == nil || n.Atom.Start < 0 || n.Atom.End < n.Atom.Start || n.Atom.End > 31 {
			return "BitDiff::Always"
		}
		a := n.Atom
		op := "Eq"
		switch a.Op {
		case ir.BitDiffNe:
			op = "Ne"
		case ir.BitDiffIn:
			op = "In"
		}
		width := a.End - a.Start + 1
		alts := make([]string, 0, len(a.Alts))
		for _, alt := range a.Alts {
			mask, value := rustBitPattern(alt, width)
			alts = append(alts, fmt.Sprintf("BitPattern { mask: 0x%08X, value: 0x%08X }", mask, value))
		}
		mask, value := rustBitPattern(a.Bits, width)
		return fmt.Sprintf(
			"BitDiff::Atom { start: %d, end: %d, op: BitDiffOp::%s, bits: BitPattern { mask: 0x%08X, value: 0x%08X }, alts: &[%s] }",
			a.Start, a.End, op, mask, value, strings.Join(alts, ", "))
	}
}

// rustBitPattern mirrors ir's bitdiff normalization and compiles a textual
// MSB-first 0/1/x value into a mask/value pair over the extracted field.
func rustBitPattern(pattern string, width int) (mask, value uint32) {
	pattern = strings.TrimSpace(pattern)
	pattern = strings.Trim(pattern, "'\"()")
	var normalized strings.Builder
	for _, r := range pattern {
		if r == '0' || r == '1' || r == 'x' || r == 'X' {
			normalized.WriteRune(r)
		}
	}
	pattern = normalized.String()
	if len(pattern) < width {
		pattern = strings.Repeat("0", width-len(pattern)) + pattern
	} else if len(pattern) > width {
		pattern = pattern[len(pattern)-width:]
	}
	for i := 0; i < len(pattern); i++ {
		shift := uint(len(pattern) - 1 - i)
		switch pattern[i] {
		case '0':
			mask |= 1 << shift
		case '1':
			mask |= 1 << shift
			value |= 1 << shift
		}
	}
	return mask, value
}

func emitRustRegistryTable(c *Catalog) string {
	var b strings.Builder
	b.WriteString("pub static ALL: &[Instruction] = &[\n")
	for _, e := range c.Entries {
		fmt.Fprintf(&b,
			"    Instruction { encoding_id: %s, mnemonic: %s, class: %s, bit_pattern: %s, fixed_word: 0x%08X, has_fixed: %v, iform_file: %s, asm: %s, alias_of: %s },\n",
			rustStringLiteral(e.EncodingID),
			rustStringLiteral(e.Mnemonic),
			rustStringLiteral(e.Class),
			rustStringLiteral(e.Pattern),
			e.FixedWord, e.HasFixed,
			rustStringLiteral(e.IFormFile),
			rustStringLiteral(e.Asm),
			rustStringLiteral(e.AliasOf),
		)
	}
	b.WriteString("];\n")
	return b.String()
}

// surfaceHasAll reports whether every named method was generated.
func (cg *CodeGenerator) surfaceHasAll(methods ...string) bool {
	if cg.surface == nil {
		return false
	}
	for _, m := range methods {
		if len(cg.surface.Methods[m]) == 0 {
			return false
		}
	}
	return true
}
