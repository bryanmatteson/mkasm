package arm

import (
	"sort"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// CodegenLang is a Pass 3 emission target.
type CodegenLang string

const (
	LangGo   CodegenLang = "go"
	LangRust CodegenLang = "rust"
)

// Catalog is the language-agnostic Pass 3 model shared by Go and Rust emitters.
type Catalog struct {
	Entries []CatalogEntry
	Classes []CatalogClass
}

// CatalogClass groups encodings by IClass for per-class encoder files (Go).
type CatalogClass struct {
	Name      string
	TypeName  string // Go exported type stem
	FieldName string // Go struct field
	Entries   []CatalogEntry
}

// CatalogEntry is one encoding ready for encode/decode/registry emission.
type CatalogEntry struct {
	EncodingID string
	Mnemonic   string
	Class      string
	Pattern    string
	AliasOf    string
	Asm        string
	IFormFile  string
	Mask       uint32
	Value      uint32
	FixedWord  uint32
	HasFixed   bool
	Fields     []CatalogField
	BitDiffs   *ir.BitDiffNode
}

// CatalogField is a named bitfield layout.
type CatalogField struct {
	Name       string
	Start, End int
	Fixed      bool
	// Free marks the bits inside [Start,End] that the encoding leaves variable,
	// as absolute bit positions. A field can be partly pinned — SMSTOP pins
	// CRm<0> to 0 while CRm<2:1> vary — so writing the whole range blind
	// produces a word belonging to a different encoding.
	Free uint32
}

// BuildCatalog projects resolved IR into the shared codegen model.
func BuildCatalog(instructions []*ir.InstructionIR) *Catalog {
	sorted := append([]*ir.InstructionIR(nil), instructions...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].EncodingID < sorted[j].EncodingID
	})

	entries := make([]CatalogEntry, 0, len(sorted))
	byClass := map[string][]CatalogEntry{}
	classOrder := []string{}

	for _, instr := range sorted {
		if instr == nil || instr.EncodingID == "" {
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
		fw, hasFW := ir.FixedWord(instr)
		var fields []CatalogField
		for _, f := range instr.Encoding.Fields {
			if f.Name == "" || f.Start < 0 || f.End < f.Start {
				continue
			}
			fields = append(fields, CatalogField{
				Name: f.Name, Start: f.Start, End: f.End, Fixed: f.Fixed != nil,
				Free: fieldRangeMask(f.Start, f.End) &^ mask,
			})
		}
		asm := ""
		if instr.Asm.Raw != "" {
			asm = instr.Asm.Raw
		}
		e := CatalogEntry{
			EncodingID: instr.EncodingID,
			Mnemonic:   instr.Mnemonic,
			Class:      instr.IClass,
			Pattern:    pat,
			AliasOf:    instr.AliasOf,
			Asm:        asm,
			IFormFile:  instr.IFormFile,
			Mask:       mask,
			Value:      value,
			FixedWord:  fw,
			HasFixed:   hasFW,
			Fields:     fields,
			BitDiffs:   instr.BitDiffsTree,
		}
		entries = append(entries, e)
		if _, ok := byClass[instr.IClass]; !ok {
			classOrder = append(classOrder, instr.IClass)
		}
		byClass[instr.IClass] = append(byClass[instr.IClass], e)
	}
	sort.Strings(classOrder)

	classes := make([]CatalogClass, 0, len(classOrder))
	for _, name := range classOrder {
		field := cleanIdentifier(name)
		if field == "" {
			field = "cls"
		}
		fieldName := strings.ToLower(field[:1]) + field[1:]
		classes = append(classes, CatalogClass{
			Name:      name,
			TypeName:  formatClassName(name),
			FieldName: fieldName,
			Entries:   byClass[name],
		})
	}
	return &Catalog{Entries: entries, Classes: classes}
}
