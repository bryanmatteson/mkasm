package codec

import (
	_ "embed"
	"encoding/json"
	"fmt"
	objectapi "github.com/bryanmatteson/mkasm/pkg/object"
	assettemplates "github.com/bryanmatteson/mkasm/templates"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/bryanmatteson/mkasm/pkg/ir"

	"github.com/bryanmatteson/mkasm/pkg/semantics"
)

//go:embed runtime.rs.tmpl
var rustRuntime string

//go:embed analysis.rs.tmpl
var rustAnalysis string

//go:embed references.rs.tmpl
var rustReferences string

//go:embed recipes.rs.tmpl
var rustRecipes string

//go:embed corpus.rs.tmpl
var rustCorpus string

// rustTables shares immutable metadata across encodings. Keeping these lists
// outside ENCODINGS also bounds the size of the initializer rustc must check.
type rustTables[T any] struct {
	indices map[string]int
	values  []T
}

func (t *rustTables[T]) intern(value T) int {
	key, _ := json.Marshal(value)
	if index, exists := t.indices[string(key)]; exists {
		return index
	}
	if t.indices == nil {
		t.indices = make(map[string]int)
	}
	index := len(t.values)
	t.indices[string(key)] = index
	t.values = append(t.values, value)
	return index
}

// Coalesce adjacent pieces of the same field before interning. TableGen often
// describes these one bit at a time; the generated codec can copy a contiguous
// run a byte at a time and share identical operand tables across source layouts.
// Work on copies so generation never changes the imported catalog.
func rustOperands(operands []Operand) []Operand {
	result := append([]Operand(nil), operands...)
	for i := range result {
		bits := append([]BitSlice(nil), result[i].Bits...)
		sort.SliceStable(bits, func(i, j int) bool { return bits[i].InstructionBit < bits[j].InstructionBit })
		merged := bits[:0]
		for _, b := range bits {
			if len(merged) > 0 {
				last := &merged[len(merged)-1]
				if last.InstructionBit+last.Width == b.InstructionBit && last.ValueBit+last.Width == b.ValueBit {
					last.Width += b.Width
					continue
				}
			}
			merged = append(merged, b)
		}
		var chunks []BitSlice
		for _, b := range merged {
			for b.Width > 0 {
				n := min(b.Width, 8-b.InstructionBit%8)
				chunks = append(chunks, BitSlice{b.InstructionBit, b.ValueBit, n})
				b.InstructionBit += n
				b.ValueBit += n
				b.Width -= n
			}
		}
		result[i].Bits = chunks
	}
	return result
}

// WriteLicense installs the license for the generated runtime implementation.
// Specification importers retain upstream corpus notices alongside their source.
func WriteLicense(output string) error {
	return os.WriteFile(filepath.Join(output, "LICENSE"), []byte(generatedLicense), 0644)
}

// GenerateRust emits a standalone dependency-free Rust codec. Every instruction
// from the imported catalog has an exact encoder, structured decode, formatting,
// text assembly and an exhaustive generated round-trip test.
func (c *Catalog) GenerateRust(output string) (generationError error) {
	defer func() {
		if generationError == nil {
			generationError = objectapi.InstallRust(output)
		}
	}()

	if err := c.Validate(); err != nil {
		return err
	}
	if output == "" {
		return fmt.Errorf("empty output directory")
	}
	var b strings.Builder
	numbers, err := template.New("numbers").ParseFS(assettemplates.FS, "rust/number_text.rs.tmpl")
	if err != nil {
		return err
	}
	if err := numbers.ExecuteTemplate(&b, "number_text", nil); err != nil {
		return err
	}
	maxOperands := 1
	var nameTables rustTables[[]string]
	var commaNames rustTables[[]string]
	commaNames.intern([]string{})
	var parsedNameTables rustTables[[]rustOperandName]
	parsedNameTables.intern([]rustOperandName{})
	var tupleTables rustTables[[][]int64]
	var operandTables rustTables[[]Operand]
	var domains rustTables[rustOperandDomain]
	var constraintTables rustTables[[]Constraint]
	var featureTables rustTables[[]string]
	type encodingTables struct{ operands, constraints, features int }
	encodingMetadata := make([]encodingTables, len(c.Encodings))
	for i, e := range c.Encodings {
		indices := encodingTables{-1, -1, -1}
		if len(e.Operands) > 0 {
			indices.operands = operandTables.intern(rustOperands(e.Operands))
		}
		if len(e.Constraints) > 0 {
			indices.constraints = constraintTables.intern(e.Constraints)
		}
		if len(e.Features) > 0 {
			indices.features = featureTables.intern(e.Features)
		}
		encodingMetadata[i] = indices
		if len(e.Operands) > maxOperands {
			maxOperands = len(e.Operands)
		}
	}
	for _, table := range constraintTables.values {
		for _, constraint := range table {
			if len(constraint.Allowed) > 0 {
				tupleTables.intern(constraint.Allowed)
			}
		}
	}
	for _, table := range operandTables.values {
		for _, o := range table {
			parsedNameTables.intern(prepareRustOperandNames(o))
			domains.intern(prepareRustOperandDomain(o))
			if rustCommaNames(o) {
				commaNames.intern(o.Names)
			}
			if len(o.Names) > 0 {
				nameTables.intern(o.Names)
			}
		}
	}
	fmt.Fprintf(&b, "type OperandDomainIndex=%s;\n", rustOperandDomainIndexType(len(domains.values)))
	b.WriteString("static OPERAND_DOMAINS:&[Domain]=&[\n")
	for _, d := range domains.values {
		fmt.Fprintf(&b, "Domain{min:%s,max:%s,step:%s,exact:%t},\n", d.Min, d.Max, d.Step, d.Exact)
	}
	b.WriteString("];\n")
	b.WriteString("static OPERAND_NAMES:&[&[(&str,u64)]]=&[\n")
	for _, table := range parsedNameTables.values {
		b.WriteString("&[")
		for _, name := range table {
			fmt.Fprintf(&b, "(%s,%d),", rustQuote(name.Name), name.Raw)
		}
		b.WriteString("],\n")
	}
	b.WriteString("];\n")
	b.WriteString("static COMMA_NAMES:&[&[&str]]=&[\n")
	for _, names := range commaNames.values {
		b.WriteString("&[")
		for _, name := range names {
			if name != "" {
				name += ", "
			}
			fmt.Fprintf(&b, "%s,", rustQuote(name))
		}
		b.WriteString("],\n")
	}
	b.WriteString("];\n")
	for i, table := range nameTables.values {
		fmt.Fprintf(&b, "static REGISTER_NAMES_%d:&[&str]=&[", i)
		for _, name := range table {
			fmt.Fprintf(&b, "%s,", rustQuote(name))
		}
		b.WriteString("];\n")
	}
	for i, table := range tupleTables.values {
		fmt.Fprintf(&b, "static TUPLE_DOMAIN_%d:&[&[i128]]=&[", i)
		for _, row := range table {
			b.WriteString("&[")
			for _, value := range row {
				fmt.Fprintf(&b, "%d,", value)
			}
			b.WriteString("],")
		}
		b.WriteString("];\n")
	}
	for i, table := range featureTables.values {
		fmt.Fprintf(&b, "static FEATURES_%d:&[&str]=&[", i)
		for _, f := range table {
			fmt.Fprintf(&b, "%s,", rustQuote(f))
		}
		b.WriteString("];\n")
	}
	for i, table := range operandTables.values {
		fmt.Fprintf(&b, "static OPERANDS_%d:&[Operand]=&[", i)
		for _, o := range table {
			scale := o.Scale
			if scale == 0 {
				scale = 1
			}
			fmt.Fprintf(&b, "Operand{name:%s,kind:%s,class:%s,signed:%t,input_signed_bits:%d,implicit:%t,optional:%t,scale:%d,bias:%d,bias_operand:%s,bias_scale:%d,xor:%d,relative:%t,pc_bias:%d,pc_pre_align_bias:%d,pc_align_bits:%d,pc_region_bits:%d,pc_wrap_bits:%d,pc_low_wrap_bits:%d,pc_bank_bits:%d,prefix:%s,identity_names:%t,bits:&[", rustQuote(o.Name), rustQuote(o.Kind), rustQuote(o.Class), o.Signed, o.InputSignedBits, o.Implicit, o.Optional, scale, o.Bias, rustQuote(o.BiasOperand), o.BiasScale, o.Xor, o.Relative, o.PCBias, o.PCPreAlignBias, o.PCAlignBits, o.PCRegionBits, o.PCWrapBits, o.PCLowWrapBits, o.PCBankBits, rustQuote(o.RegisterPrefix), len(o.Names) > 0 && scale == 1 && o.Bias == 0 && o.BiasOperand == "" && len(o.Lookup) == 0)
			for _, s := range o.Bits {
				fmt.Fprintf(&b, "BitSlice{instruction:%d,value:%d,width:%d},", s.InstructionBit, s.ValueBit, s.Width)
			}
			if len(o.Names) == 0 {
				b.WriteString("],names:&[]")
			} else {
				fmt.Fprintf(&b, "],names:REGISTER_NAMES_%d", nameTables.intern(o.Names))
			}
			b.WriteString(",lookup:&[")
			for _, value := range o.Lookup {
				fmt.Fprintf(&b, "%d,", value)
			}
			b.WriteString("],aliases:&[")
			var keys []string
			for k := range o.RegisterAliases {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "(%s,%d),", rustQuote(k), o.RegisterAliases[k])
			}
			commaIndex := 0
			if rustCommaNames(o) {
				commaIndex = commaNames.intern(o.Names)
			}
			fmt.Fprintf(&b, "],name_index:%d,comma_names:%d,encoded_width:%d,domain_index:%d},", parsedNameTables.intern(prepareRustOperandNames(o)), commaIndex, o.Width(), domains.intern(prepareRustOperandDomain(o)))
		}
		b.WriteString("];\n")
	}
	for i, table := range constraintTables.values {
		fmt.Fprintf(&b, "static CONSTRAINTS_%d:&[Constraint]=&[", i)
		for _, v := range table {
			fmt.Fprintf(&b, "Constraint{kind:%s,left:%s,right:%s,unless_zero:%s,limit:%d,left_when_mask:%d,right_when_mask:%d,equal_mask:%d,left_span:%d,right_span:%d,operands:&[", rustQuote(v.Kind), rustQuote(v.Left), rustQuote(v.Right), rustQuote(v.UnlessZero), v.Limit, v.LeftWhenMask, v.RightWhenMask, v.EqualMask, v.LeftSpan, v.RightSpan)
			for _, name := range v.Operands {
				fmt.Fprintf(&b, "%s,", rustQuote(name))
			}
			b.WriteString("],allowed:")
			if len(v.Allowed) > 0 {
				fmt.Fprintf(&b, "TUPLE_DOMAIN_%d", tupleTables.intern(v.Allowed))
			} else {
				b.WriteString("&[]")
			}
			b.WriteString("},")
		}
		b.WriteString("];\n")
	}
	fmt.Fprintf(&b, "pub const ARCHITECTURE: &str = %s;\npub static ENCODINGS: &[Encoding] = &[\n", rustQuote(c.Architecture))
	for i, e := range c.Encodings {
		fixedTarget := "None"
		if e.FixedTarget != nil {
			fixedTarget = fmt.Sprintf("Some(%d)", *e.FixedTarget)
		}
		valueFlags := 0
		for _, o := range e.Operands {
			if o.BiasOperand != "" {
				valueFlags |= 1
			}
			if o.Implicit {
				valueFlags |= 2
			}
		}
		fmt.Fprintf(&b, "Encoding{id:%s,mnemonic:%s,syntax:%s,mask:&%s,value:&%s,flow_control:%s,fixed_target:%s,target_mask:%d,assembly_only:%t,value_flags:%d,delay_slots:%d,", rustQuote(e.ID), rustQuote(e.Mnemonic), rustQuote(e.Syntax), rustBytes(e.Mask), rustBytes(e.Value), rustQuote(e.FlowControl), fixedTarget, e.TargetMask, e.AssemblyOnly, valueFlags, e.DelaySlots)
		for _, field := range []struct {
			name  string
			index int
		}{{"features", encodingMetadata[i].features}, {"operands", encodingMetadata[i].operands}, {"constraints", encodingMetadata[i].constraints}} {
			if field.index < 0 {
				fmt.Fprintf(&b, "%s:&[],", field.name)
			} else {
				fmt.Fprintf(&b, "%s:%s_%d,", field.name, strings.ToUpper(field.name), field.index)
			}
		}
		b.WriteString("},\n")
	}
	b.WriteString("];\n")
	fmt.Fprintf(&b, "pub const MAX_OPERANDS: usize = %d;\n", maxOperands)
	ids := make([]int, len(c.Encodings))
	for i := range ids {
		ids[i] = i
	}
	sort.Slice(ids, func(i, j int) bool { return c.Encodings[ids[i]].ID < c.Encodings[ids[j]].ID })
	b.WriteString("static ENCODING_IDS: &[(&str,usize)] = &[\n")
	for _, index := range ids {
		fmt.Fprintf(&b, "(%s,%d),\n", rustQuote(c.Encodings[index].ID), index)
	}
	b.WriteString("];\n")
	b.WriteString("pub static UNSUPPORTED: &[(&str,&str)] = &[\n")
	for _, u := range c.Unsupported {
		fmt.Fprintf(&b, "(%s,%s),\n", rustQuote(u.ID), rustQuote(u.Reason))
	}
	b.WriteString("];\n")
	dispatch := dispatchByte(c.Encodings)
	fmt.Fprintf(&b, "pub const DISPATCH_BYTE: usize = %d;\n", dispatch)
	writeRustDecodeTree(&b, c.Encodings)
	writeRustSyntaxTables(&b, c.Encodings)
	mnemonics := map[string][]int{}
	var dynamic []int
	for i, e := range c.Encodings {
		key := strings.ToLower(strings.Fields(e.Syntax)[0])
		if strings.Contains(key, "{") {
			dynamic = append(dynamic, i)
		} else {
			mnemonics[key] = append(mnemonics[key], i)
		}
	}
	var mnkeys []string
	for key := range mnemonics {
		mnkeys = append(mnkeys, key)
	}
	sort.Strings(mnkeys)
	b.WriteString("static MNEMONICS: &[(&str,&[u32],&[u32])] = &[\n")
	for _, key := range mnkeys {
		fmt.Fprintf(&b, "(%s,&[", rustQuote(key))
		for _, i := range mnemonics[key] {
			fmt.Fprintf(&b, "%d,", i)
		}
		b.WriteString("],&[")
		for _, i := range rustShortestCandidates(c.Encodings, mnemonics[key]) {
			fmt.Fprintf(&b, "%d,", i)
		}
		b.WriteString("]),\n")
	}
	b.WriteString("];\nstatic DYNAMIC_MNEMONICS:&[u32]=&[")
	for _, i := range dynamic {
		fmt.Fprintf(&b, "%d,", i)
	}
	b.WriteString("];\n")
	b.WriteString("static DYNAMIC_MNEMONICS_SHORTEST:&[u32]=&[")
	for _, i := range rustShortestCandidates(c.Encodings, dynamic) {
		fmt.Fprintf(&b, "%d,", i)
	}
	b.WriteString("];\n")
	b.WriteString("pub static FEATURE_SETS: &[(&str,&[&str])] = &[\n")
	var profiles []string
	for k := range c.FeatureSets {
		profiles = append(profiles, k)
	}
	sort.Strings(profiles)
	for _, p := range profiles {
		fmt.Fprintf(&b, "(%s,&[", rustQuote(p))
		for _, f := range c.FeatureSets[p] {
			fmt.Fprintf(&b, "%s,", rustQuote(f))
		}
		b.WriteString("]),\n")
	}
	b.WriteString("];\n")
	source := strings.Replace(rustRuntime, "// __MKASM_DATA__", b.String(), 1) + rustAnalysis + rustRecipes + rustReferences + "\n#[path=\"effects.rs\"] pub mod effects;\npub use effects::*;\n"
	name := strings.ReplaceAll(c.Architecture, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	if err := os.MkdirAll(filepath.Join(output, "src"), 0755); err != nil {
		return err
	}
	if err := semantics.WriteRust(filepath.Join(output, "src")); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(output, "tests"), 0755); err != nil {
		return err
	}
	requirements := make(map[string]ir.Requirements, len(c.Encodings))
	for _, e := range c.Encodings {
		requirements[e.ID] = encodingRequirements(e)
	}
	if err := os.WriteFile(filepath.Join(output, "src", "requirements.rs"), []byte(EmitRustRequirements(requirements)), 0644); err != nil {
		return err
	}
	field, decoder := "Decoded", "decode_with_features"
	switch c.Architecture {
	case "hexagon":
		field, decoder = "DecodedWord", "decode_word_with_features"
	case "xtensa", "xtensaeb":
		field, decoder = "DecodedField", "decode_field_with_features"
	case "z80", "z180":
		field, decoder = "DecodedBody", "decode_body_with_features"
	}
	corpus := fmt.Sprintf("use %s::{%s as Field, %s as decode_field_api, representative_with_seed, ENCODINGS, FEATURE_SETS, MAX_OPERANDS};\n", name, field, decoder) + rustCorpus
	readme := fmt.Sprintf("# %s instruction codec\n\nGenerated from %s. The catalog contains %d encoding/syntax forms; %d source records are explicitly unsupported and listed in `UNSUPPORTED` and `catalog.json`.\n\n`decode` returns a stable catalog index, consumed length and structured operand values without allocating. `encode_into` encodes into caller-owned storage; `encode` is an allocating convenience. `Decoded::format`, `assemble_at`, and `Template` support instruction text. `Decoded::write_to` appends to a caller-owned `fmt::Write` without codec allocations. A reusable `Assembler` normalizes input in retained storage and `assemble_into` writes the first shortest legal encoding into a caller buffer without allocating once input capacity is sufficient; failures leave the destination unchanged. `Decoded::describe` returns semantic operand spans, source classes, domains and address positions. Validated `set_operand`, `relocated` and `relocate_into` preserve exact forms and leave storage unchanged on failure. Templates expose holes, domains, positions, encoding IDs and opcode filters; `for_encoding` also opens ignored fields.\n\nUse `decode_with_features`/`assemble_with_features` and a named `profile` to select conflicting processor instruction sets. An omitted feature filter admits the union of imported extensions. Operand values follow each encoding's `operands` order and its signed/scaled value model; `representative` and `representative_with_seed` return legal sample values. Domains marked `exact == false` are conservative bounds; full encoding checks relational constraints.\n\nGenerated tests cover every emitted form with three legal samples, descriptions, templates and relocation, in addition to full byte/text round trips. `MKASM_CORPUS_LEDGER_DIR` optionally records the IDs actually exercised for comparison with the exported corpus.\n\nThe runtime does not execute instructions, resolve object relocations, or implement a decompiler. Build and test with `cargo test --lib`.\n", c.Architecture, c.Source, len(c.Encodings), len(c.Unsupported))
	license := "MIT"
	if c.SourceLicenseID != "" {
		license = c.SourceLicenseID
		readme += "\nSource metadata and the combined crate are distributed under " + license + "; see UPSTREAM-LICENSE. The runtime implementation retains its MIT notice in LICENSE.\n"
	}
	for path, data := range map[string]string{"Cargo.toml": fmt.Sprintf("[package]\nname = %s\nversion = \"0.1.0\"\nedition = \"2021\"\nlicense = %s\n\n[lib]\npath = \"src/lib.rs\"\n", rustQuote(name), rustQuote(license)), "src/lib.rs": source, "src/effects.rs": c.rustEffects(), "tests/positions.rs": corpus, "LICENSE": generatedLicense, "README.md": readme} {
		if err := os.WriteFile(filepath.Join(output, path), []byte(data), 0644); err != nil {
			return err
		}
	}
	file, err := os.Create(filepath.Join(output, "catalog.json"))
	if err != nil {
		return err
	}
	if err = c.WriteJSON(file); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if c.SourceLicense != "" {
		if err := os.WriteFile(filepath.Join(output, "UPSTREAM-LICENSE"), []byte(c.SourceLicense), 0644); err != nil {
			return err
		}
	}
	return nil
}

// Pick a discriminator inside the shortest form. In little-endian instruction
// sets the major opcode often lives in the final byte rather than byte zero.
func dispatchByte(encodings []Encoding) int {
	minimum := len(encodings[0].Mask)
	for _, e := range encodings {
		if len(e.Mask) < minimum {
			minimum = len(e.Mask)
		}
	}
	best, bestMaximum, bestTotal := 0, int(^uint(0)>>1), int(^uint(0)>>1)
	for offset := 0; offset < minimum; offset++ {
		maximum, total := 0, 0
		for value := 0; value < 256; value++ {
			count := 0
			for _, e := range encodings {
				if !e.AssemblyOnly && byte(value)&e.Mask[offset] == e.Value[offset] {
					count++
				}
			}
			if count > maximum {
				maximum = count
			}
			total += count
		}
		if maximum < bestMaximum || maximum == bestMaximum && total < bestTotal {
			best, bestMaximum, bestTotal = offset, maximum, total
		}
	}
	return best
}

func rustQuote(s string) string {
	// JSON quoting is almost Rust quoting; Go's \x and \a escapes are not Rust
	// string escapes, so encode control characters explicitly as Unicode.
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 32 || r == 127 {
				fmt.Fprintf(&b, "\\u{%x}", r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}
func rustBytes(bytes []byte) string {
	parts := make([]string, len(bytes))
	for i, b := range bytes {
		parts[i] = strconv.Itoa(int(b))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

const generatedLicense = `MIT License

Copyright (c) 2026 Bryan Matteson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`
