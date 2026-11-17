package hexagon

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

//go:embed runtime.rs.tmpl
var runtime string

//go:embed analysis.rs.tmpl
var analysis string

//go:embed testdata/LICENSE.LLVM
var llvmLicense string

func (c *Catalog) GenerateRust(output string) error {
	combined := &codec.Catalog{Schema: codec.Schema, Architecture: "hexagon", Source: "LLVM 22.1.8 Hexagon TableGen records", FeatureSets: c.FeatureSets, Unsupported: c.Unsupported}
	combined.Encodings = append(append([]codec.Encoding{}, c.Words.Encodings...), c.Subinstructions.Encodings...)
	if err := combined.GenerateRust(output); err != nil {
		return err
	}
	path := filepath.Join(output, "src/lib.rs")
	source, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	text := string(source)
	// Keep exact standalone fields available as explicitly named word APIs. The
	// standard public decode/assembly names below operate on complete packets.
	names := map[string]string{"Decoded": "DecodedWord", "Assembler": "WordAssembler", "Template": "WordTemplate", "decode": "decode_word", "decode_with_features": "decode_word_with_features", "assemble": "assemble_word", "assemble_at": "assemble_word_at", "assemble_with_features": "assemble_word_with_features", "describe": "describe_word", "describe_with_features": "describe_word_with_features"}
	for old, newName := range names {
		text = regexp.MustCompile(`\b`+old+`\b`).ReplaceAllString(text, newName)
	}
	var meta strings.Builder
	meta.WriteString("\nstatic PACKET_META:&[PacketMeta]=&[\n")
	for _, e := range combined.Encodings {
		m := c.Metadata[e.ID]
		operandIndex := func(name string) int {
			for n, o := range e.Operands {
				if o.Name == name {
					return n
				}
			}
			return -1
		}
		var producers []string
		for _, p := range m.Producers {
			if n := operandIndex(p); n >= 0 {
				producers = append(producers, strconv.Itoa(n))
			}
		}
		group := m.SubGroup
		if m.Type != "TypeSUBINSN" {
			group = ""
		}
		fmt.Fprintf(&meta, "PacketMeta{group:%q,extender:%t,extendable:%t,must_extend:%t,extend:%d,align:%d,signed:%t,new_value:%d,producers:&[%s],vector:%t,solo:%t},\n", group, m.Type == "TypeEXTENDER", m.Extendable, m.MustExtend, operandIndex(m.ExtendOperand), m.ExtentAlign, m.ExtentSigned, operandIndex(m.NewValueUse), strings.Join(producers, ","), m.Vector, m.Solo)
	}
	meta.WriteString("];\n")
	text += meta.String() + runtime + analysis
	if err := os.WriteFile(path, []byte(text), 0644); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(output, "catalog.json"))
	if err != nil {
		return err
	}
	err = json.NewEncoder(f).Encode(c)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.WriteFile(filepath.Join(output, "LICENSE.LLVM"), []byte(llvmLicense), 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(output, "README.md"), []byte(generatedREADME), 0644)
}

const generatedREADME = `# Hexagon packet codec

Generated from the complete LLVM 22.1.8 Hexagon instruction and InstAlias records.
The standalone dependency-free crate implements packet framing, 15 duplex classes,
immediate extenders, new-value producer references, source operand classes,
processor feature profiles, structured encode/decode, text assembly and templates.

Use decode/decode_with_features for complete packets. Packet.length is the consumed
byte count (4..16). Packet.words retain physical order, including explicit extender
words. encode_packet reconstructs framing and also inserts extenders requested by
extended immediates. Packet::format(address) and assemble_at support packet text;
two compact subinstructions separated by a semicolon denote one duplex word.
Template binds $name operand holes and _ wildcards over complete packets.
Operand values are semantic register encodings and assembler immediate values; branch
values are byte displacements from the packet address. The catalog retains every
encoding's exact operand order and source register class.

The explicitly named decode_word/assemble_word and WordTemplate APIs expose the
underlying fields for analysis. Their results alone are not a legal packet.

Packet encoding preserves caller word order. It validates framing, bounded word
and instruction counts, extender use, operand domains, new-value references and
solo instructions. It does not perform LLVM's slot scheduling/resource allocation,
all predicate dependency checks, register hazard checking, relocation resolution,
constant-pool/compiler pseudo lowering, or validate arbitrary packets for execution.
The two constant-pool forms, two assembler parser rewrites, two relocation
fragments, internal decoder sentinel and reserved duplex class are named with
exact diagnostics in UNSUPPORTED/catalog.json. TFRI64_V2_ext rewrites to the
supported A2_combineii spelling. TFRI64_V4 decomposes a register-pair constant
into A4_combineii's signed high32 (limited to int8) and unsigned low32, optionally
with A4_ext. Use that physical combine syntax here; complete-program object
assembly handles the original pair-constant spelling and symbolic relocations.
Neither parser record is an independent opcode. No unsupported
source record is silently claimed as an instruction. An omitted feature filter
accepts the union of target extensions; profile(name) selects the imported CPU.

Run cargo test --lib. MIT runtime license is in LICENSE; the source corpus retains
LLVM's Apache-2.0 WITH LLVM-exception notice in the importer fixture directory.
`
