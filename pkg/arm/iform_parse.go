package arm

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// ParsedIForm is the authoritative content extracted from an instructionsection XML file
// for one encoding (matched by EncodingID / encoding@name).
type ParsedIForm struct {
	EncodingName string
	Mnemonic     string
	// AliasMnemonic is the preferred disassembly on an alias page (docvar
	// alias_mnemonic), e.g. ASR for the ASRV encoding it aliases.
	AliasMnemonic string
	// AsmTemplate is the encoding's syntax exactly as ARM writes it, spacing
	// included: "LDR  <Wt>, [<Xn|SP>{, #<pimm>}]". Whitespace is load-bearing —
	// it is what separates the mnemonic from its first operand when the text is
	// printed back out.
	AsmTemplate string
	// AsmSuffix is the literal template text after the last operand. It holds
	// the closing brackets of every memory form ("}]" for LDR's unsigned offset,
	// "]" for LD1's list form), which have no operand to hang off as a Prefix.
	AsmSuffix string
	// AsmOperands are the <a> operand references inside this encoding's
	// asmtemplate, in source order. ARM's hover text names both the operand's
	// type and the bit field that encodes it, which is what makes a typed
	// assembler surface generatable rather than guessed.
	AsmOperands []AsmOperand
	// EquivalentOperands are operands named only by an alias's
	// <equivalent_to> expansion. They can carry fixed defaults for fields the
	// alias syntax hides entirely, such as SYS's optional Rt = 11111 behind
	// the bare GCSPOPX mnemonic.
	EquivalentOperands []AsmOperand
	// EquivalentSuffix is the literal after the final equivalent operand. It
	// completes relations split around an anchor, such as #(-<const> - 1).
	EquivalentSuffix string
	// Explanations is ARM's operand documentation for this instruction page:
	// field bindings and enumerated value tables. Not filtered by encoding —
	// use ExplanationsFor.
	Explanations []AsmExplanation
	BitDiffs     string
	Boxes        []RegBox
	Pseudocode   []string
	Features     []string
	// IsAlias is true when instructionsection@type="alias".
	IsAlias bool
	// AliasOf is the canonical EncodingID when known (from asmtemplate href fragment).
	AliasOf string
	// AliasCond is ARM's equality condition for the alias spelling. Besides
	// deciding decode preference, it fixes fields hidden by the alias template:
	// MOV Vd,Vn aliases ORR Vd,Vn,Vn, so Rm must mirror Rn.
	AliasCond string
}

// AsmOperand is one operand reference from an encoding's asmtemplate.
type AsmOperand struct {
	// Symbol is the placeholder as written, e.g. "<Xn|SP>" or "<T>".
	Symbol string
	// Link is ARM's operand-class id, e.g. "XnSP_option". Stable across
	// instructions, so it groups operands that share a type.
	Link string
	// Hover is ARM's prose description of the operand.
	Hover string
	// Field is the bit field Hover names ("encoded in the \"Rn\" field"),
	// empty when the prose does not state one.
	Field string
	// Prefix is the literal template text between the previous operand and this
	// one, kept untrimmed. It is the only thing that distinguishes "SADDLV
	// <V><d>" — where <V> is a width specifier sizing <d> — from "SSHR D<d>",
	// where the width is a literal. Empty means the two operands are adjacent.
	Prefix string
}

// hoverField pulls the encoding field out of ARM's operand prose without
// invoking the regexp engine on every operand.
func hoverField(hover string) string {
	const prefix = `encoded in the "`
	start := strings.Index(hover, prefix)
	if start < 0 {
		return ""
	}
	start += len(prefix)
	end := start
	for end < len(hover) && isFieldNameByte(hover[end]) {
		end++
	}
	if end == start || !strings.HasPrefix(hover[end:], `" field`) {
		return ""
	}
	return hover[start:end]
}

func isFieldNameByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

// RegBox is a <regdiagram>/<box> field, or a per-<encoding> override box.
type RegBox struct {
	Name  string
	HiBit int
	Width int
	// Bits holds one character per bit, MSB first (Bits[0] is HiBit):
	// '0'/'1' fixed, 'x' variable, '-' inherit from the iclass diagram.
	// Per-bit resolution is required because ARM diagrams mix fixed and
	// variable bits inside one box (e.g. size with psbits "xx" and <c>1</c><c>x</c>).
	Bits  string
	Fixed *uint64 // set only when every bit in Bits is 0 or 1
	// NotEq holds the excluded value from a "!= 0000" style cell, width-aligned
	// with the box ('x' = don't-care). ARM uses it to carve one encoding out of
	// another's space — SSHR (vector) requires immh != 0000, which is what keeps
	// it from colliding with the MOVI modified-immediate group.
	NotEq  string
	PSBits string
}

// cellBits renders one <c> cell as span per-bit characters.
func cellBits(text string, span int) string {
	if span < 1 {
		span = 1
	}
	t := strings.TrimSpace(text)
	switch {
	case t == "":
		// An empty cell asserts nothing: inherit whatever the diagram said.
		return strings.Repeat("-", span)
	case t == "0" || t == "1":
		return strings.Repeat(t, span)
	case t == "(0)" || t == "(1)":
		// ARM "should be" bit. Pin it: the spec fixes the value, so both the
		// encoder's fixed word and the decode pattern must carry it.
		return strings.Repeat(t[1:2], span)
	case len(t) == span && isBinary(t):
		return t
	default:
		// Field name, "!= 1111" constraint, Z/N markers: variable here.
		// Inequality constraints are carried separately as bitdiffs.
		return strings.Repeat("x", span)
	}
}

// notEqValue extracts the excluded value from a "!= 0000" cell, padded to span.
func notEqValue(text string, span int) (string, bool) {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "!=") {
		return "", false
	}
	v := strings.TrimSpace(t[2:])
	if v == "" {
		return "", false
	}
	for i := 0; i < len(v); i++ {
		if v[i] != '0' && v[i] != '1' && v[i] != 'x' && v[i] != 'X' {
			return "", false
		}
	}
	if span > 0 && len(v) != span {
		if len(v) > span {
			return "", false
		}
		v = strings.Repeat("x", span-len(v)) + v
	}
	return v, true
}

func isBinary(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' && s[i] != '1' {
			return false
		}
	}
	return len(s) > 0
}

// fixedFromBits returns the box value when every bit is fixed, else nil.
func fixedFromBits(bits string) *uint64 {
	if bits == "" {
		return nil
	}
	var v uint64
	for i := 0; i < len(bits); i++ {
		switch bits[i] {
		case '1':
			v |= 1 << uint(len(bits)-1-i)
		case '0':
		default:
			return nil
		}
	}
	return &v
}

// mergeBoxes overlays per-encoding override boxes onto an iclass regdiagram.
// Overrides apply per bit; '-' cells inherit the diagram's bit. The returned
// boxes keep the diagram's field structure with fully resolved Bits.
func mergeBoxes(base, overrides []RegBox) []RegBox {
	var pat [32]byte
	for i := range pat {
		pat[i] = 'x'
	}
	apply := func(b RegBox) {
		for i := 0; i < b.Width && i < len(b.Bits); i++ {
			pos := b.HiBit - i
			if pos < 0 || pos > 31 {
				continue
			}
			if c := b.Bits[i]; c != '-' {
				pat[pos] = c
			}
		}
	}
	for _, b := range base {
		apply(b)
	}
	for _, b := range overrides {
		apply(b)
	}
	// A per-encoding box can also carry the "!= value" exclusion.
	neByRange := map[[2]int]string{}
	for _, b := range overrides {
		if b.NotEq != "" {
			neByRange[[2]int{b.HiBit, b.Width}] = b.NotEq
		}
	}

	out := make([]RegBox, 0, len(base))
	for _, b := range base {
		nb := b
		if ne, ok := neByRange[[2]int{b.HiBit, b.Width}]; ok {
			nb.NotEq = ne
		}
		if b.Width > 0 && b.HiBit >= 0 && b.HiBit <= 31 && b.HiBit-b.Width+1 >= 0 {
			bits := make([]byte, b.Width)
			for i := 0; i < b.Width; i++ {
				bits[i] = pat[b.HiBit-i]
			}
			nb.Bits = string(bits)
			nb.Fixed = fixedFromBits(nb.Bits)
		}
		out = append(out, nb)
	}
	return out
}

// ParseIFormFile loads an iform XML and extracts data for encodingID.
// encodingID should match <encoding name="…"> (e.g. CLREX_BN_barriers).
func ParseIFormFile(path, encodingID string) (*ParsedIForm, error) {
	if isUnavailableCloudFile(path) {
		return &ParsedIForm{}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open iform %q: %w", path, err)
	}
	defer f.Close()
	return parseIForm(f, encodingID)
}

func parseIForm(r io.Reader, encodingID string) (*ParsedIForm, error) {
	return parseIFormShared(r, encodingID, nil)
}

// parseIFormShared reuses page-level explanations already decoded from the same
// IForm XML member. Explanations are immutable and scoped to the whole page;
// decoding their nested value tables once per encoding only duplicates work.
func parseIFormShared(
	r io.Reader,
	encodingID string,
	sharedExplanations *[]AsmExplanation,
) (*ParsedIForm, error) {
	dec := xml.NewDecoder(r)

	out := &ParsedIForm{EncodingName: encodingID}
	var (
		pathStack []string
		// Text is stored once per XML character chunk. textStart records the
		// first token owned by each open element, so an element that needs its
		// descendant text can join exactly its slice at close. The previous
		// builder-per-ancestor scheme copied every token once per XML depth.
		textStart  []int
		textTokens []string
		inEncoding bool
		encName    string
		docvarKey  string

		// Box collection. curDst points at whichever slice the box being read
		// belongs to: the current regdiagram, or the current encoding's overrides.
		curDst  *[]RegBox
		curBox  *RegBox
		cBits   []byte
		curSpan int

		// Diagram scoping. A file holds one regdiagram per <iclass>; an encoding
		// must take the diagram of the iclass that contains it, never the last
		// one in the file.
		// Operand reference currently open inside an asmtemplate.
		pendingOperand *AsmOperand
		encOperands    []AsmOperand
		// asmLiteral is the raw <text> seen since the previous operand closed.
		asmLiteral string
		// Assembly syntax is captured untrimmed, unlike ordinary element text.
		// Collapsing XML character chunks would turn
		// "LDR  <Wt>, [<Xn|SP>]" into "LDR <Wt> , [ <Xn|SP> ]"; those spaces are
		// part of the source syntax, so asmtemplate keeps a verbatim stream.
		asmVerbatim  strings.Builder
		textVerbatim strings.Builder

		diagram      []RegBox // regdiagram currently being read
		iclassBase   []RegBox // regdiagram of the enclosing iclass
		lastDiagram  []RegBox // fallback when encodingID is not found
		encOverrides []RegBox // per-encoding override boxes for encodingID
		matched      bool
		iclassSerial int
		ownerIClass  int
	)

	elementText := func() string {
		if len(textStart) == 0 {
			return ""
		}
		return strings.Join(textTokens[textStart[len(textStart)-1]:], " ")
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			pathStack = append(pathStack, t.Name.Local)
			textStart = append(textStart, len(textTokens))
			switch t.Name.Local {
			case "instructionsection":
				if attr(t, "type") == "alias" {
					out.IsAlias = true
				}
			case "aliasto":
				// Prefer explicit encoding when present; refiform is the iform file.
				if id := attr(t, "encname"); id != "" {
					out.AliasOf = id
				}
			case "iclass":
				iclassSerial++
				iclassBase = nil
			case "encoding":
				encName = attr(t, "name")
				inEncoding = encodingID == "" || encName == encodingID
				if inEncoding {
					out.EncodingName = encName
					out.BitDiffs = attr(t, "bitdiffs")
					ownerIClass = iclassSerial
					encOverrides = nil
					matched = true
				}
			case "a":
				// Alias equivalent asmtemplate links: href="sbc.xml#SBC_32_addsub_carry"
				// Ignore later operand symbol hrefs (WdOrWZR, imm9_offset, …).
				if inEncoding && out.IsAlias && out.AliasOf == "" {
					if href := attr(t, "href"); href != "" {
						if i := strings.LastIndex(href, "#"); i >= 0 && i+1 < len(href) {
							frag := href[i+1:]
							if looksLikeEncodingID(frag) {
								out.AliasOf = frag
							}
						}
					}
				}
				// Operand references carry the type and field binding.
				if inEncoding && hasAncestor(pathStack, "asmtemplate") {
					hover := attr(t, "hover")
					op := AsmOperand{Link: attr(t, "link"), Hover: hover}
					op.Field = hoverField(hover)
					pendingOperand = &op
				}
			case "box":
				// Boxes come from two places: the iclass <regdiagram>, and
				// per-<encoding> override boxes that pin that encoding's bits.
				switch {
				case inRegdiagram(pathStack):
					curDst = &diagram
				case inEncoding && directChildOfEncoding(pathStack):
					curDst = &encOverrides
				default:
					curDst = nil
				}
				if curDst == nil {
					break
				}
				hi, _ := decimal(attr(t, "hibit"))
				w, ok := decimal(attr(t, "width"))
				if !ok || w <= 0 {
					w = 1
				}
				*curDst = append(*curDst, RegBox{
					Name:   attr(t, "name"),
					HiBit:  hi,
					Width:  w,
					PSBits: attr(t, "psbits"),
				})
				curBox = &(*curDst)[len(*curDst)-1]
				cBits = cBits[:0]
			case "c":
				curSpan = 1
				if curBox != nil {
					if cs, ok := decimal(attr(t, "colspan")); ok && cs > 1 {
						curSpan = cs
					}
				}
			case "docvar":
				docvarKey = attr(t, "key")
				if inEncoding || encodingID == "" {
					if attr(t, "key") != "" && attr(t, "value") != "" {
						applyDocvar(out, attr(t, "key"), attr(t, "value"))
					}
				}
			case "arch_variant":
				if feat := attr(t, "feature"); feat != "" {
					out.Features = append(out.Features, feat)
				}
			case "asmtemplate":
				asmVerbatim.Reset()
			case "text":
				textVerbatim.Reset()
			case "explanations":
				if sharedExplanations != nil {
					if err := dec.Skip(); err != nil {
						return nil, err
					}
					out.Explanations = *sharedExplanations
				} else {
					// Unmarshal the whole subtree once: value tables are too
					// nested to track with the outer state machine.
					exps, err := decodeExplanations(dec, t)
					if err != nil {
						return nil, err
					}
					out.Explanations = exps
				}
				// The subtree consumer advanced through </explanations>, so drop
				// the bookkeeping this element pushed.
				pathStack = pathStack[:len(pathStack)-1]
				textStart = textStart[:len(textStart)-1]
				continue
			}
		case xml.EndElement:
			name := t.Name.Local
			switch name {
			case "encoding":
				if inEncoding {
					// The owning diagram and overrides are now complete. Resolve
					// them before the next iclass can replace iclassBase, avoiding
					// a full diagram copy for every parsed encoding.
					out.Boxes = mergeBoxes(iclassBase, encOverrides)
				}
				inEncoding = false
				encName = ""
			case "text":
				if inEncoding && hasAncestor(pathStack, "asmtemplate") {
					asmLiteral = textVerbatim.String()
				}
			case "a":
				if pendingOperand != nil {
					pendingOperand.Symbol = elementText()
					pendingOperand.Prefix = asmLiteral
					asmLiteral = ""
					encOperands = append(encOperands, *pendingOperand)
					pendingOperand = nil
				}
			case "asmtemplate":
				// An <equivalent_to> asmtemplate spells the instruction an alias
				// expands to, not the alias itself: STUMINH's own syntax is
				// "STUMINH <Ws>, [<Xn|SP>]", and its equivalent_to reads
				// "LDUMINH <Ws>, WZR, [<Xn|SP>]". Taking the latter would name
				// the alias after the instruction it hides behind.
				raw := asmVerbatim.String()
				if inEncoding && !hasAncestor(pathStack, "equivalent_to") {
					if raw != "" && out.AsmTemplate == "" {
						out.AsmTemplate = raw
						// asmLiteral holds whatever <text> followed the final
						// operand; </a> clears it, so a template ending on an
						// operand leaves it empty, which is correct.
						out.AsmSuffix = asmLiteral
					}
					if len(out.AsmOperands) == 0 && len(encOperands) > 0 {
						out.AsmOperands = append([]AsmOperand(nil), encOperands...)
					}
				} else if inEncoding && hasAncestor(pathStack, "equivalent_to") {
					for _, op := range encOperands {
						if strings.HasPrefix(strings.TrimSpace(op.Symbol), "<") {
							out.EquivalentOperands = append(out.EquivalentOperands, op)
						}
					}
					out.EquivalentSuffix = asmLiteral
				} else if encodingID == "" && out.AsmTemplate == "" && raw != "" {
					out.AsmTemplate = raw
					out.AsmSuffix = asmLiteral
				}
				encOperands = nil
				pendingOperand = nil
				asmLiteral = ""
			case "aliascond":
				if inEncoding {
					out.AliasCond = elementText()
				}
			case "box":
				if curBox != nil {
					// Cells are listed from hibit down. Missing cells assert
					// nothing, so they inherit rather than forcing don't-care.
					for len(cBits) < curBox.Width {
						cBits = append(cBits, '-')
					}
					curBox.Bits = string(cBits[:curBox.Width])
					curBox.Fixed = fixedFromBits(curBox.Bits)
				}
				curBox = nil
				curDst = nil
			case "c":
				if curBox != nil {
					text := elementText()
					if ne, ok := notEqValue(text, curSpan); ok {
						curBox.NotEq = ne
					}
					cBits = append(cBits, cellBits(text, curSpan)...)
				}
				curSpan = 1
			case "pstext":
				text := elementText()
				if text != "" && inIClass(pathStack) && iclassSerial == ownerIClass {
					out.Pseudocode = append(out.Pseudocode, text)
				}
			case "docvar":
				// value may be in attribute (handled on start) or text
				text := elementText()
				if docvarKey != "" && text != "" && (inEncoding || encodingID == "") {
					applyDocvar(out, docvarKey, text)
				}
				docvarKey = ""
			case "regdiagram":
				if len(diagram) > 0 {
					// Transfer ownership instead of copying. The next diagram
					// starts with a fresh slice, while iclassBase and the fallback
					// retain this immutable one.
					lastDiagram = diagram
					// A regdiagram inside an iclass belongs to that iclass only.
					if inIClass(pathStack) {
						iclassBase = lastDiagram
					}
				}
				diagram = nil
			}
			if len(pathStack) > 0 {
				pathStack = pathStack[:len(pathStack)-1]
			}
			if len(textStart) > 0 {
				textStart = textStart[:len(textStart)-1]
			}
			if len(textStart) == 0 {
				textTokens = textTokens[:0]
			}
		case xml.CharData:
			if hasAncestor(pathStack, "asmtemplate") {
				asmVerbatim.Write(t)
				if len(pathStack) > 0 && pathStack[len(pathStack)-1] == "text" {
					textVerbatim.Write(t)
				}
			}
			trimmed := strings.TrimSpace(string(t))
			if trimmed == "" {
				continue
			}
			textTokens = append(textTokens, trimmed)
		}
	}

	switch {
	case matched && len(out.Boxes) > 0:
	case len(lastDiagram) > 0:
		// encodingID absent from this file (or a file with a bare regdiagram):
		// fall back to the only diagram available.
		out.Boxes = mergeBoxes(lastDiagram, nil)
	case len(diagram) > 0:
		out.Boxes = mergeBoxes(diagram, nil)
	}
	return out, nil
}

func inRegdiagram(path []string) bool {
	return hasAncestor(path, "regdiagram")
}

func inIClass(path []string) bool {
	return hasAncestor(path, "iclass")
}

func hasAncestor(path []string, tag string) bool {
	for _, p := range path {
		if p == tag {
			return true
		}
	}
	return false
}

// directChildOfEncoding reports whether the element at the top of path is an
// immediate child of <encoding> — where per-encoding override boxes live.
func directChildOfEncoding(path []string) bool {
	return len(path) >= 2 && path[len(path)-2] == "encoding"
}

func attr(se xml.StartElement, name string) string {
	for _, a := range se.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// decimal parses the non-negative decimal XML attributes used for bit
// positions and spans. strconv.Atoi allocates an error for every omitted
// optional attribute; absence is the common case for <c colspan>.
func decimal(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		digit := int(c - '0')
		if n > (int(^uint(0)>>1)-digit)/10 {
			return 0, false
		}
		n = n*10 + digit
	}
	return n, true
}

// looksLikeEncodingID distinguishes encoding names (SBC_32_addsub_carry) from
// asmtemplate symbol fragments (WdOrWZR, imm9_offset).
func looksLikeEncodingID(s string) bool {
	if s == "" || !strings.Contains(s, "_") {
		return false
	}
	if strings.Contains(s, "Or") || strings.Contains(s, "or") {
		return false
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "imm") || strings.HasPrefix(lower, "label") ||
		strings.HasPrefix(lower, "shift") || strings.HasPrefix(lower, "extend") {
		return false
	}
	return true
}

func applyDocvar(out *ParsedIForm, key, value string) {
	switch key {
	case "alias_mnemonic":
		// On an alias page this is the preferred disassembly and outranks the
		// canonical instruction's own mnemonic.
		out.AliasMnemonic = value
	case "mnemonic":
		if out.Mnemonic == "" {
			out.Mnemonic = value
		}
	case "feature", "extension":
		out.Features = append(out.Features, value)
	}
}

// ApplyParsedIForm merges ParsedIForm into InstructionIR (authoritative encoding).
func ApplyParsedIForm(instr *ir.InstructionIR, p *ParsedIForm) {
	if p == nil {
		return
	}
	if p.AsmTemplate != "" {
		instr.Asm = parseAsmTemplate(p.AsmTemplate)
		instr.AsmMnemonic = leadingMnemonic(p.AsmTemplate)
	}
	if instr.AsmMnemonic == "" {
		if p.AliasMnemonic != "" {
			instr.AsmMnemonic = p.AliasMnemonic
		} else {
			instr.AsmMnemonic = p.Mnemonic
		}
	}
	if p.AliasMnemonic != "" {
		instr.Mnemonic = p.AliasMnemonic
	} else if p.Mnemonic != "" && (instr.Mnemonic == "" || strings.Contains(instr.Mnemonic, ",")) {
		instr.Mnemonic = p.Mnemonic
	}
	if len(p.Boxes) > 0 {
		instr.Encoding = boxesToEncoding(p.Boxes)
		instr.BitPattern = boxesToBitPattern(p.Boxes)
		instr.Operands = boxesToOperandHints(p.Boxes)
	}
	// Box-level "!= value" exclusions constrain matching just like the
	// encoding's bitdiffs attribute, so both feed one tree.
	constraints := boxExclusions(p.Boxes)
	constraints = append(constraints, decodeEqualityConstraints(p.Pseudocode)...)
	constraints = append(constraints, decodeBitPinConstraints(p.Pseudocode, p.Boxes)...)
	constraints = append(constraints, decodeEnumeratedPinConstraints(p.Pseudocode)...)
	if expr := combineConstraints(p.BitDiffs, constraints); expr != "" {
		// Equality pins fold into BitPattern / Fixed; full tree kept for match.
		_ = applyBitDiffs(instr, expr)
	}
	if p.IsAlias {
		instr.AliasOf = p.AliasOf
		if instr.AliasOf == "" {
			instr.AliasOf = "?" // mark as alias even without resolved target
		}
	}
	if len(p.Pseudocode) > 0 {
		pc := parsePseudocode(p.Pseudocode)
		if instr.Documentation == nil {
			instr.Documentation = &ir.InstructionDoc{}
		}
		instr.Documentation.Pseudocode = pc
	}
	if len(p.Features) > 0 {
		tags := make([]ir.FeatureTag, 0, len(p.Features))
		for _, f := range p.Features {
			tags = append(tags, ir.FeatureTag{Name: f, Required: true, Description: featureDescription(f)})
		}
		instr.Features = mergeFeatures(instr.Features.Tags, tags)
	}
}

var (
	decodeEqualityRE        = regexp.MustCompile(`(?i)\bif\s+([A-Za-z_][A-Za-z0-9_]*)\s*!=\s*'([01]+)'\s+then\s+EndOfDecode\s*\(\s*Decode_UNDEF`)
	decodeUndefIfRE         = regexp.MustCompile(`(?is)\bif\s+(.+?)\s+then\s+EndOfDecode\s*\(\s*Decode_UNDEF`)
	decodeFieldNeRE         = regexp.MustCompile(`(?i)^([A-Za-z_][A-Za-z0-9_]*)\s*!=\s*'([01]+)'$`)
	decodeFieldEqRE         = regexp.MustCompile(`(?i)^([A-Za-z_][A-Za-z0-9_]*)\s*==\s*'([01]+)'$`)
	decodeFieldInRE         = regexp.MustCompile(`(?i)^([A-Za-z_][A-Za-z0-9_]*)\s+IN\s*\{\s*'([01x]+)'\s*\}$`)
	decodeNoFeatRE          = regexp.MustCompile(`(?i)^!\s*IsFeatureImplemented\s*\([^)]*\)$`)
	decodeConstIntRE        = regexp.MustCompile(`(?i)\bconstant\s+integer\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d+)\s*;`)
	decodeSubtractRE        = regexp.MustCompile(`(?i)\bconstant\s+integer\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*([A-Za-z_][A-Za-z0-9_]*|\d+)\s*-\s*UInt\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*;`)
	decodeEvenRangeRE       = regexp.MustCompile(`(?i)\bif\s+([A-Za-z_][A-Za-z0-9_]*)<(\d+):(\d+)>\s*==\s*'([01]+)'\s*\|\|\s*([A-Za-z_][A-Za-z0-9_]*)<0>\s*==\s*'1'\s+then\s+EndOfDecode\s*\(\s*Decode_UNDEF`)
	decodeEvenRE            = regexp.MustCompile(`(?i)\bif\s+([A-Za-z_][A-Za-z0-9_]*)<0>\s*==\s*'1'(?:\s*&&\s*([A-Za-z_][A-Za-z0-9_]*)\s*!=\s*'[01]+')?\s+then\s+EndOfDecode\s*\(\s*Decode_UNDEF`)
	decodeBitPinRE          = regexp.MustCompile(`(?im)^if\s+([A-Za-z_][A-Za-z0-9_]*)[\[<](\d+)[\]>]\s*==\s*'([01])'\s+then\s+EndOfDecode\s*\(\s*Decode_UNDEF`)
	decodeTopLevelUndefIfRE = regexp.MustCompile(`(?im)^if\s+([^\r\n]+?)\s+then\s+EndOfDecode\s*\(\s*Decode_UNDEF`)
)

// decodeEqualityConstraints extracts exact allocation pins stated by ARM's
// decode pseudocode. "if size != '10' then EndOfDecode(Decode_UNDEF)" is
// equivalent to the encoding constraint size == 10. Only this exact,
// unconditional shape is folded; set exclusions and compound conditions stay
// in pseudocode rather than being guessed into a fixed word.
func decodeEqualityConstraints(pseudocode []string) []string {
	var out []string
	for _, text := range pseudocode {
		for _, m := range decodeEqualityRE.FindAllStringSubmatch(text, -1) {
			out = append(out, m[1]+" == "+m[2])
		}
		// Some allocation guards combine the architectural field pin with the
		// instruction's feature check:
		//
		//   if !IsFeatureImplemented(FEAT_MOPS) || sz != '00'
		//       then EndOfDecode(Decode_UNDEF);
		//
		// Once this encoding is being decoded the feature term is contextual;
		// the field inequality is still an unconditional allocation exclusion.
		// Accept only a disjunction made entirely from those two exact term
		// shapes, so arbitrary pseudocode is never approximated as fixed bits.
		for _, guard := range decodeTopLevelUndefIfRE.FindAllStringSubmatch(text, -1) {
			terms := strings.Split(guard[1], "||")
			if len(terms) < 2 {
				continue
			}
			var field, bits string
			valid := true
			for _, term := range terms {
				term = strings.TrimSpace(term)
				if decodeNoFeatRE.MatchString(term) {
					continue
				}
				m := decodeFieldNeRE.FindStringSubmatch(term)
				if m == nil || field != "" {
					valid = false
					break
				}
				field, bits = m[1], m[2]
			}
			if valid && field != "" {
				out = append(out, field+" == "+bits)
			}
		}
	}
	return out
}

// decodeBitPinConstraints turns an exact one-bit UNDEFINED guard into the
// corresponding allocated value. PMULL, for example, states
// "if size[0] == '0' then UNDEFINED", which pins size<0> to one even though the
// value table writes that selector bit as a don't-care.
func decodeBitPinConstraints(pseudocode []string, boxes []RegBox) []string {
	widths := map[string]int{}
	for _, box := range boxes {
		if box.Name != "" && box.Width > 0 {
			widths[box.Name] = box.Width
		}
	}
	var out []string
	for _, text := range pseudocode {
		for _, match := range decodeBitPinRE.FindAllStringSubmatch(text, -1) {
			width := widths[match[1]]
			bit, err := strconv.Atoi(match[2])
			if err != nil || width <= 0 || bit < 0 || bit >= width {
				continue
			}
			pattern := make([]byte, width)
			for i := range pattern {
				pattern[i] = 'x'
			}
			if match[3] == "0" {
				pattern[width-1-bit] = '1'
			} else {
				pattern[width-1-bit] = '0'
			}
			out = append(out, match[1]+" == "+string(pattern))
		}
	}
	return out
}

// decodeEnumeratedPinConstraints recognizes a complete forbidden half of a
// field's values. "size == 10 || size == 11" excludes every value whose high
// bit is one, so the allocated encoding pins that bit to zero.
func decodeEnumeratedPinConstraints(pseudocode []string) []string {
	var out []string
	for _, text := range pseudocode {
		for _, guard := range decodeUndefIfRE.FindAllStringSubmatch(text, -1) {
			terms := strings.Split(guard[1], "||")
			if len(terms) == 1 {
				// A wildcard pattern with one fixed bit denotes exactly half
				// the field. If that half is UNDEFINED, the allocated half pins
				// the fixed bit to its complement: size IN {'0x'} rejects size
				// bit 1 == 0, so legal encodings require size == 1x.
				if match := decodeFieldInRE.FindStringSubmatch(strings.TrimSpace(terms[0])); match != nil {
					bits := []byte(strings.ToLower(match[2]))
					fixed := -1
					for i, bit := range bits {
						if bit != '0' && bit != '1' {
							continue
						}
						if fixed >= 0 {
							fixed = -2
							break
						}
						fixed = i
					}
					if fixed >= 0 {
						if bits[fixed] == '0' {
							bits[fixed] = '1'
						} else {
							bits[fixed] = '0'
						}
						out = append(out, match[1]+" == "+string(bits))
					}
				}
				continue
			}
			if len(terms) < 2 {
				continue
			}
			field, width := "", 0
			values := map[string]bool{}
			valid := true
			for _, term := range terms {
				match := decodeFieldEqRE.FindStringSubmatch(strings.TrimSpace(term))
				if match == nil {
					valid = false
					break
				}
				if field == "" {
					field, width = match[1], len(match[2])
				}
				if match[1] != field || len(match[2]) != width {
					valid = false
					break
				}
				values[match[2]] = true
			}
			if !valid || len(values) != 1<<uint(width-1) {
				continue
			}
			for bit := 0; bit < width; bit++ {
				var shared byte
				same := true
				for value := range values {
					if shared == 0 {
						shared = value[bit]
					} else if value[bit] != shared {
						same = false
						break
					}
				}
				if !same {
					continue
				}
				pattern := make([]byte, width)
				for i := range pattern {
					pattern[i] = 'x'
				}
				if shared == '0' {
					pattern[bit] = '1'
				} else {
					pattern[bit] = '0'
				}
				out = append(out, field+" == "+string(pattern))
				break
			}
		}
	}
	return out
}

type decodedRegRestriction struct {
	Multiple int64
	Lo, Hi   int64
	HasRange bool
}

// decodeRegisterRestrictions extracts allocation checks that constrain a
// register field rather than pinning it to one value. LS64, for example,
// rejects Rt<4:3> == '11' and odd Rt, exactly the even X0-X22 bank.
func decodeRegisterRestrictions(pseudocode []string) map[string]decodedRegRestriction {
	out := map[string]decodedRegRestriction{}
	for _, text := range pseudocode {
		// ARM pseudocode uses both field<0> and field[0] spellings for bit
		// selection. Normalize the latter before applying the same allocation
		// rule; they are semantically identical.
		normalized := strings.NewReplacer("[", "<", "]", ">").Replace(text)
		for _, m := range decodeEvenRE.FindAllStringSubmatch(normalized, -1) {
			if m[2] != "" && m[2] != m[1] {
				continue
			}
			out[m[1]] = decodedRegRestriction{Multiple: 2}
		}
		for _, m := range decodeEvenRangeRE.FindAllStringSubmatch(normalized, -1) {
			if m[1] != m[5] || strings.Trim(m[4], "1") != "" {
				continue
			}
			hi, e1 := strconv.Atoi(m[2])
			lo, e2 := strconv.Atoi(m[3])
			if e1 != nil || e2 != nil || hi < lo || lo < 1 {
				continue
			}
			// The first excluded all-ones run starts at this value. Values
			// below it remain allocated; the odd exclusion lowers the largest
			// usable register by one when necessary.
			limit := (int64(1) << uint(hi+1)) - (int64(1) << uint(lo))
			max := limit - 1
			if max&1 != 0 {
				max--
			}
			out[m[1]] = decodedRegRestriction{Multiple: 2, Lo: 0, Hi: max, HasRange: true}
		}
	}
	return out
}

// decodeRegisterSuccessors extracts explicit consecutive-register relations
// from Decode pseudocode. PEXT, for example, exposes two destination predicate
// registers but encodes only Pd; Decode states d1 = (UInt(Pd) + 1) MOD 16.
// Keeping the modulus is essential for predicate banks, which wrap at 16
// rather than at the 32-register vector-bank boundary.
func decodeRegisterSuccessors(pseudocode []string) map[string]DerivedRel {
	out := map[string]DerivedRel{}
	for _, block := range pseudocode {
		for _, line := range strings.Split(block, "\n") {
			const marker = "= (UInt("
			at := strings.Index(line, marker)
			if at < 0 {
				continue
			}
			fieldStart := at + len(marker)
			fieldEnd := strings.IndexByte(line[fieldStart:], ')')
			if fieldEnd <= 0 {
				continue
			}
			fieldEnd += fieldStart
			field := strings.TrimSpace(line[fieldStart:fieldEnd])
			if field == "" {
				continue
			}
			rest := strings.TrimSpace(line[fieldEnd+1:])
			if !strings.HasPrefix(rest, "+") {
				continue
			}
			rest = strings.TrimSpace(rest[1:])
			addEnd := 0
			for addEnd < len(rest) && rest[addEnd] >= '0' && rest[addEnd] <= '9' {
				addEnd++
			}
			if addEnd == 0 {
				continue
			}
			add, err := strconv.ParseInt(rest[:addEnd], 10, 64)
			if err != nil {
				continue
			}
			rest = strings.TrimSpace(rest[addEnd:])
			if !strings.HasPrefix(rest, ") MOD ") {
				continue
			}
			rest = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(rest, ") MOD "), ";"))
			mod, err := strconv.ParseInt(rest, 10, 64)
			if err != nil || mod <= 0 {
				continue
			}
			out[field] = DerivedRel{Field: field, Mul: 1, Add: add, Mod: mod}
		}
	}
	return out
}

// decodeForbiddenConstraints parses field-equality boolean expressions whose
// true branch is Decode_UNDEF. It supports the exact Decode grammar used for
// allocation constraints: == over quoted bit strings, &&, ||, and parentheses.
// Feature tests and arithmetic expressions are rejected as a whole rather than
// partially interpreted.
func decodeForbiddenConstraints(
	pseudocode []string,
	byName map[string]ir.BitField,
	fixedMask uint32,
) []DisasmForbidden {
	var out []DisasmForbidden
	for _, block := range pseudocode {
		var context []forbiddenConditionFrame
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			if strings.HasPrefix(line, "end;") {
				if len(context) > 0 {
					context = context[:len(context)-1]
				}
				continue
			}

			condition, suffix, hasCondition := splitDecodeIf(line)
			var clauses []forbiddenClause
			conditionOK := false
			if hasCondition {
				parser := forbiddenConditionParser{text: condition, fields: byName}
				clauses, conditionOK = parser.parseOr()
				parser.space()
				conditionOK = conditionOK && parser.pos == len(parser.text)
			}

			if strings.Contains(line, "Decode_UNDEF") && hasCondition && conditionOK {
				combined := clauses
				for _, frame := range context {
					if !frame.valid {
						combined = nil
						break
					}
					combined = combineForbiddenClauses(frame.clauses, combined)
					if len(combined) == 0 {
						break
					}
				}
				for _, clause := range combined {
					out = append(out, DisasmForbidden{
						Mask: clause.Mask, Value: clause.Value,
						Mutable: clause.Mask &^ fixedMask,
					})
				}
			}

			// An if whose body starts on the next line contributes to every
			// nested Decode_UNDEF. Keep even an unsupported condition as an
			// invalid frame: dropping it would incorrectly make an inner
			// allocation check unconditional.
			if hasCondition && strings.TrimSpace(suffix) == "" {
				context = append(context, forbiddenConditionFrame{
					clauses: clauses,
					valid:   conditionOK,
				})
			}
		}
	}
	return out
}

type forbiddenConditionFrame struct {
	clauses []forbiddenClause
	valid   bool
}

type forbiddenConditionParser struct {
	text   string
	pos    int
	fields map[string]ir.BitField
}

type forbiddenClause struct {
	Mask, Value uint32
}

func splitDecodeIf(line string) (condition, suffix string, ok bool) {
	if !strings.HasPrefix(line, "if ") {
		return "", "", false
	}
	end := strings.Index(line, " then")
	if end <= len("if ") {
		return "", "", false
	}
	return strings.TrimSpace(line[len("if "):end]), line[end+len(" then"):], true
}

func combineForbiddenClauses(left, right []forbiddenClause) []forbiddenClause {
	var product []forbiddenClause
	for _, a := range left {
		for _, b := range right {
			overlap := a.Mask & b.Mask
			if (a.Value^b.Value)&overlap != 0 {
				continue
			}
			product = append(product, forbiddenClause{
				Mask: a.Mask | b.Mask, Value: a.Value | b.Value,
			})
		}
	}
	return product
}

func (p *forbiddenConditionParser) parseOr() ([]forbiddenClause, bool) {
	left, ok := p.parseAnd()
	if !ok {
		return nil, false
	}
	for {
		p.space()
		if !p.take("||") {
			return left, true
		}
		right, ok := p.parseAnd()
		if !ok {
			return nil, false
		}
		left = append(left, right...)
	}
}

func (p *forbiddenConditionParser) parseAnd() ([]forbiddenClause, bool) {
	left, ok := p.parsePrimary()
	if !ok {
		return nil, false
	}
	for {
		p.space()
		if !p.take("&&") {
			return left, true
		}
		right, ok := p.parsePrimary()
		if !ok {
			return nil, false
		}
		product := combineForbiddenClauses(left, right)
		if len(product) == 0 {
			return nil, false
		}
		left = product
	}
}

func (p *forbiddenConditionParser) parsePrimary() ([]forbiddenClause, bool) {
	p.space()
	if p.take("(") {
		clauses, ok := p.parseOr()
		p.space()
		if !ok || !p.take(")") {
			return nil, false
		}
		return clauses, true
	}
	start := p.pos
	for p.pos < len(p.text) && isConditionFieldByte(p.text[p.pos]) {
		p.pos++
	}
	if start == p.pos {
		return nil, false
	}
	name := p.text[start:p.pos]
	p.space()
	if !p.take("==") {
		return nil, false
	}
	p.space()
	if !p.take("'") {
		return nil, false
	}
	bitsStart := p.pos
	for p.pos < len(p.text) &&
		(p.text[p.pos] == '0' || p.text[p.pos] == '1' ||
			p.text[p.pos] == 'x' || p.text[p.pos] == 'X') {
		p.pos++
	}
	bits := p.text[bitsStart:p.pos]
	if bits == "" || !p.take("'") {
		return nil, false
	}
	fields, width, ok := conditionFields(name, p.fields)
	if !ok || len(bits) != width {
		return nil, false
	}
	var clause forbiddenClause
	bitIndex := 0
	for _, field := range fields {
		for pos := field.End; pos >= field.Start; pos-- {
			bit := bits[bitIndex]
			bitIndex++
			if bit == 'x' || bit == 'X' {
				continue
			}
			mask := uint32(1) << uint(pos)
			clause.Mask |= mask
			if bit == '1' {
				clause.Value |= mask
			}
		}
	}
	if clause.Mask == 0 {
		return nil, false
	}
	return []forbiddenClause{clause}, true
}

func conditionFields(
	name string,
	byName map[string]ir.BitField,
) ([]ir.BitField, int, bool) {
	names := strings.Split(name, "::")
	fields := make([]ir.BitField, 0, len(names))
	width := 0
	for _, fieldName := range names {
		if fieldName == "" {
			return nil, 0, false
		}
		field, ok := lookupField(fieldName, byName)
		if !ok {
			return nil, 0, false
		}
		fields = append(fields, field)
		width += field.End - field.Start + 1
	}
	return fields, width, true
}

func (p *forbiddenConditionParser) space() {
	for p.pos < len(p.text) &&
		(p.text[p.pos] == ' ' || p.text[p.pos] == '\t') {
		p.pos++
	}
}

func (p *forbiddenConditionParser) take(want string) bool {
	if !strings.HasPrefix(p.text[p.pos:], want) {
		return false
	}
	p.pos += len(want)
	return true
}

func isConditionFieldByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
		b >= '0' && b <= '9' || b == '_' ||
		b == '<' || b == '>' || b == '[' || b == ']' || b == ':'
}

// decodeMemoryOperationRegisterConstraints reads the semantic CPYParams and
// SETParams categories from Decode pseudocode. The architecture classifies use
// of register 31, overlapping CPY roles, and an overlapping SET source/size as
// constrained-unpredictable. Assemblers intentionally reject those spellings,
// so the reference print model treats them as non-canonical instruction words.
func decodeMemoryOperationRegisterConstraints(
	pseudocode []string,
	byName map[string]ir.BitField,
	fixedMask uint32,
) ([]DisasmForbidden, []DisasmFieldInequality) {
	text := strings.Join(pseudocode, "\n")
	copyOperation := strings.Contains(text, ": CPYParams")
	setOperation := strings.Contains(text, ": SETParams")
	if !copyOperation && !setOperation {
		return nil, nil
	}

	names := []string{"Rd", "Rs", "Rn"}
	fields := make([]ir.BitField, len(names))
	for i, name := range names {
		field, ok := lookupField(name, byName)
		if !ok || field.End-field.Start+1 != 5 {
			return nil, nil
		}
		fields[i] = field
	}

	forbidden := make([]DisasmForbidden, 0, len(fields))
	for _, field := range fields {
		mask := fieldRangeMask(field.Start, field.End)
		forbidden = append(forbidden, DisasmForbidden{
			Mask: mask, Value: mask, Mutable: mask &^ fixedMask,
		})
	}

	pairs := [][2]int{{0, 1}, {0, 2}, {1, 2}} // SET roles must all differ.
	if copyOperation {
		pairs = [][2]int{{0, 1}, {0, 2}, {1, 2}}
	}
	unequal := make([]DisasmFieldInequality, 0, len(pairs))
	for _, pair := range pairs {
		left, right := fields[pair[0]], fields[pair[1]]
		unequal = append(unequal, DisasmFieldInequality{
			LeftStart: left.Start, LeftEnd: left.End,
			RightStart: right.Start, RightEnd: right.End,
			RightMutable: fieldRangeMask(right.Start, right.End) &^ fixedMask,
		})
	}
	return forbidden, unequal
}

// decodeWritebackSampleRegisterConstraints avoids constrained-unpredictable
// load/store representatives. Register 31 can legally mean ZR versus SP, so
// these constraints are sample-only rather than formatter validity rules.
func decodeWritebackSampleRegisterConstraints(
	pseudocode []string,
	byName map[string]ir.BitField,
	fixedMask uint32,
) []DisasmFieldInequality {
	if !strings.Contains(strings.Join(pseudocode, "\n"), "wback : boolean = TRUE") {
		return nil
	}
	base, ok := lookupField("Rn", byName)
	if !ok || base.End-base.Start+1 != 5 {
		return nil
	}
	var out []DisasmFieldInequality
	for _, name := range []string{"Rt", "Rt2"} {
		transfer, found := lookupField(name, byName)
		if !found || transfer.End-transfer.Start+1 != 5 {
			continue
		}
		mutable := fieldRangeMask(transfer.Start, transfer.End) &^ fixedMask
		if mutable == 0 {
			continue
		}
		out = append(out, DisasmFieldInequality{
			LeftStart: base.Start, LeftEnd: base.End,
			RightStart: transfer.Start, RightEnd: transfer.End,
			RightMutable: mutable,
		})
	}
	return out
}

// decodeFieldNegates extracts exact countdown encodings from Decode
// pseudocode: "shift = esize - UInt(imm4)" with "esize = 16" means the
// assembler operand is encoded as 16-shift. Unlike prose range inference, this
// relation determines the direction of the mapping.
func decodeFieldNegates(pseudocode []string) map[string]int64 {
	constants := map[string]int64{}
	for _, text := range pseudocode {
		for _, m := range decodeConstIntRE.FindAllStringSubmatch(text, -1) {
			if n, err := strconv.ParseInt(m[2], 10, 64); err == nil {
				constants[m[1]] = n
			}
		}
	}
	out := map[string]int64{}
	for _, text := range pseudocode {
		for _, m := range decodeSubtractRE.FindAllStringSubmatch(text, -1) {
			n, err := strconv.ParseInt(m[1], 10, 64)
			if err != nil {
				var ok bool
				n, ok = constants[m[1]]
				if !ok {
					continue
				}
			}
			out[m[2]] = n
		}
	}
	return out
}

// boxExclusions renders each box's "!= value" cell as a bitdiffs term.
func boxExclusions(boxes []RegBox) []string {
	var terms []string
	for _, b := range boxes {
		if b.NotEq == "" || b.Name == "" {
			continue
		}
		terms = append(terms, b.Name+" != "+b.NotEq)
	}
	return terms
}

// combineConstraints ANDs a bitdiffs expression with extra terms.
func combineConstraints(expr string, terms []string) string {
	parts := make([]string, 0, len(terms)+1)
	if e := strings.TrimSpace(expr); e != "" {
		parts = append(parts, "("+e+")")
	}
	for _, t := range terms {
		parts = append(parts, t)
	}
	return strings.Join(parts, " && ")
}

func boxesToEncoding(boxes []RegBox) ir.EncodingMask {
	fields := make([]ir.BitField, 0, len(boxes))
	for _, b := range boxes {
		if b.HiBit < 0 || b.Width <= 0 {
			continue
		}
		start := b.HiBit - b.Width + 1
		if start < 0 {
			continue
		}
		name := b.Name
		if name == "" {
			// Unnamed fixed boxes in ARM XML: stable synthetic name for tooling.
			if b.Fixed != nil {
				name = fmt.Sprintf("_const_%d_%d", start, b.HiBit)
			} else {
				name = fmt.Sprintf("_field_%d_%d", start, b.HiBit)
			}
		}
		f := ir.BitField{
			Name:  name,
			Start: start,
			End:   b.HiBit,
		}
		if b.Fixed != nil {
			v := *b.Fixed
			f.Fixed = &v
		}
		fields = append(fields, f)
	}
	return ir.EncodingMask{Width: 32, Fields: fields}
}

func boxesToBitPattern(boxes []RegBox) string {
	pat := make([]byte, 32)
	for i := range pat {
		pat[i] = 'x'
	}
	for _, b := range boxes {
		if b.HiBit < 0 || b.HiBit > 31 || b.Width <= 0 || b.HiBit-b.Width+1 < 0 {
			continue
		}
		// Prefer per-bit data: boxes routinely mix fixed and variable bits, and
		// b.Fixed is set only when the whole box is fixed.
		if b.Bits != "" {
			for i := 0; i < b.Width && i < len(b.Bits); i++ {
				if c := b.Bits[i]; c == '0' || c == '1' {
					pat[31-(b.HiBit-i)] = c
				}
			}
			continue
		}
		if b.Fixed == nil {
			continue
		}
		start := b.HiBit - b.Width + 1
		for i := 0; i < b.Width; i++ {
			idx := 31 - (start + i)
			if idx < 0 || idx >= 32 {
				continue
			}
			if ((*b.Fixed)>>uint(i))&1 == 1 {
				pat[idx] = '1'
			} else {
				pat[idx] = '0'
			}
		}
	}
	return string(pat)
}

func boxesToOperandHints(boxes []RegBox) []ir.OperandIR {
	ops := make([]ir.OperandIR, 0)
	for _, b := range boxes {
		if b.Name == "" || b.Fixed != nil {
			continue
		}
		start := b.HiBit - b.Width + 1
		if start < 0 {
			continue
		}
		ops = append(ops, ir.OperandIR{
			Name:        b.Name,
			DisplayName: b.Name,
			Type:        InferOperandType(b.Name),
			BitRange:    ir.BitRange{Start: start, End: b.HiBit},
			Usage:       ir.Read,
		})
	}
	return ops
}

// leadingMnemonic returns the assembler spelling an asmtemplate opens with.
//
// It stops at the first operand, separator or optional-group brace, so
// "LDR  <Wt>, …" gives LDR and "ADDHN{2}  <Vd>…" gives ADDHN. The trailing dot
// of "B.<cond>" is kept: ARM spells the condition as part of the mnemonic, and
// dropping the dot would print "BEQ" for what the assembler writes "B.EQ".
func leadingMnemonic(template string) string {
	t := strings.TrimSpace(template)
	if i := strings.IndexAny(t, " \t<,[{"); i >= 0 {
		t = t[:i]
	}
	return t
}

// parseAsmTemplate converts an assembly template string to IR format.
func parseAsmTemplate(template string) ir.AsmTemplate {
	tokens := make([]ir.AsmToken, 0, 8)
	for cursor := 0; cursor < len(template); {
		switch template[cursor] {
		case ' ', '\t', '\r', '\n':
			cursor++
		case '<':
			end := strings.IndexByte(template[cursor+1:], '>')
			if end < 0 {
				cursor++
				continue
			}
			end += cursor + 1
			content := template[cursor+1 : end]
			name, options, _ := strings.Cut(content, ":")
			if name != "" {
				token := ir.AsmToken{Kind: ir.TokenOperand, Operand: name}
				if options != "" {
					token.Options = strings.Split(options, ",")
				}
				tokens = append(tokens, token)
			}
			cursor = end + 1
		case '{':
			end := strings.IndexByte(template[cursor+1:], '}')
			if end < 0 {
				cursor++
				continue
			}
			end += cursor + 1
			if symbol := template[cursor+1 : end]; symbol != "" {
				tokens = append(tokens, ir.AsmToken{Kind: ir.TokenSymbol, Value: symbol})
			}
			cursor = end + 1
		default:
			start := cursor
			for cursor < len(template) {
				c := template[cursor]
				if c == '<' || c == '{' || c == ' ' || c == '\t' || c == '\r' || c == '\n' {
					break
				}
				cursor++
			}
			if cursor > start {
				tokens = append(tokens, ir.AsmToken{Kind: ir.TokenLiteral, Value: template[start:cursor]})
			}
		}
	}
	return ir.AsmTemplate{Raw: template, Tokens: tokens}
}

// parsePseudocode converts pseudocode lines to IR format with AST + effects.
func parsePseudocode(lines []string) []ir.PseudocodeLine {
	return NewPseudocodeParser().ParseLines(lines)
}
