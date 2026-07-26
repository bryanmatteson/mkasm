package arm

import (
	"encoding/xml"
	"html"
	"regexp"
	"strings"
)

// AsmExplanation is ARM's authoritative description of one operand symbol for a
// set of encodings, from the <explanations> section of an instruction page.
//
// This is a better operand source than the asmtemplate hover text: 99.7% of
// explanation blocks state the encoding field in `encodedin`, including
// multi-field placements like "size:Q" and "immh:immb", and enumerated operands
// carry a value table mapping bit combinations to their assembler spelling
// (size:Q = 00:0 -> 8B, cond = 0000 -> EQ).
type AsmExplanation struct {
	// Symbol is the operand placeholder, e.g. "<T>" or "<Xn|SP>".
	Symbol string
	// Link is ARM's operand-class id.
	Link string
	// Fields are the bit fields the operand encodes into, in order. "size:Q"
	// yields ["size", "Q"].
	Fields []string
	// Prose is ARM's description.
	Prose string
	// Values is the value table for enumerated operands, empty otherwise.
	Values []SymbolValue
	// ValueFields are the table's own selector columns. They can be narrower
	// than Fields: EXT is encoded in Q:imm4, but its legality table selects on
	// Q and imm4[3]. Keeping both prevents a one-bit row pattern from being
	// compared with the entire four-bit field.
	ValueFields []string
	// Encodings lists the encoding IDs this explanation applies to.
	Encodings []string
}

// SymbolValue is one row of an operand's value table.
type SymbolValue struct {
	// Bits holds one bit pattern per entry in the owning explanation's Fields,
	// in the same order. 'x' appears as a don't-care.
	Bits []string
	// Symbol is the assembler spelling this combination selects, e.g. "8B".
	// "RESERVED" marks an unallocated combination.
	Symbol string
}

// Reserved reports whether this row is an unallocated combination.
func (v SymbolValue) Reserved() bool {
	s := strings.ToUpper(v.Symbol)
	return s == "RESERVED" || s == "UNALLOCATED" || s == ""
}

// --- XML shapes, unmarshalled as whole subtrees ---

type xmlExplanations struct {
	Explanation []xmlExplanation `xml:"explanation"`
}

type xmlExplanation struct {
	EncList string `xml:"enclist,attr"`
	Symbol  struct {
		Link string `xml:"link,attr"`
		Text string `xml:",chardata"`
	} `xml:"symbol"`
	Account    *xmlAccount `xml:"account"`
	Definition *xmlAccount `xml:"definition"`
}

type xmlAccount struct {
	EncodedIn string         `xml:"encodedin,attr"`
	Intro     xmlProse       `xml:"intro"`
	Table     *xmlValueTable `xml:"table"`
	After     xmlProse       `xml:"after"`
}

// xmlProse captures an element's full text. Unmarshalling <intro> straight into
// a string yields only its direct character data, and ARM wraps every operand
// description in <para> with embedded <a> links — so a plain string field comes
// back empty or truncated at the first link, which silently strips the prose
// every operand classification depends on.
type xmlProse struct {
	Inner string `xml:",innerxml"`
}

var xmlTagRE = regexp.MustCompile(`<[^>]*>`)

// Text renders captured markup as plain prose.
func (p xmlProse) Text() string {
	return collapseSpace(html.UnescapeString(xmlTagRE.ReplaceAllString(p.Inner, "")))
}

type xmlValueTable struct {
	Head []xmlTableEntry `xml:"tgroup>thead>row>entry"`
	Rows []struct {
		Entry []xmlTableEntry `xml:"entry"`
	} `xml:"tgroup>tbody>row"`
}

type xmlTableEntry struct {
	Class string `xml:"class,attr"`
	Inner string `xml:",innerxml"`
}

func (e xmlTableEntry) Text() string {
	return collapseSpace(html.UnescapeString(xmlTagRE.ReplaceAllString(e.Inner, "")))
}

// decodeExplanations unmarshals an <explanations> subtree.
func decodeExplanations(dec *xml.Decoder, start xml.StartElement) ([]AsmExplanation, error) {
	var raw xmlExplanations
	if err := dec.DecodeElement(&raw, &start); err != nil {
		return nil, err
	}
	out := make([]AsmExplanation, 0, len(raw.Explanation))
	for _, e := range raw.Explanation {
		acct := e.Account
		if acct == nil {
			acct = e.Definition
		}
		if acct == nil {
			continue
		}
		ex := AsmExplanation{
			Symbol:    strings.TrimSpace(e.Symbol.Text),
			Link:      e.Symbol.Link,
			Prose:     collapseSpace(acct.Intro.Text() + " " + acct.After.Text()),
			Encodings: splitEncList(e.EncList),
		}
		if f := strings.TrimSpace(acct.EncodedIn); f != "" {
			ex.Fields = splitFieldList(f)
		}
		if acct.Table != nil {
			bitColumns, symbolColumn := tableColumnRoles(acct.Table, len(ex.Fields))
			for _, column := range bitColumns {
				field := acct.Table.Head[column].Text()
				if field == "" {
					ex.ValueFields = nil
					break
				}
				ex.ValueFields = append(ex.ValueFields, field)
			}
			for _, r := range acct.Table.Rows {
				if symbolColumn < 0 || symbolColumn >= len(r.Entry) {
					continue
				}
				vals := make([]string, 0, len(bitColumns))
				complete := true
				for _, column := range bitColumns {
					if column >= len(r.Entry) {
						complete = false
						break
					}
					vals = append(vals, r.Entry[column].Text())
				}
				if !complete {
					continue
				}
				ex.Values = append(ex.Values, SymbolValue{
					Bits:   vals,
					Symbol: r.Entry[symbolColumn].Text(),
				})
			}
		}
		out = append(out, ex)
	}
	return out, nil
}

func tableColumnRoles(table *xmlValueTable, fallbackBits int) (bits []int, symbol int) {
	symbol = -1
	for i, heading := range table.Head {
		switch strings.ToLower(heading.Class) {
		case "bitfield":
			bits = append(bits, i)
		case "symbol":
			if symbol < 0 {
				symbol = i
			}
		}
	}
	if len(bits) > 0 && symbol >= 0 {
		return bits, symbol
	}

	// Older corpus tables occasionally omit entry classes. In that shape the
	// encoded fields come first and the spelling follows them.
	nbits := len(table.Head) - 1
	if fallbackBits > 0 && (nbits < 1 || fallbackBits < nbits) {
		nbits = fallbackBits
	}
	if nbits < 1 || nbits >= len(table.Head) {
		return nil, -1
	}
	bits = make([]int, nbits)
	for i := range bits {
		bits[i] = i
	}
	return bits, nbits
}

// splitFieldList parses an `encodedin` value into field references.
//
// ARM uses two equivalent tuple spellings:
//
//	size:Q
//	(size :: Q)
//
// A reference may also name a bit slice of a field, where the colon is not a
// tuple separator: "H:L:M:Rm<3>" is four fields, but "CRm<2:1>" is one. This
// scanner recognizes those few tokens directly instead of trying to repair the
// result of a delimiter split.
func splitFieldList(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		for i < len(s) && !isFieldStartByte(s[i]) {
			i++
		}
		if i == len(s) {
			break
		}
		start := i
		for i < len(s) && isFieldNameByte(s[i]) {
			i++
		}
		if i < len(s) && (s[i] == '<' || s[i] == '[') {
			close := byte('>')
			if s[i] == '[' {
				close = ']'
			}
			j := i + 1
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] == ':') {
				j++
			}
			if j < len(s) && s[j] == close && j > i+1 {
				i = j + 1
			}
		}
		out = append(out, s[start:i])
	}
	return out
}

func isFieldStartByte(c byte) bool {
	return c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func splitEncList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func collapseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// ExplanationsFor returns the explanations that apply to encodingID, keyed by
// operand symbol. When an explanation lists no encodings it applies to all.
func ExplanationsFor(all []AsmExplanation, encodingID string) map[string]AsmExplanation {
	out := make(map[string]AsmExplanation, len(all))
	for _, e := range all {
		if len(e.Encodings) > 0 && !containsStr(e.Encodings, encodingID) {
			continue
		}
		// First match wins: ARM lists the most specific explanation first when
		// a symbol is described more than once for one encoding.
		if _, seen := out[e.Symbol]; !seen {
			out[e.Symbol] = e
		}
	}
	// Some encodings are absent from every enclist that names their operands —
	// aliases mostly. Falling back to the first description of the symbol on the
	// page is better than having none, and a description belonging to the wrong
	// variant shows up as a decode mismatch in the generated round-trip tests.
	for _, e := range all {
		if _, seen := out[e.Symbol]; !seen {
			out[e.Symbol] = e
		}
	}
	return out
}

func containsStr(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
