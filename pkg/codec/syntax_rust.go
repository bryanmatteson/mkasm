package codec

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// A second order is needed only when catalog order is not already shortest
// first. Stable sorting keeps the allocating API's tie-breaking order intact.
func rustShortestCandidates(encodings []Encoding, indices []int) []int {
	if sort.SliceIsSorted(indices, func(i, j int) bool {
		return len(encodings[indices[i]].Value) < len(encodings[indices[j]].Value)
	}) {
		return nil
	}
	result := append([]int(nil), indices...)
	sort.SliceStable(result, func(i, j int) bool {
		return len(encodings[result[i]].Value) < len(encodings[result[j]].Value)
	})
	return result
}

// Keep formatting tokens and normalized assembly patterns immutable. Preparing
// them for every candidate made text assembly allocate in proportion to the
// number of matching catalog forms.
type rustFormatPart struct {
	Start, End uint32
	Operand    int
	Comma      bool
}
type rustSyntax struct {
	Pattern []byte
	Display string
	Parts   []rustFormatPart
}

func rustNormalizeLiteral(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsSpace(r) {
			continue
		}
		// Rust char::to_lowercase includes the expanding lowercase mapping for İ.
		if r == '\u0130' {
			b.WriteString("i\u0307")
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}
func prepareRustSyntax(e Encoding) rustSyntax {
	protected := strings.ReplaceAll(strings.ReplaceAll(e.Syntax, "{{", "\x01"), "}}", "\x02")
	// Restore escaped literal braces once. Each replacement is one byte, so
	// the prepared literal offsets retain their meaning.
	result := rustSyntax{Display: strings.NewReplacer("\x01", "{", "\x02", "}").Replace(protected)}
	var pattern strings.Builder
	literal := func(s string, start int) {
		if s != "" {
			result.Parts = append(result.Parts, rustFormatPart{Start: uint32(start), End: uint32(start + len(s)), Operand: -1})
		}
	}

	rest := protected
	for {
		i := strings.IndexByte(rest, '{')
		if i < 0 {
			pattern.WriteString(rustNormalizeLiteral(rest))
			literal(rest, len(protected)-len(rest))
			break
		}
		pattern.WriteString(rustNormalizeLiteral(rest[:i]))
		literal(rest[:i], len(protected)-len(rest))
		rest = rest[i:]
		j := strings.IndexByte(rest, '}')
		if j < 0 {
			pattern.WriteString(rest)
			literal(rest, len(protected)-len(rest))
			break
		}
		token := rest[:j+1]
		pattern.WriteString(token)
		index := -1
		for i, o := range e.Operands {
			if o.Name == token[1:len(token)-1] {
				index = i
				break
			}
		}
		if index < 0 {
			literal(token, len(protected)-len(rest))
		} else {
			result.Parts = append(result.Parts, rustFormatPart{Operand: index})
		}
		rest = rest[j+1:]
	}
	// Merge a frequent named-register + comma literal into one display token.
	// Do this only for bounded identity tables; transformed names keep the
	// generic path and large symbolic namespaces are never duplicated.
	merged := result.Parts[:0]
	for i := 0; i < len(result.Parts); i++ {
		part := result.Parts[i]
		if part.Operand >= 0 && i+1 < len(result.Parts) {
			o := e.Operands[part.Operand]
			next := result.Parts[i+1]
			if rustCommaNames(o) && next.Operand < 0 && result.Display[next.Start:next.End] == ", " {
				part.Comma = true
				i++
			}
		}
		merged = append(merged, part)
	}
	result.Parts = merged
	result.Pattern = rustMatchProgram(pattern.String(), e.Operands)
	return result
}

// 0xff cannot occur in a UTF-8 literal. A following byte identifies the operand;
// 255 escapes a little-endian u32 index for unusually large operand lists.
// Invalid placeholders deliberately reference an unavailable operand.
func rustMatchProgram(pattern string, operands []Operand) []byte {
	var result []byte
	for {
		i := strings.IndexByte(pattern, '{')
		if i < 0 {
			return append(result, pattern...)
		}
		result = append(result, pattern[:i]...)
		pattern = pattern[i+1:]
		j := strings.IndexByte(pattern, '}')
		index := ^uint32(0)
		if j >= 0 {
			for k, o := range operands {
				if o.Name == pattern[:j] {
					index = uint32(k)
					break
				}
			}
		}
		result = append(result, 0xff)
		if index < 255 {
			result = append(result, byte(index))
		} else {
			result = append(result, 255, byte(index), byte(index>>8), byte(index>>16), byte(index>>24))
		}
		if j < 0 {
			return result
		}
		pattern = pattern[j+1:]
	}
}

func rustMatchOperandCount(program []byte) int {
	count := 0
	for i := 0; i < len(program); i++ {
		if program[i] == 255 {
			count++
			i++
			if program[i] == 255 {
				i += 4
			}
		}
	}
	return count
}

func rustByteString(data []byte) string {
	const hex = "0123456789abcdef"
	var b strings.Builder
	b.WriteString(`b"`)
	for _, c := range data {
		if c >= 32 && c <= 126 && c != '"' && c != '\\' {
			b.WriteByte(c)
		} else {
			b.WriteString(`\x`)
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	b.WriteByte('"')
	return b.String()
}

// A necessary-only literal fingerprint rejects unrelated forms before operand
// parsing. Hash collisions only admit extra candidates; they never reject one.
func rustLiteralFingerprint(program []byte) uint64 {
	var mask uint64
	var run []byte
	flush := func() {
		for i := 0; i+3 <= len(run); i++ {
			word := uint32(run[i]) | uint32(run[i+1])<<8 | uint32(run[i+2])<<16
			mask |= uint64(1) << ((word * 0x9e3779b1) >> 26)
		}
		run = run[:0]
	}
	for i := 0; i < len(program); i++ {
		c := program[i]
		if c == 255 {
			flush()
			i++
			if program[i] == 255 {
				i += 4
			}
			continue
		}
		if c == 1 {
			c = '{'
		} else if c == 2 {
			c = '}'
		}
		run = append(run, c)
	}
	flush()
	return mask
}

func writeRustSyntaxTables(b *strings.Builder, encodings []Encoding) {
	var tables rustTables[rustSyntax]
	indices := make([]int, len(encodings))
	maxBytes, maxMatchOperands := 0, 0
	buckets := map[string]int{}
	dynamic := 0
	filter := false
	for i, e := range encodings {
		syntax := prepareRustSyntax(e)
		indices[i] = tables.intern(syntax)
		maxMatchOperands = max(maxMatchOperands, rustMatchOperandCount(syntax.Pattern))
		maxBytes = max(maxBytes, len(e.Value))
		key := strings.ToLower(strings.Fields(e.Syntax)[0])
		if strings.Contains(key, "{") {
			dynamic++
		} else {
			buckets[key]++
			filter = filter || buckets[key] > 64
		}
	}
	b.WriteString("static ASSEMBLY_LITERALS:&[u64]=&[")
	if filter || dynamic > 64 {
		for _, s := range tables.values {
			fmt.Fprintf(b, "%d,", rustLiteralFingerprint(s.Pattern))
		}
	}
	b.WriteString("];\n")
	fmt.Fprintf(b, "const MAX_INSTRUCTION_BYTES:usize=%d;\n", maxBytes)
	fmt.Fprintf(b, "const MAX_SYNTAX_OPERANDS:usize=%d;\n", maxMatchOperands)
	b.WriteString("struct Syntax{pattern:&'static[u8],display:&'static str,parts:&'static[(u32,u32)]}\nstatic SYNTAXES:&[Syntax]=&[\n")
	for _, s := range tables.values {
		fmt.Fprintf(b, "Syntax{pattern:%s,display:%s,parts:&[", rustByteString(s.Pattern), rustQuote(s.Display))
		for _, p := range s.Parts {
			if p.Operand < 0 {
				fmt.Fprintf(b, "(%d,%d),", p.Start, p.End)
			} else if p.Comma {
				fmt.Fprintf(b, "(%d,u32::MAX-1),", p.Operand)
			} else {
				fmt.Fprintf(b, "(%d,u32::MAX),", p.Operand)
			}
		}
		b.WriteString("]},\n")
	}
	b.WriteString("];\nstatic SYNTAX_INDEX:&[u32]=&[")
	for _, i := range indices {
		fmt.Fprintf(b, "%d,", i)
	}
	b.WriteString("];\n")
}

func rustCommaNames(o Operand) bool {
	return len(o.Names) > 0 && len(o.Names) <= 64 && (o.Scale == 0 || o.Scale == 1) && o.Bias == 0 && o.BiasOperand == "" && len(o.Lookup) == 0
}
