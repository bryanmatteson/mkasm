package x86

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type opcodesDBDocument struct {
	Version string            `json:"version"`
	Arch    string            `json:"arch"`
	Records []opcodesDBRecord `json:"records"`
}

type opcodesDBRecord struct {
	ID      string `json:"id"`
	RecType string `json:"rectype"`
	Diagram struct {
		Fields []opcodesDBField `json:"fields"`
	} `json:"diagram"`
	Templates []opcodesDBTemplate `json:"templates"`
}

type opcodesDBTemplate struct {
	BitDiffs *struct {
		Fields []opcodesDBField `json:"fields"`
	} `json:"bitdiffs"`
	Syntax struct {
		Mnemonic string             `json:"mnem"`
		Text     string             `json:"text"`
		AST      []opcodesDBOperand `json:"ast"`
	} `json:"syntax"`
	Metadata struct {
		Tuple string `json:"tuple"`
	} `json:"metadata"`
}

type opcodesDBField struct {
	Name  string `json:"name"`
	Value any    `json:"value"`
}

type opcodesDBOperand struct {
	Type             string `json:"type"`
	Symbol           string `json:"symbol"`
	EncodedIn        string `json:"encodedin"`
	DataType         string `json:"datatype"`
	Size             any    `json:"size"`
	Value            any    `json:"value"`
	Read             int    `json:"read"`
	Write            int    `json:"write"`
	Suppressed       int    `json:"suppressed"`
	Zeroing          int    `json:"zeroing"`
	ConditionalRead  int    `json:"conditional_reading"`
	ConditionalWrite int    `json:"conditional_writing"`
}

// ParseOpcodesDB reads an uncompressed opcodesDB v3 JSON document and
// normalizes every syntax template into a separately decodable form.
func ParseOpcodesDB(r io.Reader) (*Catalog, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	var doc opcodesDBDocument
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode opcodesDB JSON: %w", err)
	}
	if doc.Version != "3" {
		return nil, fmt.Errorf("unsupported opcodesDB version %q (want 3)", doc.Version)
	}
	if !strings.EqualFold(doc.Arch, "x86") {
		return nil, fmt.Errorf("opcodesDB architecture is %q, not x86", doc.Arch)
	}

	cat := &Catalog{}
	for _, record := range doc.Records {
		if record.RecType != "ENCODING" {
			continue
		}
		base := fieldMap(record.Diagram.Fields)
		for templateIndex, tmpl := range record.Templates {
			fields := cloneFields(base)
			if tmpl.BitDiffs != nil {
				for name, value := range fieldMap(tmpl.BitDiffs.Fields) {
					fields[name] = value
				}
			}
			e, err := importOpcodesDBForm(record.ID, templateIndex, tmpl, fields)
			if err != nil {
				return nil, err
			}
			cat.Encodings = append(cat.Encodings, e)
		}
	}
	if err := cat.Validate(); err != nil {
		return nil, err
	}
	return cat, nil
}

func importOpcodesDBForm(id string, templateIndex int, tmpl opcodesDBTemplate, fields map[string]string) (Encoding, error) {
	op, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(fields["OP"]), "0x"), 16, 8)
	if err != nil {
		return Encoding{}, fmt.Errorf("%s template %d: invalid opcode %q", id, templateIndex, fields["OP"])
	}
	kind, err := parseEncodingKind(fields["ENC"])
	if err != nil {
		return Encoding{}, fmt.Errorf("%s template %d: %w", id, templateIndex, err)
	}
	opcodeMap, err := parseOpcodeMap(fields["MAP"])
	if err != nil {
		return Encoding{}, fmt.Errorf("%s template %d: %w", id, templateIndex, err)
	}
	prefix, err := parseMandatoryPrefix(fields)
	if err != nil {
		return Encoding{}, fmt.Errorf("%s template %d: %w", id, templateIndex, err)
	}

	e := Encoding{
		ID: id, FormID: fmt.Sprintf("%s/%d", id, templateIndex),
		Mnemonic: tmpl.Syntax.Mnemonic, Syntax: tmpl.Syntax.Text,
		Kind: kind, Map: opcodeMap, Opcode: byte(op), MandatoryPrefix: prefix,
		Modes: parseModes(fields["MODE"]), W: parseBit(fields["W"]), Tuple: tmpl.Metadata.Tuple,
		Mod: ModAny,
	}
	e.PrefixMask, e.PrefixValue = parsePrefixBits(fields)
	if size, parseErr := strconv.ParseUint(fields["OSZ"], 10, 8); parseErr == nil && (size == 16 || size == 32 || size == 64) {
		e.OperandSize = uint8(size)
	}
	if e.Kind == EncodingLegacy && fields["OSZ"] != "" {
		// In legacy encodings the physical 66 byte can be the OSZ
		// override even when P66 (mandatory-prefix role) is zero.
		e.PrefixMask &^= 1
		e.PrefixValue &^= 1
		if strings.EqualFold(fields["OSZ"], "Z") {
			e.W = BitZero
		}
	}
	if vl, parseErr := strconv.ParseUint(fields["VL"], 10, 16); parseErr == nil {
		e.VectorLength = uint16(vl)
	}
	e.HasModRM = fields["MR"] == "1" || fields["MOD"] != "" || fields["REG"] != "" || fields["RM"] != ""
	switch fields["MOD"] {
	case "MEM":
		e.Mod = ModMemory
	case "REG":
		e.Mod = ModRegister
	}
	if v, ok := parseThreeBits(fields["REG"]); ok {
		e.RegMask, e.RegValue = 7, v
	}
	if v, ok := parseThreeBits(fields["RM"]); ok {
		e.RMMask, e.RMValue = 7, v
	}
	hasIS4 := false
	for _, operand := range tmpl.Syntax.AST {
		if strings.EqualFold(operand.EncodedIn, "IS4") {
			hasIS4 = true
			break
		}
	}
	for _, operand := range tmpl.Syntax.AST {
		e.Operands = append(e.Operands, Operand{
			Type: strings.ToUpper(operand.Type), Symbol: operand.Symbol,
			EncodedIn: strings.ToUpper(operand.EncodedIn), DataType: operand.DataType,
			Size: scalarString(operand.Size), Value: scalarString(operand.Value),
			Read: operand.Read != 0, Write: operand.Write != 0,
			Suppressed: operand.Suppressed != 0, Zeroing: operand.Zeroing != 0,
			ConditionalRead:  operand.ConditionalRead != 0,
			ConditionalWrite: operand.ConditionalWrite != 0,
		})
		// opcodesDB expands +r opcode families into one ENCODING record per
		// register (B8, B9, ...), while retaining encodedin=OPCODE on the
		// operand. The opcode is therefore already exact for this form.
		// IS4 stores a register in the high nibble of the same byte whose
		// low nibble is described as IB. It is one physical tail byte, not
		// two consecutive immediates.
		if width, ok := tailWidth(operand.Type, operand.EncodedIn); ok && !(hasIS4 && strings.EqualFold(operand.EncodedIn, "IB")) {
			e.Tail = append(e.Tail, width)
		}
	}
	return e, nil
}

func scalarString(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func fieldMap(in []opcodesDBField) map[string]string {
	out := make(map[string]string, len(in))
	for _, field := range in {
		out[strings.ToUpper(field.Name)] = fmt.Sprint(field.Value)
	}
	return out
}

func cloneFields(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func parseEncodingKind(s string) (EncodingKind, error) {
	switch strings.ToUpper(s) {
	case "":
		return EncodingLegacy, nil
	case "VEX":
		return EncodingVEX, nil
	case "EVEX":
		return EncodingEVEX, nil
	case "MVEX":
		return EncodingMVEX, nil
	case "XOP":
		return EncodingXOP, nil
	case "3DNOW":
		return Encoding3DNow, nil
	default:
		return 0, fmt.Errorf("unsupported encoding family %q", s)
	}
}

func parseOpcodeMap(s string) (OpcodeMap, error) {
	switch strings.ToLower(s) {
	case "":
		return MapPrimary, nil
	case "0f":
		return Map0F, nil
	case "0f38":
		return Map0F38, nil
	case "0f3a":
		return Map0F3A, nil
	case "0f0f":
		return Map0F0F, nil
	case "xop8":
		return MapXOP8, nil
	case "xop9":
		return MapXOP9, nil
	case "xopa":
		return MapXOPA, nil
	default:
		return 0, fmt.Errorf("unsupported opcode map %q", s)
	}
}

func parseMandatoryPrefix(fields map[string]string) (MandatoryPrefix, error) {
	var found []MandatoryPrefix
	for name, prefix := range map[string]MandatoryPrefix{"P66": Prefix66, "PF3": PrefixF3, "PF2": PrefixF2} {
		if fields[name] == "1" {
			found = append(found, prefix)
		}
	}
	if len(found) > 1 {
		return 0, fmt.Errorf("conflicting mandatory prefixes")
	}
	if len(found) == 1 {
		return found[0], nil
	}
	return PrefixNone, nil
}

func parsePrefixBits(fields map[string]string) (mask, value byte) {
	for name, bit := range map[string]byte{"P66": 1 << 0, "PF3": 1 << 1, "PF2": 1 << 2} {
		if v, exists := fields[name]; exists {
			mask |= bit
			if v == "1" {
				value |= bit
			}
		}
	}
	return mask, value
}

func parseModes(s string) ModeMask {
	switch strings.ToUpper(s) {
	case "64":
		return mode64
	case "NO64":
		return mode16 | mode32
	default:
		return modeAll
	}
}

func parseBit(s string) BitConstraint {
	switch s {
	case "0":
		return BitZero
	case "1":
		return BitOne
	default:
		return BitAny
	}
}

func parseThreeBits(s string) (byte, bool) {
	n, err := strconv.ParseUint(s, 10, 3)
	return byte(n), err == nil
}

func tailWidth(operandType, encodedIn string) (TailWidth, bool) {
	if strings.EqualFold(operandType, "MOFFS") {
		return TailAddress, true
	}
	switch strings.ToUpper(encodedIn) {
	case "IB", "RB":
		return Tail8, true
	case "IS4":
		return Tail8, true
	case "IW", "RW":
		return Tail16, true
	case "ID", "RD":
		return Tail32, true
	case "IQ", "RQ":
		return Tail64, true
	case "IZ", "RZ":
		return TailZ, true
	case "IV", "RV":
		return TailV, true
	case "IDPP":
		return TailFarPointer, true
	default:
		return 0, false
	}
}
