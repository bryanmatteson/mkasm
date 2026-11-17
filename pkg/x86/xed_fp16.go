package x86

import (
	"bufio"
	"crypto/sha256"
	_ "embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// XEDFP16Revision pins the Apache-2.0 Intel XED source used by the supplement.
const XEDFP16Revision = "0bcb6237345c5066726dcc08b3d87928df3b5b26"

//go:embed testdata/intel-xed-fp16/LICENSE
var xedFP16License string

//go:embed testdata/intel-xed-fp16/SOURCE.txt
var xedFP16Provenance string

//go:embed testdata/intel-xed-fp16/avx512-fp16-isa.xed.txt
var xedFP16Source string

// XEDExclusion identifies a source form whose physical constraints the current
// model cannot represent. Exclusions are explicit, never weakened into matches.
type XEDExclusion struct{ Form, Reason string }
type XEDFP16Report struct {
	Imported int
	Excluded []XEDExclusion
}

// SupplementXEDFP16 adds the pinned Intel source to an existing catalog. It does
// not modify or replace opcodesDB forms. Repeated installation is an error.
func SupplementXEDFP16(c *Catalog) (XEDFP16Report, error) {
	supplement, report, err := ParseXEDFP16(strings.NewReader(xedFP16Source))
	if err != nil {
		return report, err
	}
	combined := &Catalog{Encodings: append(append([]Encoding(nil), c.Encodings...), supplement.Encodings...)}
	if err := combined.Validate(); err != nil {
		return report, err
	}
	c.Encodings = combined.Encodings
	return report, nil
}

// ParseXEDFP16 normalizes the pinned AVX512-FP16 grammar into ordinary codec
// forms. This is intentionally a bounded importer, not a general XED compiler:
// unknown grammar fails. Embedded RC/SAE retains logical VL independently of LL.
func ParseXEDFP16(input io.Reader) (*Catalog, XEDFP16Report, error) {
	var report XEDFP16Report
	cat := &Catalog{}
	scanner := bufio.NewScanner(input)
	var block map[string]string
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") || text == "EVEX_INSTRUCTIONS()::" {
			continue
		}
		if text == "{" {
			if block != nil {
				return nil, report, fmt.Errorf("XED line %d: nested block", line)
			}
			block = map[string]string{}
			continue
		}
		if text == "}" {
			if block == nil {
				return nil, report, fmt.Errorf("XED line %d: unmatched block", line)
			}
			e, reason, err := normalizeXEDFP16(block)
			if err != nil {
				return nil, report, fmt.Errorf("XED %s: %w", block["IFORM"], err)
			}
			if reason != "" {
				report.Excluded = append(report.Excluded, XEDExclusion{block["IFORM"], reason})
			} else {
				cat.Encodings = append(cat.Encodings, e)
			}
			block = nil
			continue
		}
		if block == nil {
			return nil, report, fmt.Errorf("XED line %d: unexpected top-level text %q", line, text)
		}
		key, value, ok := strings.Cut(text, ":")
		if !ok {
			return nil, report, fmt.Errorf("XED line %d: expected field", line)
		}
		key = strings.TrimSpace(key)
		if _, exists := block[key]; exists {
			return nil, report, fmt.Errorf("XED line %d: duplicate %s", line, key)
		}
		block[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, report, err
	}
	if block != nil {
		return nil, report, fmt.Errorf("XED: unterminated block")
	}
	if err := cat.Validate(); err != nil {
		return nil, report, err
	}
	report.Imported = len(cat.Encodings)
	return cat, report, nil
}

func normalizeXEDFP16(d map[string]string) (Encoding, string, error) {
	e := Encoding{ID: "XED/" + d["IFORM"], FormID: "XED/" + d["IFORM"], Mnemonic: d["ICLASS"], Kind: EncodingEVEX, Modes: mode32 | mode64, W: BitAny, HasModRM: true, SourceISA: d["ISA_SET"], SourceExtensions: []string{"AVX512_FP16"}, PrefixMask: 7}
	if e.Mnemonic == "" || d["IFORM"] == "" || !strings.HasPrefix(d["ISA_SET"], "AVX512_FP16_") {
		return e, "", fmt.Errorf("missing or non-FP16 identity")
	}
	for _, token := range strings.Fields(d["PATTERN"]) {
		switch token {
		case "EVV", "UBIT=1", "REG[rrr]", "RM[nnn]", "MODRM()", "NOEVSR", "MOD[0b11]", "MOD[mm]":
		case "EVEXR4_ONE()":
			e.RegMask |= 16
		case "MOD=3":
			e.Mod = ModRegister
		case "MOD!=3":
			e.Mod = ModMemory
		case "BCRC=1":
			e.EVEXMask |= 0x10
			e.EVEXValue |= 0x10
		case "AVX512_ROUND()":
			e.EmbeddedRounding = true
			e.SuppressExceptions = true
		case "SAE()":
			e.SuppressExceptions = true
		case "BCRC=0":
			e.EVEXMask |= 0x10
		case "ZEROING=0":
			e.EVEXMask |= 0x80
		case "MASK=0":
			e.EVEXMask |= 7
		case "VNP":
			e.MandatoryPrefix = PrefixNone
		case "V66":
			e.MandatoryPrefix = Prefix66
			e.PrefixValue = 1
		case "VF3":
			e.MandatoryPrefix = PrefixF3
			e.PrefixValue = 2
		case "VF2":
			e.MandatoryPrefix = PrefixF2
			e.PrefixValue = 4
		case "MAP5":
			e.Map = MapEVEX5
		case "MAP6":
			e.Map = MapEVEX6
		case "V0F3A":
			e.Map = Map0F3A
		case "W0":
			e.W = BitZero
		case "W1":
			e.W = BitOne
		case "FIX_ROUND_LEN128()":
			e.VectorLength = 128
			e.VectorLengthIgnored = true
		case "VL128":
			e.VectorLength = 128
		case "VL256":
			e.VectorLength = 256
		case "VL512", "FIX_ROUND_LEN512()":
			e.VectorLength = 512
		case "mode64":
			e.Modes = mode64
		case "not64":
			e.Modes = mode32
		case "ESIZE_16_BITS()", "ESIZE_32_BITS()", "ESIZE_64_BITS()":
		case "NELEM_FULL()":
			e.Tuple = "FV"
		case "NELEM_HALF()":
			e.Tuple = "XED_HALF"
		case "NELEM_QUARTER()":
			e.Tuple = "XED_QUARTER"
		case "NELEM_ONE()":
			e.Tuple = "T1S"
		case "UIMM8()":
			e.Tail = append(e.Tail, Tail8)
		default:
			if strings.HasPrefix(token, "0x") {
				v, err := strconv.ParseUint(token[2:], 16, 8)
				if err != nil {
					return e, "", err
				}
				e.Opcode = byte(v)
			} else {
				return e, "", fmt.Errorf("unrecognized pattern token %q", token)
			}
		}
	}
	if e.VectorLength == 0 || e.Map == MapPrimary {
		return e, "", fmt.Errorf("incomplete physical constraints")
	}
	e.NoSourceDestMatch = strings.Contains(d["ATTRIBUTES"], "NO_SRC_DEST_MATCH")
	if !strings.Contains(d["ATTRIBUTES"], "BROADCAST_ENABLED") {
		e.EVEXMask |= 0x10
	}
	names := []string{}
	for _, token := range strings.Fields(d["OPERANDS"]) {
		op, name, err := xedFP16Operand(token, e)
		if err != nil {
			return e, "", err
		}
		e.Operands = append(e.Operands, op)
		names = append(names, name)
	}
	e.FormID += fmt.Sprintf("/%x", sha256.Sum256([]byte(d["PATTERN"])))
	if strings.Contains(d["ATTRIBUTES"], "BROADCAST_ENABLED") {
		e.Operands = append(e.Operands, Operand{Type: "BCST"})
	}
	e.Syntax = e.Mnemonic + " " + strings.Join(names, ", ")
	e.ReservedVVVV = reservedVVVV(e.Kind, e.Operands)
	features := []ir.RequirementExpr{ir.ParseRequirementExpression("AVX512_FP16", true)}
	if strings.HasSuffix(e.SourceISA, "_128") || strings.HasSuffix(e.SourceISA, "_256") {
		features = append(features, ir.ParseRequirementExpression("AVX512VL", true))
	}
	requirement := features[0]
	if len(features) > 1 {
		requirement = ir.RequirementAll(features...)
	}
	e.Requirements = ir.Requirements{Expression: &requirement, Source: "Intel XED " + XEDFP16Revision + " cpuid.xed.txt"}
	return e, "", nil
}

func xedFP16Operand(token string, e Encoding) (Operand, string, error) {
	fields := strings.Split(token, ":")
	if len(fields) < 3 {
		return Operand{}, "", fmt.Errorf("invalid operand %q", token)
	}
	identity := fields[0]
	access := fields[1]
	size := fields[2]
	datatype := size
	if len(fields) > 3 && !strings.HasPrefix(fields[3], "TXT=") {
		datatype = fields[3]
	}
	if strings.HasPrefix(datatype, "z") {
		datatype = strings.TrimPrefix(datatype, "z")
	}
	op := Operand{Read: strings.Contains(access, "r"), Write: strings.Contains(access, "w"), DataType: strings.ToUpper(datatype)}
	if strings.HasPrefix(identity, "IMM") {
		op.Type = "IMM"
		op.EncodedIn = "IB"
		op.Size = "8"
		return op, "imm8", nil
	}
	if strings.HasPrefix(identity, "MEM") {
		op.Type = "MEM"
		op.EncodedIn = "RM"
		width := int(e.VectorLength)
		switch size {
		case "wrd":
			width = 16
		case "d":
			width = 32
		case "q":
			width = 64
		case "vv":
			switch e.Tuple {
			case "XED_HALF":
				width /= 2
			case "XED_QUARTER":
				width /= 4
			}
		default:
			return op, "", fmt.Errorf("unknown memory width %q", size)
		}
		op.Size = strconv.Itoa(width)
		return op, fmt.Sprintf("m%d", width), nil
	}
	_, value, ok := strings.Cut(identity, "=")
	if !ok {
		return op, "", fmt.Errorf("invalid register %q", identity)
	}
	op.Type = "REG"
	op.EncodedIn = "REG"
	switch {
	case strings.Contains(value, "_B"):
		op.EncodedIn = "RM"
	case strings.Contains(value, "_N"):
		op.EncodedIn = "VVVV"
	case value == "MASK1()":
		op.EncodedIn = "AAA"
		op.Type = "PREG"
	}
	switch {
	case strings.HasPrefix(value, "XMM_"):
		op.Symbol = "XMMREG"
		op.Size = "128"
	case strings.HasPrefix(value, "YMM_"):
		op.Symbol = "YMMREG"
		op.Size = "256"
	case strings.HasPrefix(value, "ZMM_"):
		op.Symbol = "ZMMREG"
		op.Size = "512"
	case strings.HasPrefix(value, "MASK"):
		op.Symbol = "MASKREG"
		op.Size = "64"
	case strings.HasPrefix(value, "GPR32"):
		op.Symbol = "GPR32"
		op.Size = "32"
	case strings.HasPrefix(value, "GPR64"):
		op.Symbol = "GPR64"
		op.Size = "64"
	default:
		return op, "", fmt.Errorf("unknown register %q", value)
	}
	return op, op.Symbol, nil
}

func writeXEDFP16License(c *Catalog, dir string) error {
	for _, e := range c.Encodings {
		if strings.HasPrefix(e.ID, "XED/") {
			if err := os.WriteFile(filepath.Join(dir, "INTEL-XED-LICENSE"), []byte(xedFP16License), 0644); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dir, "INTEL-XED-SOURCE"), []byte(xedFP16Provenance), 0644)
		}
	}
	return nil
}
