package x86

import (
	"bufio"
	"crypto/sha256"
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

// XEDIntegerRevision pins the unmodified Apache-2.0 Intel definitions.
const XEDIntegerRevision = "0bcb6237345c5066726dcc08b3d87928df3b5b26"

//go:embed testdata/intel-xed-integer/*
var xedIntegerFiles embed.FS

var xedIntegerISA = []string{"avx-ifma-isa.xed.txt", "avx-vnni-isa.xed.txt", "avx-vnni-int8-isa.xed.txt", "avx-vnni-int16-isa.xed.txt", "avx512-vnni-int16-isa.xed.txt", "avx10-2-simd-isa.xed.txt"}

type XEDIntegerReport struct {
	Imported int
	// OtherClasses counts non-integer classes in the unmodified AVX10.2 file.
	OtherClasses int
}

// SupplementXEDInteger installs the pinned VEX IFMA/VNNI and EVEX VNNI
// signedness variants. It preserves existing forms and rejects duplicate installs.
func SupplementXEDInteger(c *Catalog) (XEDIntegerReport, error) {
	var report XEDIntegerReport
	forms := append([]Encoding(nil), c.Encodings...)
	for _, name := range xedIntegerISA {
		data, err := xedIntegerFiles.ReadFile("testdata/intel-xed-integer/" + name)
		if err != nil {
			return report, err
		}
		cat, r, err := ParseXEDInteger(strings.NewReader(string(data)))
		if err != nil {
			return report, fmt.Errorf("%s: %w", name, err)
		}
		report.Imported += r.Imported
		report.OtherClasses += r.OtherClasses
		forms = append(forms, cat.Encodings...)
	}
	combined := &Catalog{Encodings: forms}
	if err := combined.Validate(); err != nil {
		return report, err
	}
	c.Encodings = forms
	return report, nil
}

func integerXEDISA(isa string) bool {
	return isa == "AVX_IFMA" || isa == "AVX_VNNI" || isa == "AVX_VNNI_INT8" || isa == "AVX_VNNI_INT16" || strings.HasPrefix(isa, "AVX512_VNNI_INT8_") || strings.HasPrefix(isa, "AVX512_VNNI_INT16_")
}

// ParseXEDInteger implements the closed grammar of these primary definitions.
// Unknown constraints on selected classes fail; unrelated AVX10.2 classes are
// counted separately, never presented as imported integer coverage.
func ParseXEDInteger(input io.Reader) (*Catalog, XEDIntegerReport, error) {
	var report XEDIntegerReport
	cat := &Catalog{}
	scanner := bufio.NewScanner(input)
	var block map[string]string
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(scanner.Text())
		if text == "" || strings.HasPrefix(text, "#") || text == "AVX_INSTRUCTIONS()::" || text == "EVEX_INSTRUCTIONS()::" {
			continue
		}
		if text == "{" {
			if block != nil {
				return nil, report, fmt.Errorf("line%d: nested block", line)
			}
			block = map[string]string{}
			continue
		}
		if text == "}" {
			if block == nil {
				return nil, report, fmt.Errorf("line%d: unmatched block", line)
			}
			if integerXEDISA(block["ISA_SET"]) {
				e, err := normalizeXEDInteger(block)
				if err != nil {
					return nil, report, fmt.Errorf("%s: %w", block["IFORM"], err)
				}
				cat.Encodings = append(cat.Encodings, e)
			} else {
				if strings.HasPrefix(block["ICLASS"], "VPDP") || strings.HasPrefix(block["ICLASS"], "VPMADD52") {
					return nil, report, fmt.Errorf("integer class has unknown ISA %s", block["ISA_SET"])
				}
				report.OtherClasses++
			}
			block = nil
			continue
		}
		if block == nil {
			return nil, report, fmt.Errorf("line%d: unexpected text", line)
		}
		key, value, ok := strings.Cut(text, ":")
		if !ok {
			return nil, report, fmt.Errorf("line%d: missing field separator", line)
		}
		key = strings.TrimSpace(key)
		if _, ok := block[key]; ok {
			return nil, report, fmt.Errorf("line%d: duplicate field %s", line, key)
		}
		block[key] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, report, err
	}
	if block != nil {
		return nil, report, fmt.Errorf("unterminated block")
	}
	if err := cat.Validate(); err != nil {
		return nil, report, err
	}
	report.Imported = len(cat.Encodings)
	return cat, report, nil
}

func normalizeXEDInteger(d map[string]string) (Encoding, error) {
	e := Encoding{ID: "XED-INTEGER/" + d["IFORM"], FormID: "XED-INTEGER/" + d["IFORM"], Mnemonic: d["ICLASS"], Modes: modeAll, W: BitAny, HasModRM: true, SourceISA: d["ISA_SET"], PrefixMask: 7}
	if e.Mnemonic == "" || d["IFORM"] == "" {
		return e, fmt.Errorf("missing identity")
	}
	family := ""
	switch e.Mnemonic {
	case "VPMADD52HUQ", "VPMADD52LUQ":
		family = "AVX_IFMA"
	case "VPDPBUSD", "VPDPBUSDS", "VPDPWSSD", "VPDPWSSDS":
		family = "AVX_VNNI"
	case "VPDPBSSD", "VPDPBSSDS", "VPDPBSUD", "VPDPBSUDS", "VPDPBUUD", "VPDPBUUDS":
		family = "AVX_VNNI_INT8"
	case "VPDPWSUD", "VPDPWSUDS", "VPDPWUSD", "VPDPWUSDS", "VPDPWUUD", "VPDPWUUDS":
		family = "AVX_VNNI_INT16"
	default:
		return e, fmt.Errorf("unknown integer class %s", e.Mnemonic)
	}
	evex := strings.HasPrefix(e.SourceISA, "AVX512_")
	if e.SourceISA != family && (!evex || !strings.HasPrefix(e.SourceISA, strings.Replace(family, "AVX_", "AVX512_", 1)+"_")) {
		return e, fmt.Errorf("class/ISA mismatch")
	}
	for _, token := range strings.Fields(d["PATTERN"]) {
		switch token {
		case "VV1":
			e.Kind = EncodingVEX
		case "EVV":
			e.Kind = EncodingEVEX
		case "UBIT=1", "REG[rrr]", "RM[nnn]", "MODRM()", "MOD[0b11]", "MOD[mm]", "ESIZE_32_BITS()":
		case "MOD=3":
			e.Mod = ModRegister
		case "MOD!=3":
			e.Mod = ModMemory
		case "BCRC=0":
			e.EVEXMask |= 16
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
		case "V0F38":
			e.Map = Map0F38
		case "W0":
			e.W = BitZero
		case "W1":
			e.W = BitOne
		case "VL128":
			e.VectorLength = 128
		case "VL256":
			e.VectorLength = 256
		case "VL512":
			e.VectorLength = 512
		case "NELEM_FULL()":
			e.Tuple = "FV"
		default:
			if strings.HasPrefix(token, "0x") {
				v, err := strconv.ParseUint(token[2:], 16, 8)
				if err != nil {
					return e, err
				}
				e.Opcode = byte(v)
			} else {
				return e, fmt.Errorf("unrecognized pattern token %q", token)
			}
		}
	}
	if (e.Kind == EncodingEVEX) != evex || e.Map != Map0F38 || e.VectorLength == 0 || e.W == BitAny || e.Mod == ModAny || e.Kind == EncodingVEX && e.VectorLength > 256 {
		return e, fmt.Errorf("incomplete physical constraints")
	}
	for _, attribute := range strings.Fields(d["ATTRIBUTES"]) {
		switch attribute {
		case "BROADCAST_ENABLED", "DISP8_FULL", "MASKOP_EVEX", "MEMORY_FAULT_SUPPRESSION":
		default:
			return e, fmt.Errorf("unknown attribute %s", attribute)
		}
	}
	if evex && !strings.Contains(d["ATTRIBUTES"], "BROADCAST_ENABLED") {
		e.EVEXMask |= 16
	}
	names := []string{}
	for _, token := range strings.Fields(d["OPERANDS"]) {
		fields := strings.Split(token, ":")
		if len(fields) < 3 {
			return e, fmt.Errorf("bad operand %s", token)
		}
		if strings.HasPrefix(fields[0], "MEM") {
			switch fields[2] {
			case "dq", "qq":
				if fields[2] == "dq" && e.VectorLength != 128 || fields[2] == "qq" && e.VectorLength != 256 {
					return e, fmt.Errorf("fixed memory width disagrees with vector length")
				}
				fields[2] = "vv"
			case "vv":
			default:
				return e, fmt.Errorf("unrecognized memory width %s", fields[2])
			}
		}
		if len(fields) > 3 {
			switch fields[3] {
			case "4i8", "2i16":
				fields[3] = "i32"
			case "4u8", "2u16":
				fields[3] = "u32"
			}
		}
		op, name, err := xedFP16Operand(strings.Join(fields, ":"), e)
		if err != nil {
			return e, err
		}
		e.Operands = append(e.Operands, op)
		names = append(names, name)
	}
	if strings.Contains(d["ATTRIBUTES"], "BROADCAST_ENABLED") {
		e.Operands = append(e.Operands, Operand{Type: "BCST"})
	}
	e.FormID += fmt.Sprintf("/%x", sha256.Sum256([]byte(d["PATTERN"])))
	e.Syntax = e.Mnemonic + " " + strings.Join(names, ", ")
	e.ReservedVVVV = reservedVVVV(e.Kind, e.Operands)
	e.SourceExtensions = []string{family}
	feature := ir.ParseRequirementExpression(family, true)
	if evex {
		feature = ir.RequirementAny(ir.RequirementAll(ir.ParseRequirementExpression("AVX10_ENABLED", true), ir.RequirementExpr{Op: "field_eq", Name: "CPUID.24.0.EBX", Mask: 255, Value: 2}), ir.ParseRequirementExpression("AVX10_V1_AUX", true))
		e.SourceExtensions = []string{"AVX10_2", "AVX10_V1_AUX"}
	}
	e.Requirements = ir.Requirements{Expression: &feature, Source: "Intel XED " + XEDIntegerRevision + " cpuid.xed.txt"}
	return e, nil
}

func writeXEDIntegerLicense(c *Catalog, dir string) error {
	for _, e := range c.Encodings {
		if strings.HasPrefix(e.ID, "XED-INTEGER/") {
			license, err := xedIntegerFiles.ReadFile("testdata/intel-xed-integer/LICENSE")
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(dir, "INTEL-XED-LICENSE"), license, 0644); err != nil {
				return err
			}
			notice, err := xedIntegerFiles.ReadFile("testdata/intel-xed-integer/SOURCE.txt")
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dir, "INTEL-XED-INTEGER-SOURCE"), notice, 0644)
		}
	}
	return nil
}
