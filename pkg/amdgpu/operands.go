package amdgpu

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func (p *importer) registerNames(class string, operand *record, bits int, instruction *record) ([]string, error) {
	if bits > 12 {
		return nil, fmt.Errorf("register selector %s has %d bits", class, bits)
	}
	meta := p.rec(class)
	// BaseClassOrder is an allocation priority (VGPR_16 uses 17), not
	// the register width. TableGen's Size is the physical class width.
	width := meta.Size
	if width == 0 {
		if m := wordWidth.FindStringSubmatch(class); m != nil {
			width, _ = strconv.Atoi(m[1])
		}
	}
	if width == 0 {
		width = 32
	}
	if strings.HasPrefix(class, "SReg_1_") || class == "SReg_1" {
		width = 64
		for _, f := range instruction.Predicates {
			if f.Def == "isWave32" {
				width = 32
			}
		}
	}
	key := fmt.Sprintf("%s/%s/%d/%d/%s", class, operand.OperandType, bits, width, instruction.DecoderNamespace+operand.EncoderMethod+operand.DecoderMethod)
	if cached := p.names[key]; cached != nil {
		return cached, nil
	}
	count := 1 << bits
	names := make([]string, count)
	words := (width + 31) / 32
	sgpr, vgpr, agpr := meta.HasSGPR != 0, meta.HasVGPR != 0, meta.HasAGPR != 0
	if strings.Contains(class, "VGPR") || strings.HasPrefix(class, "VReg") {
		vgpr = true
	}
	if strings.HasPrefix(class, "SReg") || strings.HasPrefix(class, "SGPR") {
		sgpr = true
	}
	if strings.HasPrefix(class, "VS_") {
		sgpr = true
		vgpr = true
	}
	if strings.HasPrefix(class, "AV") {
		vgpr = true
		agpr = true
	}
	if strings.HasPrefix(class, "AReg") || strings.HasPrefix(class, "AGPR") {
		agpr = true
	}
	if !sgpr && !vgpr && !agpr {
		return nil, fmt.Errorf("register class %s has no resolved bank", class)
	}
	tuple := func(bank string, base int) string {
		if words <= 1 {
			return fmt.Sprintf("%s%d", bank, base)
		}
		return fmt.Sprintf("%s[%d:%d]", bank, base, base+words-1)
	}
	source := (bits >= 9 && (vgpr || agpr)) || strings.Contains(operand.OperandType, "REG_IMM") || strings.Contains(operand.OperandType, "REG_INLINE") || strings.Contains(operand.OperandType, "REG_INLINE_AC") || strings.HasPrefix(operand.DecoderMethod, "decodeSrc")
	for i := range names {
		index := i
		bank := ""
		if agpr && !vgpr && !sgpr && source {
			index -= 256
		}
		if vgpr && (!sgpr || i >= 256) {
			bank = "v"
			if source || sgpr {
				index -= 256
			}
		} else if sgpr {
			bank = "s"
		} else if agpr {
			bank = "a"
		}
		if index < 0 {
			continue
		}
		if bank == "s" {
			if index+words <= 106 && (words == 1 || index%words == 0 || words == 3) {
				names[i] = tuple(bank, index)
			}
		} else if index+words <= 256 {
			if words <= 1 || !strings.Contains(class, "Align2") || index%2 == 0 {
				names[i] = tuple(bank, index)
			}
		}
	}
	if sgpr {
		// Architectural selector values. Scalar tuples use the base selector, not
		// a tuple ordinal; the source bit slices encode the omitted low bits.
		specials := map[int]string{106: "vcc_lo", 107: "vcc_hi", 124: "m0", 125: "null", 126: "exec_lo", 127: "exec_hi", 251: "vccz", 252: "execz", 253: "scc", 254: "lds_direct"}
		if words == 2 {
			specials = map[int]string{106: "vcc", 126: "exec", 125: "null"}
		}
		if strings.Contains(instruction.DecoderNamespace, "GFX11") || strings.Contains(instruction.DecoderNamespace, "GFX12") {
			delete(specials, 124)
			delete(specials, 125)
			specials[124] = "null"
			if words == 1 {
				specials[125] = "m0"
			}
		}
		for i, name := range specials {
			if name == "null" && strings.Contains(class, "XNULL") {
				continue
			}
			if i < len(names) {
				names[i] = name
			}
		}
		if strings.Contains(class, "XNULL") && len(names) > 125 {
			if names[124] == "null" {
				names[124] = ""
			}
			if names[125] == "null" {
				names[125] = ""
			}
		}
		if strings.Contains(class, "XM0") && len(names) > 124 {
			names[124] = ""
		}
		if strings.Contains(class, "XEXEC") && len(names) > 127 {
			names[126] = ""
			names[127] = ""
		}
		ttmp := 108
		if instruction.DecoderNamespace == "GFX6GFX7" || instruction.DecoderNamespace == "GFX7" || instruction.DecoderNamespace == "GFX8" {
			ttmp = 112
		}
		for n := 0; n < 16; n++ {
			i := ttmp + n
			if i < len(names) && i < 124 && n+words <= 16 && (words == 1 || n%words == 0) {
				if words == 1 {
					names[i] = fmt.Sprintf("ttmp%d", n)
				} else {
					names[i] = fmt.Sprintf("ttmp[%d:%d]", n, n+words-1)
				}
			}
		}
	}
	if strings.Contains(operand.OperandType, "REG_IMM") || strings.Contains(operand.OperandType, "REG_INLINE") {
		if !strings.Contains(operand.OperandType, "NOINLINE") {
			for v := 0; v <= 64; v++ {
				if i := 128 + v; i < count {
					names[i] = strconv.Itoa(v)
				}
			}
			for v := 1; v <= 16; v++ {
				if i := 192 + v; i < count {
					names[i] = strconv.Itoa(-v)
				}
			}
			for k, s := range []string{"0.5", "-0.5", "1.0", "-1.0", "2.0", "-2.0", "4.0", "-4.0", "0.15915494"} {
				if i := 240 + k; i < count {
					names[i] = s
				}
			}
		}
		// Literal selectors are framed by separate expanded catalog forms.
		if count > 255 {
			names[255] = ""
		}
		if count > 254 && strings.HasSuffix(operand.OperandType, "64") {
			// On GFX12.5 this selector frames an eight-byte literal. It is
			// not an LDS source for 64-bit scalar/vector operand classes.
			names[254] = ""
		}
	}
	if width == 16 && strings.Contains(operand.EncoderMethod, "T16") {
		for k, n := range names {
			if len(n) > 1 && n[0] == 'v' && n[1] >= '0' && n[1] <= '9' {
				index := k
				if sgpr || source {
					index -= 256
				}
				high := false
				if strings.Contains(operand.EncoderMethod, "Lo128") {
					index &= 255
					high = index&128 != 0
					index &= 127
				}
				if index < 0 || index >= 256 {
					names[k] = ""
					continue
				}
				suffix := ".l"
				if high {
					suffix = ".h"
				}
				names[k] = fmt.Sprintf("v%d%s", index, suffix)
			}
		}
	}
	if operand.EncoderMethod == "getAVOperandEncoding" {
		for k := range names {
			names[k] = ""
			if k&256 != 0 {
				continue
			}
			index := k & 255
			if index+words > 256 {
				continue
			}
			bank := "v"
			if k&512 != 0 || agpr && !vgpr {
				bank = "a"
			}
			names[k] = tuple(bank, index)
		}
	}
	if operand.EncoderMethod == "getSDWASrcEncoding" && bits == 8 {
		for k := range names {
			names[k] = fmt.Sprintf("v%d", k)
		}
	}
	if operand.EncoderMethod == "getSDWASrcEncoding" && bits == 9 {
		sdwa := make([]string, count)
		for k, n := range names {
			if n == "" {
				continue
			}
			dst := k + 256
			if k >= 256 {
				dst = k - 256
			}
			if dst < count {
				sdwa[dst] = n
			}
		}
		names = sdwa
	}
	if operand.EncoderMethod == "getSDWAVopcDstEncoding" {
		dst := make([]string, count)
		for k, n := range names {
			if n != "" && k+128 < count {
				dst[k+128] = n
			}
		}
		dst[0] = "vcc"
		names = dst
	}
	valid := false
	for _, n := range names {
		if n != "" {
			valid = true
			break
		}
	}
	if !valid {
		return nil, fmt.Errorf("no register names for %s", class)
	}
	p.names[key] = names
	return names, nil
}

var namedBit = regexp.MustCompile(`printNamedBit\([^;]*"([A-Za-z0-9_]+)"`)

func (p *importer) suffixNames(o *codec.Operand, m *record, r *record) ([]string, bool) {
	width := o.Width()
	if width > 16 {
		return nil, false
	}
	count := 1 << width
	prefix := numericPrefix(m)
	method := m.PrintMethod
	if method == "printCPol" && r.IsAtomicRet != 0 {
		for _, b := range o.Bits {
			if b.ValueBit == 0 {
				copy := *r
				copy.IsAtomicRet = 0
				r = &copy
				break
			}
		}
	}
	key := fmt.Sprintf("suffix/%s/%s/%d/%s", o.Class, o.Name, width, r.DecoderNamespace)
	if method == "printCPol" {
		key += fmt.Sprintf("/%s/%d/%v", strings.Fields(r.AsmString)[0], r.IsAtomicRet, r.Predicates)
	}
	if cached := p.names[key]; cached != nil {
		return cached, true
	}
	names := make([]string, count)
	for i := range names {
		names[i] = " "
	}
	ok := true
	if match := namedBit.FindStringSubmatch(method); match != nil {
		if count != 2 {
			return nil, false
		}
		names[1] = " " + match[1]
	} else if prefix != "" && !strings.HasPrefix(method, "printDpp") {
		def, _ := strconv.ParseInt(m.DefaultValue, 0, 64)
		for i := 0; i < count; i++ {
			if int64(i) != def {
				names[i] = fmt.Sprintf(" %s:%d", prefix, i)
			}
		}
	} else {
		switch {
		case method == "printMatrixAScaleFmt" || method == "printMatrixBScaleFmt":
			for k := range names {
				if k != 0 {
					names[k] = fmt.Sprintf(" %s:%d", o.Name, k)
				}
			}
		case method == "printMatrixAScale" || method == "printMatrixBScale":
			for k := range names {
				if k != 0 {
					names[k] = fmt.Sprintf(" %s:MATRIX_SCALE_ROW%d", o.Name, k)
				}
			}
		case method == "printMatrixAFMT" || method == "printMatrixBFMT":
			for k := range names {
				if k != 0 {
					names[k] = fmt.Sprintf(" %s:%d", o.Name, k)
				}
			}
		case method == "printInterpAttr":
			for k := range names {
				names[k] = fmt.Sprintf("attr%d", k)
			}
		case method == "printInterpAttrChan":
			for k := range names {
				if k < 4 {
					names[k] = "." + string("xyzw"[k])
				} else {
					names[k] = ""
				}
			}
		case method == "printInterpSlot":
			for k := range names {
				if k < 3 {
					names[k] = []string{"p10", "p20", "p0"}[k]
				} else {
					names[k] = ""
				}
			}
		case method == "printExpTgt":
			for k := range names {
				switch {
				case k < 8:
					names[k] = fmt.Sprintf("mrt%d", k)
				case k == 8:
					names[k] = "mrtz"
				case k == 9:
					names[k] = "null"
				case k >= 12 && k < 16:
					names[k] = fmt.Sprintf("pos%d", k-12)
				case k >= 32 && k < 64:
					names[k] = fmt.Sprintf("param%d", k-32)
				default:
					names[k] = ""
				}
			}
		case method == "printHwreg":
			for k := range names {
				names[k] = fmt.Sprintf("hwreg(%d,%d,%d)", k&63, (k>>6)&31, (k>>11)+1)
			}
		case method == "printDPPCtrl":
			names = dppNames(count, r.DecoderNamespace)
		case method == "printFORMAT":
			for i := range names {
				names[i] = fmt.Sprintf(" format:%d", i)
			}
		case method == "printDppRowMask" || method == "printDppBankMask":
			for i := range names {
				names[i] = fmt.Sprintf(" %s:%d", o.Name, i)
			}
		case method == "printDppBoundCtrl":
			if count > 1 {
				names[1] = " bound_ctrl:1"
			}
		case method == "printDppFI":
			for i := range names {
				names[i] = ""
			}
			if count > 234 {
				names[233] = " "
				names[234] = " fi:1"
			} else if count > 1 {
				names[0] = " "
				names[1] = " fi:1"
			}
		case method == "printCPol":
			for i := range names {
				names[i] = cachePolicyName(i, r)
			}
		case method == "printDim":
			dims := []string{"1d", "2d", "3d", "cube", "1d_array", "2d_array", "2d_msaa", "2d_msaa_array"}
			for i := range names {
				if i < len(dims) {
					names[i] = " dim:SQ_RSRC_IMG_" + strings.ToUpper(dims[i])
				} else {
					names[i] = ""
				}
			}
		case method == "printOModSI":
			for i := range names {
				if i < 4 {
					names[i] = []string{" ", " mul:2", " mul:4", " div:2"}[i]
				} else {
					names[i] = ""
				}
			}
		case method == "printEndpgm":
			for i := 1; i < count; i++ {
				names[i] = " " + strconv.Itoa(i)
			}
		case strings.HasPrefix(method, "printSDWA"):
			values := []string{"BYTE_0", "BYTE_1", "BYTE_2", "BYTE_3", "WORD_0", "WORD_1", "DWORD"}
			label := strings.ToLower(o.Name)
			if strings.Contains(method, "Unused") {
				values = []string{"UNUSED_PAD", "UNUSED_SEXT", "UNUSED_PRESERVE"}
			}
			for i := range names {
				if i < len(values) {
					names[i] = " " + label + ":" + values[i]
				} else {
					names[i] = ""
				}
			}
		case strings.HasPrefix(o.Class, "op_sel") || strings.HasPrefix(o.Class, "neg_lo") || strings.HasPrefix(o.Class, "neg_hi"):
			for i := range names {
				var s []string
				for b := 0; b < width; b++ {
					s = append(s, strconv.Itoa((i>>b)&1))
				}
				if i != 0 || strings.Contains(o.Class, "hi") {
					names[i] = " " + o.Name + ":[" + strings.Join(s, ",") + "]"
				}
			}
		case o.Class == "gds" || o.Class == "GDS":
			if count > 1 {
				names[1] = " gds"
			}
		case method == "printR128A16":
			if count > 1 {
				names[1] = " r128"
			}
		case o.Class == "i1imm_0":
			if count > 1 {
				names[1] = " " + o.Name
			}
		default:
			ok = false
		}
	}
	if !ok {
		return nil, false
	}
	p.names[key] = names
	return names, true
}

var namedInt = regexp.MustCompile(`printNamedInt\([^;]*"([A-Za-z0-9_]+)"`)

func numericPrefix(m *record) string {
	if match := namedInt.FindStringSubmatch(m.PrintMethod); match != nil {
		return match[1]
	}
	if strings.HasPrefix(m.PrintMethod, "printDpp") {
		return ""
	}
	if m.Prefix != "" && (m.PrintMethod == "" || m.PrintMethod == "printOperand") {
		return m.Prefix
	}
	return map[string]string{"printOffset": "offset", "printFlatOffset": "offset", "printBLGP": "blgp", "printBitOp3": "bitop3", "printIndexKey16bit": "index_key", "printIndexKey8bit": "index_key", "printIndexKey32bit": "index_key"}[m.PrintMethod]
}
func dppNames(count int, generation string) []string {
	names := make([]string, count)
	for i := range names {
		switch {
		case i <= 255:
			names[i] = fmt.Sprintf(" quad_perm:[%d,%d,%d,%d]", i&3, (i>>2)&3, (i>>4)&3, (i>>6)&3)
		case i > 0x100 && i <= 0x10f:
			names[i] = fmt.Sprintf(" row_shl:%d", i-0x100)
		case i > 0x110 && i <= 0x11f:
			names[i] = fmt.Sprintf(" row_shr:%d", i-0x110)
		case i > 0x120 && i <= 0x12f:
			names[i] = fmt.Sprintf(" row_ror:%d", i-0x120)
		case i >= 0x150 && i <= 0x15f:
			prefix := "row_share"
			if generation == "GFX90A" || generation == "GFX940" {
				prefix = "row_newbcast"
			}
			names[i] = fmt.Sprintf(" %s:%d", prefix, i-0x150)
		case i >= 0x160 && i <= 0x16f:
			names[i] = fmt.Sprintf(" row_xmask:%d", i-0x160)
		default:
			names[i] = map[int]string{0x130: " wave_shl:1", 0x134: " wave_rol:1", 0x138: " wave_shr:1", 0x13c: " wave_ror:1", 0x140: " row_mirror", 0x141: " row_half_mirror", 0x142: " row_bcast:15", 0x143: " row_bcast:31"}[i]
		}
	}
	return names
}

// Cache policy values are LLVM's semantic CPol flags, rather than a dense
// hardware field. In particular pre-GFX12 SCC occupies bit four.
func cachePolicyName(value int, r *record) string {
	if strings.Contains(r.DecoderNamespace, "GFX12") {
		if value & ^0x83f != 0 {
			return ""
		}
		th, scope := value&7, (value>>3)&3
		atomic := strings.Contains(r.AsmString, "atomic")
		store := strings.Contains(r.AsmString, "store")
		if atomic && r.IsAtomicRet != 0 {
			th |= 1
		}
		var parts []string
		if value&0x800 != 0 {
			parts = append(parts, "scale_offset")
		}
		if th != 0 {
			if atomic {
				name := ""
				if th&4 != 0 {
					if scope < 2 {
						return ""
					}
					if th&2 != 0 {
						name = "CASCADE_NT"
					} else {
						name = "CASCADE_RT"
					}
				} else if th&2 != 0 {
					name = "NT"
					if th&1 != 0 {
						name += "_RETURN"
					}
				} else {
					name = "RETURN"
				}
				parts = append(parts, "th:TH_ATOMIC_"+name)
			} else {
				if th == 7 && !store {
					return ""
				}
				names := []string{"RT", "NT", "HT", "LU", "NT_RT", "RT_NT", "NT_HT", "NT_WB"}
				if th == 3 {
					if scope == 3 {
						names[3] = "BYPASS"
					} else if store {
						names[3] = "WB"
					}
				}
				prefix := "th:TH_LOAD_"
				if store {
					prefix = "th:TH_STORE_"
				}
				parts = append(parts, prefix+names[th])
			}
		}
		if scope != 0 {
			parts = append(parts, "scope:"+[]string{"SCOPE_CU", "SCOPE_SE", "SCOPE_DEV", "SCOPE_SYS"}[scope])
		}
		if value&32 != 0 {
			parts = append(parts, "nv")
		}
		return " " + strings.Join(parts, " ")
	}
	if value & ^23 != 0 {
		return ""
	}
	gfx940 := false
	for _, f := range r.Predicates {
		if strings.Contains(strings.ToLower(f.Def), "gfx940") {
			gfx940 = true
		}
	}
	labels := map[int]string{1: "glc", 2: "slc", 4: "dlc", 16: "scc"}
	if gfx940 {
		labels[2], labels[16] = "nt", "sc1"
		if !strings.HasPrefix(r.AsmString, "s_") {
			labels[1] = "sc0"
		}
	}
	var parts []string
	for _, bit := range []int{1, 2, 4, 16} {
		if value&bit != 0 {
			parts = append(parts, labels[bit])
		}
	}
	return " " + strings.Join(parts, " ")
}
