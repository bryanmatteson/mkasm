package arc

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// npsOperand resolves the nonlinear and constrained operands from GNU's NPS400
// insertion/extraction definitions. Ordinary contiguous fields use gnuOperand.
func npsOperand(name, definition, source string) (codec.Operand, string, bool, error) {
	o := codec.Operand{Class: name, Kind: "immediate"}
	f := fields(definition)
	if len(f) < 6 {
		return o, "", false, nil
	}
	fn := f[4]
	if strings.Contains(f[3], "ARC_OPERAND_COLON") {
		return o, ":", true, nil
	}
	if strings.Contains(f[3], "ARC_OPERAND_ADDRTYPE") {
		return o, strings.TrimPrefix(fn, "insert_nps_"), true, nil
	}
	if !strings.HasPrefix(name, "NPS_") {
		return o, "", false, nil
	}
	add := func(p, v, n int) { o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: p, ValueBit: v, Width: n}) }
	domain := func(values []int64) {
		o.Lookup = values
		o.Names = make([]string, len(values))
		for i, v := range values {
			o.Names[i] = strconv.FormatInt(v, 10)
		}
	}
	limited := func(width, shift int, allowed func(int) bool) {
		add(shift, 0, width)
		o.Names = make([]string, 1<<uint(width))
		for i := range o.Names {
			if allowed(i) {
				o.Names[i] = strconv.Itoa(i)
			}
		}
	}
	if m := regexp.MustCompile(`^insert_nps_3bit_reg_at_(\d+)_(?:dst|src2)$`).FindStringSubmatch(fn); m != nil {
		add(int(integer(m[1])), 0, 3)
		domain([]int64{0, 1, 2, 3, 12, 13, 14, 15})
		o.Kind = "register"
		for i, v := range o.Lookup {
			o.Names[i] = fmt.Sprintf("r%d", v)
		}
		return o, "", true, nil
	}
	// These macros are retained verbatim in both upstream source layouts.
	for _, macro := range []string{"MAKE_BIAS_INSERT_EXTRACT_FUNCS", "MAKE_1BASED_INSERT_EXTRACT_FUNCS", "MAKE_SRC_POS_INSERT_EXTRACT_FUNCS"} {
		re := regexp.MustCompile(`\b` + macro + `\s*\(([^)]+)\)`)
		for _, m := range re.FindAllStringSubmatch(source, -1) {
			a := fields(m[1])
			if len(a) == 0 {
				continue
			}
			suffix := ""
			if macro == "MAKE_SRC_POS_INSERT_EXTRACT_FUNCS" {
				suffix = "_pos"
			}
			if fn != "insert_nps_"+a[0]+suffix {
				continue
			}
			switch macro {
			case "MAKE_SRC_POS_INSERT_EXTRACT_FUNCS":
				if len(a) != 2 {
					continue
				}
				add(int(integer(a[1])), 0, 2)
				o.Scale = 8
			case "MAKE_BIAS_INSERT_EXTRACT_FUNCS":
				if len(a) != 6 {
					continue
				}
				width, shift, bias := int(integer(a[3])), int(integer(a[5])), integer(a[4])
				add(shift, 0, width)
				o.Bias = bias
				o.Names = make([]string, 1<<uint(width))
				for i := range o.Names {
					v := int64(i) + bias
					if v >= integer(a[1]) && v <= integer(a[2]) {
						o.Names[i] = strconv.FormatInt(v, 10)
					}
				}
			case "MAKE_1BASED_INSERT_EXTRACT_FUNCS":
				if len(a) != 4 {
					continue
				}
				width, upper := int(integer(a[3])), integer(a[2])
				add(int(integer(a[1])), 0, width)
				v := make([]int64, 1<<uint(width))
				for i := range v {
					v[i] = int64(i)
				}
				v[0] = upper
				domain(v)
			}
			return o, "", true, nil
		}
	}
	switch fn {
	case "insert_nps_bitop_size_2b":
		add(10, 0, 2)
		domain([]int64{1, 2, 4, 8})
	case "insert_nps_bitop_uimm8":
		add(0, 0, 5)
		add(12, 5, 3)
	case "insert_nps_rflt_uimm6":
		limited(6, 6, func(v int) bool { return v == 1 || v == 2 || v == 4 })
	case "insert_nps_dst_pos_and_size":
		add(0, 0, 5) // complemented copy is installed by gnuEncoding
	case "insert_nps_cmem_uimm16":
		add(0, 0, 16)
		o.Bias = 0x57f00000
	case "insert_nps_imm_offset":
		limited(3, 10, func(v int) bool { return v <= 4 })
		o.Scale = 16
		for i := range o.Names {
			if o.Names[i] != "" {
				o.Names[i] = strconv.Itoa(i * 16)
			}
		}
	case "insert_nps_imm_entry":
		add(2, 0, 2)
		domain([]int64{16, 32, 64, 128})
	case "insert_nps_size_16bit":
		add(6, 0, 6)
		v := make([]int64, 64)
		for i := range v {
			v[i] = int64(i)
		}
		v[0] = 64
		domain(v)
	case "insert_nps_calc_entry_size":
		add(8, 0, 4)
		o.Lookup = make([]int64, 16)
		o.Names = make([]string, 16)
		for i := range o.Lookup {
			o.Lookup[i] = 1 << uint(i)
			if i <= 8 {
				o.Names[i] = strconv.FormatInt(o.Lookup[i], 10)
			}
		}
	case "insert_nps_bitop_mod4":
		add(47, 0, 1)
		add(31, 1, 1)
	case "insert_nps_bitop_dst_pos3_pos4":
		add(42, 0, 5)
		add(37, 0, 5)
	case "insert_nps_bitop_ins_ext":
		limited(5, 20, func(v int) bool { return v <= 28 })
	case "insert_nps_min_hofs":
		add(6, 0, 4)
		o.Scale = 16
	case "insert_nps_rbdouble_64":
		add(43, 0, 5)
		add(48, 0, 5)
		o.Kind = "register"
		register(&o)
	case "insert_nps_misc_imm_offset":
		add(8, 0, 5)
		o.Scale = 4
	case "0", "NULL":
		if name == "NPS_QCMP_M3" {
			limited(4, 5, func(v int) bool { return v < 15 })
		} else {
			return o, "", false, nil
		}
	default:
		return o, "", true, fmt.Errorf("unmodeled NPS insertion function %s", fn)
	}
	return o, "", true, nil
}
