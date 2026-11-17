package amdgpu

import (
	"fmt"
	"math/bits"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// imageDomains follows LLVM's validateMIMGDataSize/AddrSize rules. Register
// tuple sizes are properties of the concrete TableGen record; dynamic masks,
// packing and dimensions must select exactly that many words.
func (p *importer) imageDomains(base codec.Encoding, r *record) ([]codec.Encoding, error) {
	if !strings.HasPrefix(base.ID, "IMAGE_") {
		return []codec.Encoding{base}, nil
	}
	info := p.rec(r.BaseOpcode.Def).imageInfo
	views := []codec.Encoding{base}
	if operandIndex(base, "d16") >= 0 {
		views = nil
		for mode := 0; mode < 3; mode++ {
			e := base
			e.Operands = append([]codec.Operand(nil), base.Operands...)
			e.Features = append([]string(nil), base.Features...)
			o := &e.Operands[operandIndex(e, "d16")]
			o.Names = append([]string(nil), o.Names...)
			if mode == 0 {
				if len(o.Names) > 1 {
					o.Names[1] = ""
				}
			} else {
				o.Names[0] = ""
				e.Features = append(e.Features, "AMDGPU_D16Images")
				if mode == 1 {
					e.ID += "/d16-packed"
					e.Features = append(e.Features, "HasPackedD16VMem")
				} else {
					e.ID += "/d16-unpacked"
					e.Features = append(e.Features, "HasUnpackedD16VMem")
				}
			}
			views = append(views, e)
		}
	}
	var out []codec.Encoding
	for _, view := range views {
		g16s := []bool{true}
		if info.Gradients != 0 && info.G16 == 0 && operandIndex(view, "a16") >= 0 {
			g16s = []bool{true, false}
		}
		for _, g16 := range g16s {
			e := view
			e.Features = append([]string(nil), view.Features...)
			if len(g16s) > 1 {
				if g16 {
					e.Features = append(e.Features, "HasG16")
				} else {
					e.ID += "/no-g16"
					e.Features = append(e.Features, "AMDGPU_NoG16")
				}
			}
			if p.imageDataDomain(&e, r) != nil {
				continue
			}
			if p.imageAddressDomain(&e, r, info, g16) != nil {
				continue
			}
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("source image register tuple has no legal dmask/d16/tfe or dim/a16 combination")
	}
	return out, nil
}

func operandIndex(e codec.Encoding, name string) int {
	for i, o := range e.Operands {
		if o.Name == name {
			return i
		}
	}
	return -1
}
func (p *importer) registerWords(o codec.Operand) int {
	c := p.rec(o.Class)
	if c.RegClass.Def != "" {
		c = p.rec(c.RegClass.Def)
	}
	width := c.Size
	if width == 0 {
		if m := wordWidth.FindStringSubmatch(o.Class); m != nil {
			_, _ = fmt.Sscanf(m[1], "%d", &width)
		}
	}
	if width == 0 {
		width = 32
	}
	return (width + 31) / 32
}
func operandAllows(e codec.Encoding, name string, value int64) bool {
	i := operandIndex(e, name)
	if i < 0 {
		return value == 0
	}
	o := e.Operands[i]
	if o.Implicit {
		return value == 0
	}
	if len(o.Names) > 0 {
		return value >= 0 && value < int64(len(o.Names)) && o.Names[value] != ""
	}
	return true
}
func domainColumns(e codec.Encoding, names ...string) []string {
	var out []string
	for _, n := range names {
		if operandIndex(e, n) >= 0 {
			out = append(out, n)
		}
	}
	return out
}
func domainRow(columns []string, values map[string]int64) []int64 {
	row := make([]int64, len(columns))
	for i, n := range columns {
		row[i] = values[n]
	}
	return row
}

func (p *importer) imageDataDomain(e *codec.Encoding, r *record) error {
	data := operandIndex(*e, "vdata")
	if data < 0 || operandIndex(*e, "dmask") < 0 {
		return nil
	}
	words := p.registerWords(e.Operands[data])
	cols := domainColumns(*e, "dmask", "d16", "tfe")
	c := codec.Constraint{Kind: "tuple_in", Operands: cols}
	atomic := strings.Contains(r.AsmString, "atomic")
	gather := r.Gather4 != 0 || strings.Contains(r.AsmString, "gather4")
	packed := strings.Contains(e.ID, "/d16-packed")
	for dmask := 0; dmask < 16; dmask++ {
		if !operandAllows(*e, "dmask", int64(dmask)) {
			continue
		}
		if atomic && dmask != 1 && dmask != 3 && dmask != 15 {
			continue
		}
		if gather && bits.OnesCount(uint(dmask)) != 1 {
			continue
		}
		for d16 := 0; d16 < 2; d16++ {
			if !operandAllows(*e, "d16", int64(d16)) {
				continue
			}
			for tfe := 0; tfe < 2; tfe++ {
				if !operandAllows(*e, "tfe", int64(tfe)) {
					continue
				}
				count := bits.OnesCount(uint(dmask))
				if count == 0 {
					count = 1
				}
				if gather {
					count = 4
				}
				if d16 != 0 && packed {
					count = (count + 1) / 2
				}
				if count+tfe != words {
					continue
				}
				c.Allowed = append(c.Allowed, domainRow(cols, map[string]int64{"dmask": int64(dmask), "d16": int64(d16), "tfe": int64(tfe)}))
			}
		}
	}
	if len(c.Allowed) == 0 {
		return fmt.Errorf("empty image data domain")
	}
	e.Constraints = append(append([]codec.Constraint(nil), e.Constraints...), c)
	return nil
}

func (p *importer) imageAddressDomain(e *codec.Encoding, r *record, info imageInfo, g16 bool) error {
	if info.BVH != 0 {
		if i := operandIndex(*e, "a16"); i >= 0 {
			e.Constraints = append(e.Constraints, codec.Constraint{Kind: "tuple_in", Operands: []string{"a16"}, Allowed: [][]int64{{int64(info.A16)}}})
		}
		if info.A16 != 0 && operandIndex(*e, "a16") < 0 {
			e.Syntax += " a16"
		}
		return nil
	}
	if operandIndex(*e, "dim") < 0 {
		return nil
	}
	words := 0
	nsa := 0
	for _, o := range e.Operands {
		if strings.HasPrefix(o.Name, "vaddr") {
			words += p.registerWords(o)
			nsa++
		}
	}
	cols := domainColumns(*e, "dim", "a16")
	c := codec.Constraint{Kind: "tuple_in", Operands: cols}
	coords := []int{1, 2, 3, 3, 2, 3, 3, 4}
	gradients := []int{2, 4, 6, 4, 2, 4, 4, 4}
	for dim := 0; dim < 8; dim++ {
		if info.MSAA != 0 && dim < 6 {
			continue
		}
		for a16 := 0; a16 < 2; a16++ {
			if !operandAllows(*e, "a16", int64(a16)) {
				continue
			}
			size := int(info.NumExtraArgs)
			components := info.Coordinates*coords[dim] + info.LodOrClampOrMip
			if a16 != 0 {
				size += (components + 1) / 2
			} else {
				size += components
			}
			if info.Gradients != 0 {
				g := gradients[dim]
				if info.G16 != 0 || a16 != 0 && !g16 {
					g = ((g / 2) + 1) &^ 1
				}
				size += g
			}
			if nsa == 1 && size > 12 {
				size = 16
			}
			if size != words && !(nsa == 1 && words == 8 && size >= 5 && size <= 7) {
				continue
			}
			c.Allowed = append(c.Allowed, domainRow(cols, map[string]int64{"dim": int64(dim), "a16": int64(a16)}))
		}
	}
	if len(c.Allowed) == 0 {
		return fmt.Errorf("empty image address domain")
	}
	e.Constraints = append(e.Constraints, c)
	return nil
}

func (p *importer) operandDomains(e *codec.Encoding, r *record) {
	if strings.Contains(e.ID, "_agpr_") {
		e.Features = append(e.Features, "AMDGPU_AGPRMemory")
	}
	dp64 := false
	if operandIndex(*e, "dpp_ctrl") >= 0 {
		for _, src := range e.Operands {
			if p.registerWords(src) == 2 {
				for _, name := range src.Names {
					if strings.Contains(name, "v[") {
						dp64 = true
						break
					}
				}
			}
		}
	}
	for i := range e.Operands {
		o := &e.Operands[i]
		restrict := func(allowed func(int) bool) {
			o.Names = append([]string(nil), o.Names...)
			for k := range o.Names {
				if !allowed(k) {
					o.Names[k] = ""
				}
			}
		}
		if o.Name == "dst_sel" && (e.ID == "V_MAC_F16_sdwa_vi" || e.ID == "V_MAC_F32_sdwa_vi") {
			restrict(func(k int) bool { return k == 6 })
		}
		if o.Name == "sdst" && strings.HasPrefix(r.AsmString, "s_waitcnt_") && strings.Contains(r.DecoderNamespace, "GFX11") {
			restrict(func(k int) bool { return o.Names[k] == "null" })
		}
		if e.ID == "V_DOT2_F32_BF16_vi" && o.Name == "op_sel_hi" {
			restrict(func(k int) bool { return k == (1<<o.Width())-1 })
			o.Names[len(o.Names)-1] = " "
		}
		dp32 := strings.Contains(e.ID, "gfx1250") && (strings.HasPrefix(e.ID, "V_MUL_LO_U32") || strings.HasPrefix(e.ID, "V_MUL_HI_U32") || strings.HasPrefix(e.ID, "V_MUL_HI_I32") || strings.HasPrefix(e.ID, "V_MAD_U32"))
		if o.Name == "dpp_ctrl" && (dp32 || dp64) {
			e.Features = append(e.Features, "AMDGPU_DPALUDPP")
			restrict(func(k int) bool { return k >= 0x150 && k <= 0x15f })
			if !strings.Contains(r.DecoderNamespace, "GFX12") {
				for k, n := range o.Names {
					o.Names[k] = strings.ReplaceAll(n, "row_share", "row_newbcast")
				}
			}
		}
		if strings.Contains(e.ID, "F8F6F4") && (o.Name == "cbsz" || o.Name == "blgp" || o.Name == "matrix_a_fmt" || o.Name == "matrix_b_fmt") {
			src := "src0"
			if o.Name == "blgp" || o.Name == "matrix_b_fmt" {
				src = "src1"
			}
			if j := operandIndex(*e, src); j >= 0 {
				words := p.registerWords(e.Operands[j])
				restrict(func(k int) bool {
					if k > 4 {
						return false
					}
					var expected int
					if strings.HasPrefix(e.ID, "V_WMMA") {
						expected = []int{16, 16, 12, 12, 8}[k]
					} else {
						expected = []int{8, 8, 6, 6, 4}[k]
					}
					return words == expected
				})
			}
		}
	}
}
func sourceGFX940(r *record) bool {
	if strings.Contains(r.DecoderNamespace, "GFX940") {
		return true
	}
	for _, f := range r.Predicates {
		if strings.Contains(strings.ToLower(f.Def), "gfx940") && !strings.Contains(strings.ToLower(f.Def), "notgfx940") {
			return true
		}
	}
	return false
}

func (p *importer) vopdDomains(e *codec.Encoding, r *record) {
	if !strings.HasPrefix(e.ID, "V_DUAL_") {
		return
	}
	wide := strings.Contains(e.ID, "e96_")
	skip := strings.Contains(e.ID, "V_DUAL_MOV_B32_e32_X_MOV_B32_e32_") && !strings.Contains(e.ID, "gfx11")
	var sources [2][3]string
	parts := strings.Split(r.AsmString, " :: ")
	if len(parts) != 2 {
		return
	}
	for side, part := range parts {
		n := 0
		for _, m := range placeholder.FindAllStringSubmatch(part, -1) {
			name := m[1]
			if name == "" {
				name = m[2]
			}
			name = strings.TrimSuffix(name, "_modifiers")
			if strings.HasPrefix(name, "vdst") {
				continue
			}
			if strings.HasPrefix(name, "src") || strings.HasPrefix(name, "vsrc") || strings.HasPrefix(name, "imm") {
				if n < 3 {
					sources[side][n] = name
					n++
				}
			}
		}
		acc := r.HasSrc2AccX
		if side == 1 {
			acc = r.HasSrc2AccY
		}
		if n < 3 && acc != 0 {
			sources[side][2] = []string{"vdstX", "vdstY"}[side]
		}
	}
	gate := func(o codec.Operand) int64 {
		for k, n := range o.Names {
			if len(n) > 1 && n[0] == 'v' && (n[1] == '[' || n[1] >= '0' && n[1] <= '9') {
				if k&256 != 0 {
					return 256
				}
				return 0
			}
		}
		return -1
	}
	for index := 0; index < 3; index++ {
		if skip {
			break
		}
		x, y := operandIndex(*e, sources[0][index]), operandIndex(*e, sources[1][index])
		if x < 0 || y < 0 {
			continue
		}
		ox, oy := e.Operands[x], e.Operands[y]
		gx, gy := gate(ox), gate(oy)
		if gx < 0 || gy < 0 {
			continue
		}
		mask := int64(3)
		if index == 2 && !wide {
			mask = 1
		}
		wx, wy := p.registerWords(ox), p.registerWords(oy)
		equal := int64(0)
		if strings.Contains(e.ID, "gfx1250") && wx == wy {
			equal = 255
		}
		e.Constraints = append(e.Constraints, codec.Constraint{Kind: "masked_ne", Left: ox.Name, Right: oy.Name, Limit: mask, LeftWhenMask: gx, RightWhenMask: gy, EqualMask: equal, LeftSpan: wx, RightSpan: wy})
	}
	x, y := operandIndex(*e, "vdstX"), operandIndex(*e, "vdstY")
	if x >= 0 && y >= 0 && wide {
		e.Constraints = append(e.Constraints, codec.Constraint{Kind: "masked_ne", Left: "vdstX", Right: "vdstY", Limit: 255, LeftSpan: p.registerWords(e.Operands[x]), RightSpan: p.registerWords(e.Operands[y])})
	}
}
