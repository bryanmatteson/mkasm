package tricore

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/bits"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func eval(e ast.Expr, values map[string]int64) (int64, error) {
	switch e := e.(type) {
	case *ast.BasicLit:
		v, err := strconv.ParseInt(e.Value, 0, 64)
		return v, err
	case *ast.Ident:
		v, ok := values[e.Name]
		if !ok {
			return 0, fmt.Errorf("unknown expression field %s", e.Name)
		}
		return v, nil
	case *ast.ParenExpr:
		return eval(e.X, values)
	case *ast.UnaryExpr:
		v, err := eval(e.X, values)
		if err != nil {
			return 0, err
		}
		switch e.Op {
		case token.SUB:
			return -v, nil
		case token.ADD:
			return v, nil
		case token.XOR:
			return ^v, nil
		}
	case *ast.BinaryExpr:
		a, err := eval(e.X, values)
		if err != nil {
			return 0, err
		}
		b, err := eval(e.Y, values)
		if err != nil {
			return 0, err
		}
		switch e.Op {
		case token.ADD:
			return a + b, nil
		case token.SUB:
			return a - b, nil
		case token.MUL:
			return a * b, nil
		case token.OR:
			return a | b, nil
		case token.AND:
			return a & b, nil
		case token.XOR:
			return a ^ b, nil
		case token.SHL:
			return a << uint(b), nil
		case token.SHR:
			return a >> uint(b), nil
		}
	}
	return 0, fmt.Errorf("unsupported source expression %T", e)
}
func expressionOperand(d *description, c constructor, name string) (codec.Operand, error) {
	expr := ""
	if c.action != "" {
		s := c.action
		p := strings.Index(s, "=")
		q := strings.Index(s, ";")
		if p < 0 || q < p {
			return codec.Operand{}, fmt.Errorf("invalid source action %s", s)
		}
		expr = strings.TrimSpace(s[p+1 : q])
	}
	if expr == "" {
		for _, s := range identifier.FindAllString(c.display, -1) {
			if _, ok := d.fields[s]; ok {
				expr = s
				break
			}
		}
	}
	if expr == "" {
		return codec.Operand{}, fmt.Errorf("operand %s has no scalar expression", name)
	}
	tree, err := parser.ParseExpr(expr)
	if err != nil {
		return codec.Operand{}, err
	}
	values := map[string]int64{"inst_start": 0}
	var fields []string
	seen := map[string]bool{}
	for _, s := range identifier.FindAllString(expr, -1) {
		if _, ok := d.fields[s]; ok && !seen[s] {
			fields = append(fields, s)
			values[s] = 0
			seen[s] = true
		}
	}
	baseline, err := eval(tree, values)
	if err != nil {
		return codec.Operand{}, err
	}
	o := codec.Operand{Name: name, Class: c.table, Kind: "immediate", Scale: 1, Bias: baseline}
	if strings.Contains(expr, "inst_start") {
		o.Relative = true
		o.Kind = "displacement"
		o.PCWrapBits = 32
		o.Bias = int64(int32(baseline))
	} else if strings.HasPrefix(name, "off") {
		o.Kind = "displacement"
	}
	if name == "off18" || name == "off24abs" {
		o.Kind = "address"
	}
	type mapping struct{ physical, logical int }
	var mappingBits []mapping
	lowest := 64
	for _, name := range fields {
		f := d.fields[name]
		for k := 0; k < f.width; k++ {
			n := int64(1) << k
			if f.signed && k == f.width-1 {
				n = -n
			}
			values[name] = n
			v, e := eval(tree, values)
			values[name] = 0
			if e != nil {
				return o, e
			}
			delta := v - baseline
			if delta == 0 {
				return o, fmt.Errorf("expression discards field %s bit%d", name, k)
			}
			if delta < 0 {
				o.Signed = true
				delta = -delta
			}
			if delta&(delta-1) != 0 {
				return o, fmt.Errorf("nonlinear source expression %s", expr)
			}
			p := bits.TrailingZeros64(uint64(delta))
			if p < lowest {
				lowest = p
			}
			mappingBits = append(mappingBits, mapping{f.start + k, p})
		}
	}
	if lowest == 64 {
		return o, fmt.Errorf("constant source expression %s", expr)
	}
	// Relative and ordinary constants expose the architectural scale. Absolute
	// address encodings retain sparse value-bit positions and reject gap bits.
	if o.Kind != "address" {
		o.Scale = int64(1) << lowest
		for i := range mappingBits {
			mappingBits[i].logical -= lowest
		}
	}
	for _, m := range mappingBits {
		o.Bits = append(o.Bits, codec.BitSlice{InstructionBit: m.physical, ValueBit: m.logical, Width: 1})
	}
	return o, nil
}
