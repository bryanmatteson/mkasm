package wasm

// Legal operands for generated corpus smoke tests.
func representativeValue(kind string) Value {
	switch kind {
	case "u32":
		return U(3)
	case "ordering", "lane":
		return U(1)
	case "zero":
		return U(0)
	case "s32":
		return S(-123456)
	case "s64":
		return S(-9876543210)
	case "f32":
		return U(0x7fc01234)
	case "f64":
		return U(0x7ff8000012345678)
	case "memarg":
		return L(U(2), U(624485), U(2))
	case "heaptype":
		return T("func")
	case "block":
		return T("empty")
	case "valtype":
		return T("i32")
	case "reftype":
		return L(T("refnull"), T("func"))
	case "br_table":
		return L(U(0), U(300), U(4))
	case "valtypes":
		return L(T("i32"), L(T("refnull"), T("func")))
	case "try_table":
		return L(T("empty"), L(L(U(0), U(1), U(2)), L(U(1), U(1), U(3)), L(U(2), U(4)), L(U(3), U(5))))
	case "resume_table":
		return L(L(U(0), U(1), U(2)), L(U(1), U(3)))
	case "cast":
		return L(U(3), U(5), T("any"), T("struct"))
	case "v128", "shuffle":
		v := L()
		for i := 0; i < 16; i++ {
			v.Items = append(v.Items, U(uint64(i)))
		}
		return v
	}
	panic(kind)
}
func representativeValues(o Opcode) []Value {
	var result []Value
	for _, f := range o.Fields {
		result = append(result, representativeValue(f.Kind))
	}
	return result
}
