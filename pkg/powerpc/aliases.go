package powerpc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// LLVM represents assembler aliases as bindings over the original instruction
// DAG. Resolve them before importing bits, including nested condition predicates
// and operands repeated in more than one encoded field (mr, not, and friends).
func expandAliases(raw map[string]json.RawMessage, instances map[string][]string, get func(string) record) []codec.Unsupported {
	var unsupported []codec.Unsupported
	for _, id := range instances["InstAlias"] {
		alias := get(id)
		result := object(alias["ResultInst"])
		target := def(result["operator"])
		base := get(target)
		if base == nil || str(alias["AsmString"]) == "" {
			continue
		}
		pseudo := false
		for _, v := range list(base["!superclasses"]) {
			if str(v) == "PPCEmitTimePseudo" {
				pseudo = true
			}
		}
		if pseudo || num(base["isPseudo"]) != 0 {
			continue
		}
		var m record
		_ = json.Unmarshal(raw[target], &m)
		formals := append(append([]any{}, args(base["OutOperandList"])...), args(base["InOperandList"])...)
		// ResultInst omits compiler-only variable_ops and tied operands which
		// have no independent instruction bits. Match against encoded formals.
		encoded := map[string]bool{}
		for _, bit := range list(base["Inst"]) {
			if name := str(object(bit)["var"]); name != "" {
				encoded[name] = true
			}
		}
		var hasBits func([]any) bool
		hasBits = func(pair []any) bool {
			if len(pair) != 2 {
				return false
			}
			if encoded[str(pair[1])] {
				return true
			}
			for _, child := range args(pair[0]) {
				if hasBits(list(child)) {
					return true
				}
			}
			return false
		}
		var physicalFormals []any
		for _, f := range formals {
			if hasBits(list(f)) {
				physicalFormals = append(physicalFormals, f)
			}
		}
		if len(formals) != len(args(result)) && len(physicalFormals) == len(args(result)) {
			formals = physicalFormals
		}
		actuals := args(result)
		// LLVM's one-operand tlbie alias reverses RB and RS in this record.
		if target == "TLBIEP9" && str(alias["AsmString"]) == "tlbie $RB" && len(actuals) == 5 {
			actuals = append([]any(nil), actuals...)
			actuals[0], actuals[1] = actuals[1], actuals[0]
		}
		bindings := map[string]any{}
		classes := map[string]any{}
		var order []string
		asm := str(alias["AsmString"])
		var bind func([]any, []any) error
		bind = func(formal, actual []any) error {
			if len(formal) != 2 || len(actual) != 2 {
				return fmt.Errorf("malformed alias operand")
			}
			source := object(formal[0])
			name := str(formal[1])
			value := object(actual[0])
			aliasName := str(actual[1])
			if str(source["kind"]) == "dag" {
				children := args(source)
				supplied := args(value)
				if len(supplied) == 0 && aliasName != "" {
					member := args(get(def(source["operator"]))["MIOperandInfo"])
					if len(member) != len(children) {
						return fmt.Errorf("alias composite member mismatch")
					}
					for i := range children {
						supplied = append(supplied, []any{list(member[i])[0], fmt.Sprintf("%s_%d", aliasName, i)})
					}
					replacement := "$" + str(list(supplied[0])[1])
					if len(children) == 2 {
						if def(source["operator"]) == "memrr" {
							replacement += ", $" + str(list(supplied[1])[1])
						} else {
							replacement += "($" + str(list(supplied[1])[1]) + ")"
						}
					}
					asm = strings.ReplaceAll(asm, "$"+aliasName, replacement)
				}
				if len(children) != len(supplied) {
					return fmt.Errorf("alias composite shape mismatch")
				}
				for i := range children {
					if err := bind(list(children[i]), list(supplied[i])); err != nil {
						return err
					}
				}
				return nil
			}
			if aliasName != "" {
				binding := record{"var": aliasName, "kind": "varbit"}
				if (def(source) == "vsrc" || def(source) == "vsfrc" || def(source) == "vssrc") && def(value) == "vrrc" {
					binding["fixed5"] = true
				}
				bindings[name] = binding
				if _, ok := classes[aliasName]; !ok {
					order = append(order, aliasName)
					classes[aliasName] = actual[0]
				}
				return nil
			}
			if n, ok := actual[0].(float64); ok {
				bindings[name] = int64(n)
				return nil
			}
			register := get(def(value))
			if register["HWEncoding"] == nil {
				return fmt.Errorf("alias constant %s is not an encoded register", def(value))
			}
			var n int64
			for bit, b := range list(register["HWEncoding"]) {
				n |= int64(num(b)) << uint(bit)
			}
			bindings[name] = n
			return nil
		}
		err := error(nil)
		if len(formals) != len(actuals) {
			err = fmt.Errorf("alias operand count requires target lowering")
		} else {
			for i := range formals {
				if err = bind(list(formals[i]), list(actuals[i])); err != nil {
					break
				}
			}
		}
		if err != nil {
			unsupported = append(unsupported, codec.Unsupported{ID: "alias_" + id, Reason: err.Error()})
			continue
		}
		inst := list(m["Inst"])
		for bit, v := range inst {
			field := object(v)
			if field == nil {
				continue
			}
			name := str(field["var"])
			binding, ok := bindings[name]
			if !ok {
				err = fmt.Errorf("unbound alias encoding field %s", name)
				break
			}
			if n, ok := binding.(int64); ok {
				inst[bit] = float64((uint64(n) >> uint(num(field["index"]))) & 1)
			} else {
				if object(binding)["fixed5"] == true && num(field["index"]) == 5 {
					inst[bit] = float64(1)
				} else {
					inst[bit] = record{"var": str(object(binding)["var"]), "kind": "varbit", "index": field["index"]}
				}
			}
		}
		if err != nil {
			unsupported = append(unsupported, codec.Unsupported{ID: "alias_" + id, Reason: err.Error()})
			continue
		}
		var operands []any
		for _, name := range order {
			operands = append(operands, []any{classes[name], name})
		}
		m["InOperandList"] = record{"operator": ref("ins"), "args": operands}
		m["OutOperandList"] = record{"operator": ref("outs"), "args": []any{}}
		m["AsmString"] = asm
		if target == "MFTB" {
			m["AsmString"] = "enc[alias_" + id + "] " + asm
		}
		m["isPseudo"] = float64(0)
		m["isAsmParserOnly"] = float64(0)
		m["isCodeGenOnly"] = float64(0)
		m["Predicates"] = append(list(m["Predicates"]), list(alias["Predicates"])...)
		key := "alias_" + id
		raw[key], _ = json.Marshal(m)
		instances["Instruction"] = append(instances["Instruction"], key)
	}
	raw["!instanceof"], _ = json.Marshal(instances)
	return unsupported
}
