package sparc

import (
	"encoding/json"
	"fmt"
	"strings"
)

func aliasRecord(alias, target record, get func(string) record) (record, error) {
	syntax := str(alias["AsmString"])
	mnemonic := strings.Fields(syntax)
	if len(mnemonic) == 0 {
		return nil, fmt.Errorf("malformed source alias mnemonic")
	}

	// Clone through JSON so bindings never modify another instruction's DAG/bits.
	b, _ := json.Marshal(target)
	var clone record
	_ = json.Unmarshal(b, &clone)
	var sourceArgs [][]any
	for _, key := range []string{"OutOperandList", "InOperandList"} {
		sourceArgs = append(sourceArgs, args(target[key])...)
	}
	actual := args(alias["ResultInst"])
	if len(sourceArgs) != len(actual) {
		// InstAlias omits tied input operands in conditional moves.
		equal := map[string]string{}
		for _, m := range tied.FindAllStringSubmatch(str(target["Constraints"]), -1) {
			equal[m[1]] = m[2]
			equal[m[2]] = m[1]
		}
		expanded := [][]any{}
		byName := map[string][]any{}
		next := 0
		for _, a := range sourceArgs {
			name := str(a[1])
			if previous, ok := byName[equal[name]]; ok {
				expanded = append(expanded, previous)
				byName[name] = previous
				continue
			}
			if next >= len(actual) {
				return nil, fmt.Errorf("alias result arity requires custom reconstruction")
			}
			expanded = append(expanded, actual[next])
			byName[name] = actual[next]
			next++
		}
		if next != len(actual) {
			return nil, fmt.Errorf("alias result arity requires custom reconstruction")
		}
		actual = expanded
	}
	var flatSource, flatActual [][]any
	for i, a := range sourceArgs {
		if d, ok := a[0].(map[string]any); ok && str(d["kind"]) == "dag" {
			op := def(d["operator"])
			if op != "MEMri" && op != "MEMrr" {
				return nil, fmt.Errorf("unsupported alias composite %s", op)
			}
			actualName := str(actual[i][1])
			if actualName == "" {
				return nil, fmt.Errorf("alias constant composite memory operand")
			}
			var holes []string
			for j, sub := range args(d) {
				cl := "IntRegs"
				if j == 1 && op == "MEMri" {
					cl = "simm13Op"
				}
				name := actualName + "_" + str(sub[1])
				flatSource = append(flatSource, []any{ref(cl), sub[1]})
				flatActual = append(flatActual, []any{ref(cl), name})
				holes = append(holes, "$"+name)
			}
			syntax = replaceHole(syntax, actualName, strings.Join(holes, " + "))
		} else {
			flatSource = append(flatSource, a)
			flatActual = append(flatActual, actual[i])
		}
	}
	sourceArgs = flatSource
	actual = flatActual
	type binding struct {
		name    string
		fixed   int
		isFixed bool
	}
	bindings := map[string]binding{}
	var dagArgs []any
	seen := map[string]bool{}
	for i, a := range sourceArgs {
		src := str(a[1])
		value := actual[i][0]
		name := str(actual[i][1])
		bind := binding{name: name}
		if name == "" {
			bind.isFixed = true
			if v, ok := value.(float64); ok {
				bind.fixed = int(v)
			} else if r := get(def(value)); r["HWEncoding"] != nil {
				bits, _ := r["HWEncoding"].([]any)
				for i, v := range bits {
					bind.fixed |= num(v) << i
				}
			} else {
				return nil, fmt.Errorf("alias requires a non-constant operand transform")
			}
		} else if !seen[name] {
			cl := a[0]
			if get(def(value))["MemberList"] != nil {
				cl = value
			}
			dagArgs = append(dagArgs, []any{cl, name})
			seen[name] = true
		}
		bindings[src] = bind
	}
	inst, _ := clone["Inst"].([]any)
	for i, v := range inst {
		bit, ok := v.(map[string]any)
		if !ok {
			continue
		}
		bind, ok := bindings[str(bit["var"])]
		if !ok {
			return nil, fmt.Errorf("alias cannot bind encoding variable %s", str(bit["var"]))
		}
		if bind.isFixed {
			inst[i] = (bind.fixed >> num(bit["index"])) & 1
		} else {
			bit["var"] = bind.name
		}
	}
	clone["AsmString"] = syntax
	clone["OutOperandList"] = map[string]any{"args": []any{}}
	clone["InOperandList"] = map[string]any{"args": dagArgs}
	ps, _ := clone["Predicates"].([]any)
	aps, _ := alias["Predicates"].([]any)
	clone["Predicates"] = append(ps, aps...)
	clone["Constraints"] = ""
	return clone, nil
}
