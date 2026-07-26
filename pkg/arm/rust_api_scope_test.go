package arm_test

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"mkasm/pkg/arm"
	"mkasm/pkg/ir"
)

// TestOperandCoverage measures how much of the ISA can be given a typed
// assembler signature. A scoping instrument, not a correctness test.
func TestOperandCoverage(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	all := reg.GetAll()
	iformDir := iformDirPath(t)

	byClass := map[arm.OperandClass]int{}
	unboundLink := map[string]int{}
	unsupportedSym := map[string]int{}
	tier := map[string]int{}
	var typedEnc, rawEnc int

	for _, instr := range all {
		p, err := arm.ParseIFormFile(filepath.Join(iformDir, instr.IFormFile), instr.EncodingID)
		if err != nil || p == nil {
			continue
		}
		typed := true
		hasVec, hasSve := false, false
		for _, o := range p.AsmOperands {
			c := arm.ClassifyOperand(o)
			byClass[c.Class]++
			switch c.Class {
			case arm.ClassArrangement:
				continue
			case arm.ClassUnsupported:
				typed = false
				unsupportedSym[o.Symbol]++
				continue
			case arm.ClassSimdVec:
				hasVec = true
			case arm.ClassSveZ, arm.ClassSveP:
				hasSve = true
				typed = false
			}
			if c.ResolvedField == "" {
				typed = false
				unboundLink[o.Link]++
			}
		}
		if typed {
			typedEnc++
			if hasVec {
				tier["typed_simd_vector"]++
			} else {
				tier["typed_scalar"]++
			}
		} else {
			rawEnc++
			if hasSve {
				tier["raw_sve_sme"]++
			} else {
				tier["raw_other"]++
			}
		}
	}

	fmt.Printf("\nencodings: %d\n", len(all))
	fmt.Printf("  fully typeable : %d (%.1f%%)\n", typedEnc, pct(typedEnc, len(all)))
	fmt.Printf("  raw fallback   : %d (%.1f%%)\n", rawEnc, pct(rawEnc, len(all)))
	fmt.Println("\ntiers:")
	for _, k := range sortedStrKeys(tier) {
		fmt.Printf("   %-20s %d\n", k, tier[k])
	}
	fmt.Println("\noperand classes:")
	type kv struct {
		k arm.OperandClass
		v int
	}
	var cs []kv
	for k, v := range byClass {
		cs = append(cs, kv{k, v})
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].v > cs[j].v })
	for _, c := range cs {
		fmt.Printf("   %-14s %d\n", c.k, c.v)
	}
	fmt.Println("\ntop unbound operand links (typed class, no field):")
	printTopN(unboundLink, 12)
	fmt.Println("\ntop unsupported symbols:")
	printTopN(unsupportedSym, 14)
}

// TestTraitOverloadFeasibility checks the Rust design that lets one method name
// take several operand shapes: `add(X0,X1,8)` and `add(W0,W1,8)`. Each typed
// encoding becomes one trait impl keyed by its parameter tuple, so two
// encodings of the same mnemonic sharing a tuple would be conflicting impls —
// a Rust compile error. This counts those collisions.
func TestTraitOverloadFeasibility(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	iformDir := iformDirPath(t)

	type form struct {
		id    string
		tuple string
	}
	byMnemonic := map[string][]form{}
	typedTotal := 0

	for _, instr := range reg.GetAll() {
		p, err := arm.ParseIFormFile(filepath.Join(iformDir, instr.IFormFile), instr.EncodingID)
		if err != nil || p == nil {
			continue
		}
		params, ok := arm.TypedParams(p.AsmOperands)
		if !ok {
			continue
		}
		typedTotal++
		var ts []string
		for _, prm := range params {
			ts = append(ts, prm.RustType)
		}
		m := arm.MethodName(arm.AsmMnemonic(p.AsmTemplate))
		if m == "" {
			continue
		}
		byMnemonic[m] = append(byMnemonic[m], form{instr.EncodingID, fmt.Sprint(ts)})
	}

	collisions := 0
	distinctImpls := 0
	var examples []string
	implCount := map[int]int{}
	for m, fs := range byMnemonic {
		seen := map[string][]string{}
		for _, f := range fs {
			seen[f.tuple] = append(seen[f.tuple], f.id)
		}
		distinctImpls += len(seen)
		implCount[len(seen)]++
		for tuple, ids := range seen {
			if len(ids) > 1 {
				collisions++
				if len(examples) < 10 {
					examples = append(examples, fmt.Sprintf("%s%s <- %v", m, tuple, ids))
				}
			}
		}
	}

	fmt.Printf("\ntyped encodings          : %d\n", typedTotal)
	fmt.Printf("typed mnemonics          : %d\n", len(byMnemonic))
	fmt.Printf("distinct param tuples    : %d  (one Rust trait impl each)\n", distinctImpls)
	fmt.Printf("colliding tuples         : %d  (would be conflicting impls)\n", collisions)
	fmt.Println("impls per mnemonic:")
	for _, k := range sortedIntKeys(implCount) {
		fmt.Printf("   %2d impl(s): %d mnemonics\n", k, implCount[k])
	}
	if len(examples) > 0 {
		fmt.Println("collision examples:")
		for _, e := range examples {
			fmt.Println("   " + e)
		}
	}
}

// TestArrangementDispatch checks the remaining collisions can be resolved at
// runtime. Two encodings of one mnemonic with identical parameter types (the
// fp16 and general SIMD forms) are distinguished only by the vector
// arrangement, so one generated method can match on the arrangement and pick
// the encoding — provided their arrangement sets do not overlap.
func TestArrangementDispatch(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	iformDir := iformDirPath(t)

	type entry struct {
		id    string
		arr   []string
		multi bool
	}
	groups := map[string][]entry{}

	for _, instr := range reg.GetAll() {
		p, err := arm.ParseIFormFile(filepath.Join(iformDir, instr.IFormFile), instr.EncodingID)
		if err != nil || p == nil {
			continue
		}
		params, ok := arm.TypedParams(p.AsmOperands)
		if !ok {
			continue
		}
		m := arm.MethodName(arm.AsmMnemonic(p.AsmTemplate))
		if m == "" {
			continue
		}
		var ts []string
		for _, prm := range params {
			ts = append(ts, prm.RustType)
		}
		exps := arm.ExplanationsFor(p.Explanations, instr.EncodingID)
		var arr []string
		for _, sym := range []string{"<T>", "<Ta>", "<Tb>", "<V>"} {
			if e, ok := exps[sym]; ok {
				for _, v := range e.Values {
					if !v.Reserved() {
						arr = append(arr, v.Symbol)
					}
				}
			}
		}
		key := m + fmt.Sprint(ts)
		groups[key] = append(groups[key], entry{instr.EncodingID, arr, len(exps["<T>"].Fields) > 1})
	}

	var colliding, resolvable, unresolvable int
	var bad []string
	for key, es := range groups {
		if len(es) < 2 {
			continue
		}
		colliding++
		seen := map[string]string{}
		overlap := false
		noArr := false
		for _, e := range es {
			if len(e.arr) == 0 {
				noArr = true
			}
			for _, a := range e.arr {
				if prev, dup := seen[a]; dup && prev != e.id {
					overlap = true
				}
				seen[a] = e.id
			}
		}
		if overlap || noArr {
			unresolvable++
			if len(bad) < 12 {
				ids := make([]string, 0, len(es))
				for _, e := range es {
					ids = append(ids, fmt.Sprintf("%s%v", e.id, e.arr))
				}
				bad = append(bad, key+" -> "+strings.Join(ids, " | "))
			}
		} else {
			resolvable++
		}
	}
	fmt.Printf("\ncolliding (method, param-tuple) groups : %d\n", colliding)
	fmt.Printf("  resolvable by arrangement dispatch    : %d\n", resolvable)
	fmt.Printf("  NOT resolvable                        : %d\n", unresolvable)
	for _, b := range bad {
		fmt.Println("   " + b)
	}
}

// TestAritySpread sizes the one real Rust limitation: a method cannot be
// overloaded on parameter count. Mnemonics whose forms all have the same arity
// can share one flat-parameter method; the rest need a suffixed variant.
func TestAritySpread(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	iformDir := iformDirPath(t)
	arities := map[string]map[int]bool{}
	for _, instr := range reg.GetAll() {
		p, err := arm.ParseIFormFile(filepath.Join(iformDir, instr.IFormFile), instr.EncodingID)
		if err != nil || p == nil {
			continue
		}
		params, ok := arm.TypedParams(p.AsmOperands)
		if !ok {
			continue
		}
		m := arm.MethodName(arm.AsmMnemonic(p.AsmTemplate))
		if m == "" {
			continue
		}
		if arities[m] == nil {
			arities[m] = map[int]bool{}
		}
		arities[m][len(params)] = true
	}
	spread := map[int]int{}
	var multi []string
	for m, as := range arities {
		spread[len(as)]++
		if len(as) > 1 && len(multi) < 15 {
			ks := sortedIntKeys(toCount(as))
			multi = append(multi, fmt.Sprintf("%s%v", m, ks))
		}
	}
	fmt.Printf("\ntyped mnemonics: %d\n", len(arities))
	for _, k := range sortedIntKeys(spread) {
		fmt.Printf("   %d distinct arity/arities: %d mnemonics\n", k, spread[k])
	}
	fmt.Println("examples spanning arities:", strings.Join(multi, " "))
}

func toCount(m map[int]bool) map[int]int {
	out := map[int]int{}
	for k := range m {
		out[k] = 1
	}
	return out
}

func sortedIntKeys(m map[int]int) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

func sortedStrKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func printTopN(m map[string]int, n int) {
	type kv struct {
		k string
		v int
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].v > s[j].v })
	for i, e := range s {
		if i >= n {
			break
		}
		fmt.Printf("   %-26s %d\n", e.k, e.v)
	}
}

// TestBuildAsmSurface reports the shape of the generated assembler API.
func TestBuildAsmSurface(t *testing.T) {
	reg := loadResolvedRegistry(t, 0)
	iformDir := iformDirPath(t)
	s := arm.BuildAsmSurface(reg.GetAll(), func(i *ir.InstructionIR) *arm.ParsedIForm {
		p, err := arm.ParseIFormFile(filepath.Join(iformDir, i.IFormFile), i.EncodingID)
		if err != nil {
			return nil
		}
		return p
	})
	forms := 0
	for _, m := range s.MethodOrder {
		forms += len(s.Methods[m])
	}
	fmt.Printf("\ntyped methods      : %d\n", len(s.MethodOrder))
	fmt.Printf("typed forms (impls): %d\n", forms)
	fmt.Printf("raw encodings      : %d\n", len(s.Raw))
	fmt.Printf("dropped            : %d\n", len(s.Dropped))

	reasons := map[string]int{}
	for _, r := range s.Raw {
		reasons[r.Reason]++
	}
	fmt.Println("raw reasons:")
	for _, k := range sortedStrKeys(reasons) {
		fmt.Printf("   %-46s %d\n", k, reasons[k])
	}
	fmt.Println("\nsample signatures:")
	for _, m := range []string{"bl", "ret", "add", "mov", "ldr", "b", "movz", "nop", "cmp", "str"} {
		for _, f := range s.Methods[m] {
			var ps []string
			for i, p := range f.Params {
				tag := ""
				if i >= f.RequiredArity {
					tag = "?"
				}
				ps = append(ps, p.Name+tag+": "+p.RustType)
			}
			var modes []string
			for _, v := range f.ModeVariants {
				modes = append(modes, string(v.Mode))
			}
			fmt.Printf("   fn %s(%s)  req=%d modes=%v\n", f.Method, strings.Join(ps, ", "), f.RequiredArity, modes)
		}
	}
}
