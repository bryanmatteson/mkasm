// Package loongarch imports LLVM's LoongArch TableGen JSON instruction records.
// Both LA32 and LA64 use little-endian, fixed-width 32-bit instructions.
package loongarch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type record map[string]json.RawMessage

type dag struct {
	Operator reference           `json:"operator"`
	Args     [][]json.RawMessage `json:"args"`
}

type reference struct {
	Def string `json:"def"`
}

func stringField(r record, key string) string {
	var s string
	_ = json.Unmarshal(r[key], &s)
	return s
}

func operandTypes(r record) (map[string]string, error) {
	result := make(map[string]string)
	for _, key := range []string{"OutOperandList", "InOperandList"} {
		var d dag
		if err := json.Unmarshal(r[key], &d); err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		for _, arg := range d.Args {
			if len(arg) != 2 {
				return nil, fmt.Errorf("%s: invalid operand DAG argument", key)
			}
			var ref reference
			var name string
			if err := json.Unmarshal(arg[0], &ref); err != nil {
				return nil, err
			}
			if err := json.Unmarshal(arg[1], &name); err != nil {
				return nil, err
			}
			if ref.Def == "" || name == "" {
				return nil, fmt.Errorf("%s: unnamed operand", key)
			}
			result[name] = ref.Def
		}
	}
	return result, nil
}

func predicates(r record) []string {
	var refs []reference
	_ = json.Unmarshal(r["Predicates"], &refs)
	var result []string
	for _, ref := range refs {
		result = append(result, ref.Def)
	}
	return result
}

var immediateType = regexp.MustCompile(`^([su])imm([0-9]+)(.*)$`)
var shiftSuffix = regexp.MustCompile(`_lsl([0-9]+)`)

// Parse reads the output of llvm-tblgen --dump-json on LoongArch.td. Target
// predicates are retained as feature requirements; instructions exclusive to
// the other register width are omitted. Pseudo instructions have no encoding
// and are handled separately from their concrete InstAlias counterparts.
func Parse(r io.Reader, architecture string) (*codec.Catalog, error) {
	architecture = strings.ToLower(architecture)
	if architecture != "loongarch32" && architecture != "loongarch64" {
		return nil, fmt.Errorf("loongarch: unsupported architecture %q", architecture)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var raw map[string]record
	// Metadata values are not records, so decode each top-level entry separately.
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("loongarch TableGen JSON: %w", err)
	}
	raw = make(map[string]record)
	for name, entry := range entries {
		if strings.HasPrefix(name, "!") {
			continue
		}
		var rec record
		if err := json.Unmarshal(entry, &rec); err != nil {
			return nil, fmt.Errorf("loongarch record %s: %w", name, err)
		}
		raw[name] = rec
	}
	catalog, err := codec.ParseTableGen(bytes.NewReader(data), codec.TableGenOptions{Architecture: architecture, LittleEndian: true})
	if err != nil {
		return nil, err
	}
	var encodings []codec.Encoding
	for _, enc := range catalog.Encodings {
		rec, ok := raw[enc.ID]
		if !ok {
			return nil, fmt.Errorf("loongarch: missing source record %s", enc.ID)
		}
		wrongWidth := false
		for _, pred := range predicates(rec) {
			if (pred == "IsLA64" && architecture == "loongarch32") || (pred == "IsLA32" && architecture == "loongarch64") {
				wrongWidth = true
			}
		}
		if wrongWidth {
			continue
		}
		if len(enc.Mask) != 4 {
			return nil, fmt.Errorf("loongarch %s: instruction width is not 32 bits", enc.ID)
		}
		if string(rec["isBranch"]) == "1" && string(rec["isBarrier"]) != "1" {
			enc.FlowControl = "conditional_branch"
		}
		if enc.ID == "JIRL" {
			enc.FlowControl = "indirect_branch"
		}
		if enc.ID == "ERTN" {
			enc.FlowControl = "return"
		}
		types, err := operandTypes(rec)
		if err != nil {
			return nil, fmt.Errorf("loongarch %s: %w", enc.ID, err)
		}
		for i := range enc.Operands {
			op := &enc.Operands[i]
			if err := configureOperand(op, types[op.Name]); err != nil {
				return nil, fmt.Errorf("loongarch %s operand %s: %w", enc.ID, op.Name, err)
			}
			if op.Relative && architecture == "loongarch32" {
				op.PCWrapBits = 32
			}
		}
		if strings.HasPrefix(enc.ID, "BSTRINS_") || strings.HasPrefix(enc.ID, "BSTRPICK_") {
			suffix := "w"
			if strings.HasSuffix(enc.ID, "_D") {
				suffix = "d"
			}
			enc.Constraints = append(enc.Constraints, codec.Constraint{Kind: "ge", Left: "msb" + suffix, Right: "lsb" + suffix})
		}
		if string(rec["IsSubjectToAMORdConstraint"]) == "1" {
			for _, other := range []string{"rk", "rj"} {
				enc.Constraints = append(enc.Constraints, codec.Constraint{Kind: "ne", Left: "rd", Right: other, UnlessZero: "rd"})
			}
		}
		encodings = append(encodings, enc)
		// LLVM accepts GAS's optional zero displacement on atomic memory
		// operands. It does not occupy an instruction field.
		for _, op := range enc.Operands {
			if types[op.Name] == "GPRMemAtomic" {
				alias := enc
				alias.ID += ".memzero"
				alias.Syntax = strings.ReplaceAll(alias.Syntax, "{"+op.Name+"}", "{"+op.Name+"}, 0")
				encodings = append(encodings, alias)
			}
		}
	}
	encodings, err = addAliases(encodings, raw)
	if err != nil {
		return nil, err
	}
	result, err := codec.NewCatalog(architecture, "LLVM TableGen LoongArch", encodings)
	if err != nil {
		return nil, err
	}
	result.Unsupported = catalog.Unsupported
	return result, nil
}

func configureOperand(op *codec.Operand, typ string) error {
	registers := map[string]struct {
		prefix string
		count  int
	}{
		"GPR": {"$r", 32}, "GPRMemAtomic": {"$r", 32}, "GPRNoR0R1": {"$r", 32},
		"GPRJR": {"$r", 32}, "GPRT": {"$r", 32}, "FPR32": {"$f", 32}, "FPR64": {"$f", 32},
		"CFR": {"$fcc", 8}, "FCSR": {"$fcsr", 4}, "LSX128": {"$vr", 32}, "LASX256": {"$xr", 32}, "SCR": {"$scr", 4},
	}
	if reg, ok := registers[typ]; ok {
		op.Kind = "register"
		op.RegisterPrefix = reg.prefix
		op.Names = make([]string, reg.count)
		for i := range op.Names {
			op.Names[i] = reg.prefix + strconv.Itoa(i)
		}
		if typ == "GPRNoR0R1" {
			op.Names[0], op.Names[1] = "", ""
		}
		if typ == "GPRJR" {
			op.Names[1] = ""
		}
		if typ == "GPRT" {
			for i := range op.Names {
				if i < 4 || i > 20 {
					op.Names[i] = ""
				}
			}
		}
		op.RegisterAliases = make(map[string]int64)
		if reg.prefix == "$r" {
			aliases := []string{"zero", "ra", "tp", "sp", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8", "", "fp", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8"}
			for i, a := range aliases {
				if a != "" && op.Names[i] != "" {
					op.RegisterAliases["$"+a] = int64(i)
				}
			}
			op.RegisterAliases["$s9"] = 22
		}
		if reg.prefix == "$f" {
			for i := 0; i < 32; i++ {
				a := ""
				switch {
				case i < 8:
					a = "fa" + strconv.Itoa(i)
				case i < 24:
					a = "ft" + strconv.Itoa(i-8)
				default:
					a = "fs" + strconv.Itoa(i-24)
				}
				op.RegisterAliases["$"+a] = int64(i)
			}
		}
		return nil
	}
	m := immediateType.FindStringSubmatch(typ)
	if m == nil {
		return fmt.Errorf("unsupported operand class %q", typ)
	}
	op.Kind = "immediate"
	op.RegisterPrefix, op.Names = "", nil
	op.Signed = m[1] == "s"
	op.Scale = 1
	if shift := shiftSuffix.FindStringSubmatch(m[3]); shift != nil {
		n, _ := strconv.Atoi(shift[1])
		op.Scale = int64(1) << n
	}
	if strings.HasSuffix(typ, "_plus1") {
		op.Bias = 1
	}
	if typ == "simm26_b" || typ == "simm26_symbol" {
		op.Scale = 4
	}
	if typ == "simm16_lsl2_br" || typ == "simm21_lsl2" || typ == "simm26_b" || typ == "simm26_symbol" {
		op.Kind, op.Relative = "address", true
	}
	return nil
}

var syntaxOperand = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)`)

func addAliases(encodings []codec.Encoding, records map[string]record) ([]codec.Encoding, error) {
	byID := make(map[string]codec.Encoding)
	for _, enc := range encodings {
		byID[enc.ID] = enc
	}
	var names []string
	for name, rec := range records {
		var classes []string
		_ = json.Unmarshal(rec["!superclasses"], &classes)
		for _, class := range classes {
			if class == "InstAlias" {
				names = append(names, name)
				break
			}
		}
	}
	sort.Strings(names)
	for _, name := range names {
		rec := records[name]
		var result dag
		if err := json.Unmarshal(rec["ResultInst"], &result); err != nil {
			return nil, fmt.Errorf("loongarch alias %s: %w", name, err)
		}
		base, ok := byID[result.Operator.Def]
		if !ok {
			continue
		} // A pseudo expansion, or an instruction for the other width.
		var order []string
		for _, key := range []string{"OutOperandList", "InOperandList"} {
			var d dag
			_ = json.Unmarshal(records[result.Operator.Def][key], &d)
			for _, arg := range d.Args {
				var n string
				_ = json.Unmarshal(arg[1], &n)
				order = append(order, n)
			}
		}
		if len(order) != len(result.Args) {
			return nil, fmt.Errorf("loongarch alias %s: operand count mismatch", name)
		}
		enc := base
		enc.ID = name
		enc.Mask = append([]byte(nil), base.Mask...)
		enc.Value = append([]byte(nil), base.Value...)
		enc.Operands = nil
		enc.Syntax = syntaxOperand.ReplaceAllString(stringField(rec, "AsmString"), "{$1}")
		enc.Mnemonic = strings.Fields(enc.Syntax)[0]
		if enc.Mnemonic == "ret" {
			enc.FlowControl = "return"
		}
		for i, arg := range result.Args {
			if len(arg) != 2 {
				return nil, fmt.Errorf("loongarch alias %s: invalid operand", name)
			}
			var op codec.Operand
			found := false
			for _, bop := range base.Operands {
				if bop.Name == order[i] {
					op = bop
					found = true
					break
				}
			}
			if !found {
				return nil, fmt.Errorf("loongarch alias %s: missing target operand %s", name, order[i])
			}
			var aliasName string
			_ = json.Unmarshal(arg[1], &aliasName)
			if aliasName != "" {
				op.Name = aliasName
				enc.Operands = append(enc.Operands, op)
				continue
			}
			var n int64
			if err := json.Unmarshal(arg[0], &n); err != nil {
				var ref reference
				_ = json.Unmarshal(arg[0], &ref)
				var bits []int
				if err := json.Unmarshal(records[ref.Def]["HWEncoding"], &bits); err != nil {
					return nil, fmt.Errorf("loongarch alias %s: unsupported constant %s", name, arg[0])
				}
				for bit, v := range bits {
					n |= int64(v) << bit
				}
			}
			for _, b := range op.Bits {
				for bit := 0; bit < b.Width; bit++ {
					p := b.InstructionBit + bit
					enc.Mask[p/8] |= 1 << uint(p%8)
					if n&(1<<uint(b.ValueBit+bit)) != 0 {
						enc.Value[p/8] |= 1 << uint(p%8)
					}
				}
			}
		}
		encodings = append(encodings, enc)
	}
	return encodings, nil
}
