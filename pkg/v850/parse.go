// Package v850 imports the complete GNU V850 opcode and operand definitions.
package v850

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

//go:embed testdata/v850.h
var header string

//go:embed testdata/tc-v850.c
var assemblerSource string

//go:embed list.rs
var rustList string

//go:embed testdata/COPYING3
var upstreamLicense string

type Catalog struct{ *codec.Catalog }

func (c *Catalog) WriteJSON(w io.Writer) error { return json.NewEncoder(w).Encode(c.Catalog) }
func (c *Catalog) GenerateRust(output string) error {
	if err := c.Catalog.GenerateRust(output); err != nil {
		return err
	}
	lib := filepath.Join(output, "src/lib.rs")
	raw, err := os.ReadFile(lib)
	if err != nil {
		return err
	}
	source := string(raw)
	signature := "pub fn assemble_with_features(text:&str,address:u64,active:Option<&[&str]>)->Result<Vec<Vec<u8>>,Error>{"
	if !strings.Contains(source, signature) {
		return fmt.Errorf("V850 generated runtime assembly hook changed")
	}
	source = strings.Replace(source, signature, signature+"\nlet normalized=v850_list_text(text)?;let text=normalized.as_str();", 1)
	signature = "pub fn parse_with_features(text:&str,address:u64,active:Option<&[&str]>)->Result<Self,Error>{"
	if !strings.Contains(source, signature) {
		return fmt.Errorf("V850 generated runtime template hook changed")
	}
	source = strings.Replace(source, signature, signature+"\nlet normalized=v850_list_text(text)?;let text=normalized.as_str();", 1)
	if err := os.WriteFile(lib, []byte("// GNU binutils 2.44 opcode metadata, Copyright (C) 1996-2025 Free Software Foundation, Inc.\n// Metadata license: GPL-3.0-or-later; see UPSTREAM-LICENSE.\n"+source+rustList), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "UPSTREAM-LICENSE"), []byte("Opcode and operand metadata: GNU binutils 2.44, GPL-3.0-or-later.\n\n"+upstreamLicense), 0644); err != nil {
		return err
	}
	manifest := filepath.Join(output, "Cargo.toml")
	data, err := os.ReadFile(manifest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(manifest, []byte(strings.Replace(string(data), `license = "MIT"`, `license = "GPL-3.0-or-later"`, 1)), 0644); err != nil {
		return err
	}
	readme := filepath.Join(output, "README.md")
	data, err = os.ReadFile(readme)
	if err != nil {
		return err
	}
	if err := os.WriteFile(readme, append(data, []byte("\nV850 opcode metadata is derived from GNU binutils 2.44 and is GPL-3.0-or-later; see UPSTREAM-LICENSE. The generated runtime implementation retains its MIT notice in LICENSE. The combined generated crate is distributed under GPL-3.0-or-later. Profiles: v850, v850e, v850e1, v850e2, v850e2v3, v850e3v5, each optionally suffixed +extension. Unfiltered decoding admits their union. Register-list values are compact twelve-bit masks for r20 through r31. Branch displacements are signed byte offsets from the current instruction, with 32-bit target wrapping.\n")...), 0644); err != nil {
		return err
	}
	return nil
}

type operandSpec struct {
	Name            string
	Bits            int
	Shift           uint64
	Insert, Extract string
	Flags           uint64
}

const (
	reg        = 1
	ep         = 2
	srg        = 4
	list       = 8
	cc         = 16
	floatcc    = 32
	vreg       = 64
	imm16      = 128
	imm16hi    = 256
	imm23      = 512
	imm32      = 1024
	signedFlag = 4096
	disp       = 8192
	pcrel      = 16384
	even       = 32768
	notr0      = 0x20000
	notimm0    = 0x40000
	notsa      = 0x80000
	bang       = 0x100000
	percent    = 0x200000
	cacheop    = 0x400000
	prefop     = 0x800000
)

var macros = map[string]int64{"PROCESSOR_V850": 1, "PROCESSOR_V850E": 2, "PROCESSOR_V850E1": 4, "PROCESSOR_V850E2": 8, "PROCESSOR_V850E2V3": 16, "PROCESSOR_V850E3V5": 32, "PROCESSOR_V850E3V5_UP": 32, "PROCESSOR_V850E2V3_UP": 48, "PROCESSOR_V850E2_UP": 56, "PROCESSOR_V850E_UP": 62, "PROCESSOR_ALL": 63, "PROCESSOR_NOT_V850": 62, "PROCESSOR_OPTION_EXTENSION": 64, "PROCESSOR_OPTION_ALIAS": 128, "OP_MASK": 0x7e0, "BOP_MASK": 0x78f, "BOP7_MASK": 0x1ffef}

func init() { // Operand flags are imported from the matching upstream public header.
	for _, m := range regexp.MustCompile(`(?m)^#define\s+(V850[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+)`).FindAllStringSubmatch(header, -1) {
		v, _ := strconv.ParseInt(m[2], 0, 64)
		macros[m[1]] = v
	}
}
func eval(s string) (int64, error) {
	node, e := parser.ParseExpr(strings.ReplaceAll(strings.TrimSpace(s), "~", "^"))
	if e != nil {
		return 0, e
	}
	var walk func(ast.Expr) (int64, error)
	walk = func(n ast.Expr) (int64, error) {
		switch x := n.(type) {
		case *ast.ParenExpr:
			return walk(x.X)
		case *ast.BasicLit:
			return strconv.ParseInt(x.Value, 0, 64)
		case *ast.Ident:
			if n, ok := macros[x.Name]; ok {
				return n, nil
			}
			return 0, fmt.Errorf("unknown source constant %s", x.Name)
		case *ast.UnaryExpr:
			v, e := walk(x.X)
			if e != nil {
				return 0, e
			}
			switch x.Op {
			case token.XOR:
				return ^v, nil
			case token.SUB:
				return -v, nil
			}
		case *ast.BinaryExpr:
			a, e := walk(x.X)
			if e != nil {
				return 0, e
			}
			b, e := walk(x.Y)
			if e != nil {
				return 0, e
			}
			switch x.Op {
			case token.OR:
				return a | b, nil
			case token.AND:
				return a & b, nil
			case token.ADD:
				return a + b, nil
			case token.SUB:
				return a - b, nil
			case token.SHL:
				return a << uint(b), nil
			}
		case *ast.CallExpr:
			id, ok := x.Fun.(*ast.Ident)
			if !ok {
				return 0, fmt.Errorf("invalid source macro")
			}
			var a []int64
			for _, arg := range x.Args {
				v, e := walk(arg)
				if e != nil {
					return 0, e
				}
				a = append(a, v)
			}
			switch id.Name {
			case "OP":
				return (a[0] & 63) << 5, nil
			case "BOP":
				return 0x580 | a[0]&15, nil
			case "BOP7":
				return 0x107e0 | a[0]&15, nil
			case "one":
				return int64(uint32(a[0])), nil
			case "two":
				return int64(uint32(a[0]) | uint32(a[1])<<16), nil
			}
		}
		return 0, fmt.Errorf("unsupported source expression %s", s)
	}
	return walk(node)
}
func split(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, c := range s {
		switch c {
		case '(', '{':
			depth++
		case ')', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	out = append(out, strings.TrimSpace(s[start:]))
	return out
}

var comments = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`)

func Parse(r io.Reader, architecture string) (*Catalog, error) {
	switch architecture {
	case "v850", "v850e", "v850e1", "v850e2", "v850e2v3", "v850e3v5":
	default:
		return nil, fmt.Errorf("unsupported V850 architecture %q", architecture)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	source := comments.ReplaceAllString(string(raw), "")
	operandStart := strings.Index(source, "const struct v850_operand v850_operands[]")
	opcodeStart := strings.Index(source, "const struct v850_opcode v850_opcodes[]")
	if operandStart < 0 || opcodeStart < operandStart {
		return nil, fmt.Errorf("V850 input must be complete GNU v850-opc.c")
	}

	specs := map[string]operandSpec{}
	ore := regexp.MustCompile(`(?m)#define\s+([A-Z0-9_]+)[^\n]*\n\s*\{([^}]+)\}`)
	for _, m := range ore.FindAllStringSubmatch(source[operandStart:opcodeStart], -1) {
		p := split(m[2])
		if len(p) != 6 {
			return nil, fmt.Errorf("invalid operand definition %s", m[1])
		}
		bits, e := eval(p[0])
		if e != nil {
			return nil, e
		}
		shift, e := eval(p[1])
		if e != nil {
			return nil, e
		}
		flags, e := eval(p[4])
		if e != nil {
			return nil, e
		}
		specs[m[1]] = operandSpec{m[1], int(bits), uint64(shift), p[2], p[3], uint64(flags)}
	}
	if len(specs) != 86 {
		return nil, fmt.Errorf("incomplete V850 operands: %d", len(specs))
	}
	tail := source[opcodeStart:]
	first := strings.Index(tail, "{")
	tail = tail[first+1:]
	var rows []string
	depth, start := 0, 0
	for i, c := range tail {
		if c == '{' {
			if depth == 0 {
				start = i + 1
			}
			depth++
		}
		if c == '}' {
			depth--
			if depth == 0 {
				rows = append(rows, tail[start:i])
			}
			if depth < 0 {
				break
			}
		}
	}
	cat := &codec.Catalog{Schema: codec.Schema, Architecture: "v850", Source: "GNU binutils 2.44 opcodes/v850-opc.c", SourceLicense: "GNU binutils 2.44 opcode and operand metadata, Copyright (C) 1996-2025 Free Software Foundation, Inc.; GPL-3.0-or-later.\n\n" + upstreamLicense, FeatureSets: map[string][]string{}}
	forms := map[string]string{"IF1": "R1,R2", "IF2": "I5,R2", "IF3": "D9_RELAX", "IF6": "I16,R1,R2", "IF6U": "I16U,R1,R2", "IF7": "D17_16"}
	for _, row := range rows {
		p := split(row)
		if len(p) == 6 && p[0] == "0" {
			continue
		}
		if len(p) != 6 {
			return nil, fmt.Errorf("invalid V850 row %q", row)
		}
		name, e := strconv.Unquote(p[0])
		if e != nil {
			return nil, e
		}
		op, e := eval(p[1])
		if e != nil {
			return nil, e
		}
		mask, e := eval(p[2])
		if e != nil {
			return nil, e
		}
		cpu, e := eval(p[5])
		if e != nil {
			return nil, e
		}
		mem, e := eval(p[4])
		if e != nil {
			return nil, e
		}
		args := p[3]
		if v, ok := forms[args]; ok {
			args = v
		}
		args = strings.Trim(args, "{} ")
		var params []operandSpec
		for _, id := range strings.Split(args, ",") {
			id = strings.TrimSpace(id)
			if id == "0" || id == "UNUSED" {
				continue
			}
			s, ok := specs[id]
			if !ok {
				return nil, fmt.Errorf("unknown V850 operand %s", id)
			}
			params = append(params, s)
		}
		enc, e := importForm(len(cat.Encodings), name, uint32(op), uint32(mask), int(cpu), int(mem), params)
		if e != nil {
			return nil, fmt.Errorf("%s: %w", name, e)
		}
		cat.Encodings = append(cat.Encodings, enc)
	}
	if len(cat.Encodings) != 403 {
		return nil, fmt.Errorf("incomplete GNU V850 corpus: %d forms", len(cat.Encodings))
	}
	cpus := []string{"v850", "v850e", "v850e1", "v850e2", "v850e2v3", "v850e3v5"}
	for i, name := range cpus {
		for _, ext := range []bool{false, true} {
			profile := name
			if ext {
				profile += "+extension"
			}
			seen := map[string]bool{}
			for _, enc := range cat.Encodings {
				for _, f := range enc.Features {
					if strings.HasPrefix(f, "cpu_") {
						mask, _ := strconv.Atoi(strings.TrimPrefix(f, "cpu_"))
						if mask&(1<<uint(i)) != 0 && !seen[f] {
							cat.FeatureSets[profile] = append(cat.FeatureSets[profile], f)
							seen[f] = true
						}
					}
				}
			}
			if ext {
				cat.FeatureSets[profile] = append(cat.FeatureSets[profile], "extension")
			}
		}
	}
	if err := cat.Validate(); err != nil {
		return nil, err
	}
	return &Catalog{cat}, nil
}
