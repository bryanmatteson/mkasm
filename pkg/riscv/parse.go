// Package riscv imports the upstream riscv/riscv-opcodes source repository.
package riscv

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

type field struct{ hi, lo int }
type definition struct {
	file, name string
	args       []string
	ref        string
	line       int
}

// Parse imports a tar or gzip-compressed tar of a riscv-opcodes checkout. The
// archive must contain arg_lut.csv and extensions/rv*; a top-level folder is fine.
// Both ratified and unratified definitions are retained with their source feature.
func Parse(r io.Reader, architecture string) (*codec.Catalog, error) {
	b := bufio.NewReader(r)
	if magic, _ := b.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		g, e := gzip.NewReader(b)
		if e != nil {
			return nil, e
		}
		defer g.Close()
		return parseTar(g, architecture)
	}
	return parseTar(b, architecture)
}
func parseTar(r io.Reader, architecture string) (*codec.Catalog, error) {
	files := map[string][]byte{}
	tr := tar.NewReader(r)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("riscv archive: %w", e)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		n := strings.TrimPrefix(path.Clean(h.Name), "./")
		if n == "arg_lut.csv" || strings.HasSuffix(n, "/arg_lut.csv") || n == "csrs.csv" || strings.HasSuffix(n, "/csrs.csv") || n == "csrs32.csv" || strings.HasSuffix(n, "/csrs32.csv") {
			n = path.Base(n)
		} else if i := strings.Index(n, "extensions/"); i >= 0 {
			n = n[i:]
		} else {
			continue
		}
		if h.Size > 16<<20 {
			return nil, fmt.Errorf("riscv archive: oversized file %s", n)
		}
		data, e := io.ReadAll(io.LimitReader(tr, 16<<20))
		if e != nil {
			return nil, e
		}
		files[n] = data
	}
	return parseFiles(files, architecture)
}

// ParseDirectory imports an unpacked upstream checkout without modifying it.
func ParseDirectory(directory, architecture string) (*codec.Catalog, error) {
	files := map[string][]byte{}
	e := filepath.WalkDir(directory, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		n, e := filepath.Rel(directory, p)
		if e != nil {
			return e
		}
		n = filepath.ToSlash(n)
		if n != "arg_lut.csv" && n != "csrs.csv" && n != "csrs32.csv" && !strings.HasPrefix(n, "extensions/") {
			return nil
		}
		data, e := os.ReadFile(p)
		if e == nil {
			files[n] = data
		}
		return e
	})
	if e != nil {
		return nil, e
	}
	return parseFiles(files, architecture)
}
func parseFiles(files map[string][]byte, architecture string) (*codec.Catalog, error) {
	switch architecture {
	case "riscv32", "rv32":
		architecture = "riscv32"
	case "riscv64", "rv64":
		architecture = "riscv64"
	default:
		return nil, fmt.Errorf("riscv: expected riscv32 or riscv64, got %q", architecture)
	}
	data, ok := files["arg_lut.csv"]
	if !ok {
		return nil, fmt.Errorf("riscv: archive missing arg_lut.csv")
	}
	cr := csv.NewReader(strings.NewReader(string(data)))
	cr.TrimLeadingSpace = true
	rows, e := cr.ReadAll()
	if e != nil {
		return nil, e
	}
	lut := map[string]field{}
	for _, r := range rows {
		if len(r) != 3 {
			return nil, fmt.Errorf("riscv: malformed arg_lut row")
		}
		hi, e1 := strconv.Atoi(strings.TrimSpace(r[1]))
		lo, e2 := strconv.Atoi(strings.TrimSpace(r[2]))
		if e1 != nil || e2 != nil || lo < 0 || hi < lo || hi > 31 {
			return nil, fmt.Errorf("riscv: invalid arg_lut range %v", r)
		}
		lut[r[0]] = field{hi, lo}
	}
	// These upstream constants.py additions have not yet moved to arg_lut.csv.
	for n, f := range map[string]field{"mop_r_t_30": {30, 30}, "mop_r_t_27_26": {27, 26}, "mop_r_t_21_20": {21, 20}, "mop_rr_t_30": {30, 30}, "mop_rr_t_27_26": {27, 26}, "c_mop_t": {10, 8}} {
		lut[n] = f
	}
	var defs []definition
	bases := map[string]definition{}
	var names []string
	for n := range files {
		if strings.HasPrefix(n, "extensions/") && strings.HasPrefix(path.Base(n), "rv") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		for i, line := range strings.Split(string(files[n]), "\n") {
			t := strings.Fields(strings.SplitN(line, "#", 2)[0])
			if len(t) == 0 {
				continue
			}
			d := definition{file: n, line: i + 1}
			switch t[0] {
			case "$import":
				if len(t) != 2 {
					return nil, fmt.Errorf("%s:%d: malformed import", n, i+1)
				}
				d.ref = t[1]
			case "$pseudo_op":
				if len(t) < 3 {
					return nil, fmt.Errorf("%s:%d: malformed pseudo", n, i+1)
				}
				d.ref = t[1]
				d.name = t[2]
				d.args = t[3:]
			default:
				if strings.HasPrefix(t[0], "$") {
					return nil, fmt.Errorf("%s:%d: unknown directive", n, i+1)
				}
				d.name = t[0]
				d.args = t[1:]
				key := path.Base(n) + "::" + d.name
				if _, ok := bases[key]; ok {
					return nil, fmt.Errorf("riscv duplicate base %s", key)
				}
				bases[key] = d
			}
			defs = append(defs, d)
		}
	}
	c := &codec.Catalog{Schema: codec.Schema, Architecture: architecture, Source: "https://github.com/riscv/riscv-opcodes (arg_lut.csv, extensions/*)"}
	seen := map[string]int{}
	for _, d := range defs {
		if !applies(path.Base(d.file), architecture) {
			continue
		}
		if d.ref != "" {
			base, ok := bases[d.ref]
			if !ok {
				return nil, fmt.Errorf("%s:%d: missing base %s", d.file, d.line, d.ref)
			}
			if d.name == "" {
				d.name = base.name
				d.args = base.args
			}
		}
		enc, e := makeEncoding(d, lut)
		if e != nil {
			return nil, fmt.Errorf("%s:%d (%s): %w", d.file, d.line, d.name, e)
		}
		id := strings.TrimPrefix(d.file, "extensions/") + "::" + d.name
		seen[id]++
		if seen[id] > 1 {
			id += fmt.Sprintf("#%d", seen[id])
		}
		enc.ID = id
		if architecture == "riscv32" {
			for i := range enc.Operands {
				if enc.Operands[i].Relative {
					enc.Operands[i].PCWrapBits = 32
				}
			}
		}
		probe := codec.Catalog{Architecture: architecture, Encodings: []codec.Encoding{enc}}
		if err := probe.Validate(); err != nil {
			c.Unsupported = append(c.Unsupported, codec.Unsupported{ID: id, Reason: err.Error()})
			continue
		}
		c.Encodings = append(c.Encodings, enc)
		c.Encodings = append(c.Encodings, assemblyVariants(enc)...)
		c.Encodings = append(c.Encodings, stackVariants(enc, architecture)...)
	}
	addFeatureProfiles(c)
	if err := addCSRAliases(c, files); err != nil {
		return nil, err
	}
	if e := c.Validate(); e != nil {
		return nil, e
	}
	return c, nil
}
func applies(file, arch string) bool {
	return !(strings.HasPrefix(file, "rv32_") && arch == "riscv64" || strings.HasPrefix(file, "rv64_") && arch == "riscv32" || strings.HasPrefix(file, "rv128_"))
}

func makeEncoding(d definition, lut map[string]field) (codec.Encoding, error) {
	e := codec.Encoding{Mnemonic: d.name, Features: []string{strings.TrimSuffix(path.Base(d.file), path.Ext(path.Base(d.file)))}}
	if strings.Contains(d.file, "/unratified/") {
		e.Features = append(e.Features, "unratified")
	}
	mask, value := uint32(0), uint32(0)
	var variables []string
	ties := map[string]string{}
	for _, arg := range d.args {
		pair := strings.SplitN(arg, "=", 2)
		if len(pair) == 1 {
			variables = append(variables, arg)
			continue
		}
		if f, ok := lut[pair[0]]; ok {
			if target, tied := lut[pair[1]]; tied {
				if target.hi-target.lo != f.hi-f.lo {
					return e, fmt.Errorf("mismatched tie widths %s", arg)
				}
				variables = append(variables, pair[0])
				ties[pair[0]] = pair[1]
				continue
			}
			pair[0] = fmt.Sprintf("%d..%d", f.hi, f.lo)
		}
		r := strings.Split(pair[0], "..")
		hi, err := strconv.Atoi(r[0])
		if err != nil {
			return e, fmt.Errorf("invalid bit assignment %s", arg)
		}
		lo := hi
		if len(r) == 2 {
			lo, err = strconv.Atoi(r[1])
		}
		if err != nil || lo < 0 || hi < lo || hi > 31 {
			return e, fmt.Errorf("invalid bit range %s", arg)
		}
		v, err := strconv.ParseUint(pair[1], 0, 32)
		if err != nil || v > uint64((uint64(1)<<uint(hi-lo+1))-1) {
			return e, fmt.Errorf("invalid bit value %s", arg)
		}
		m := uint32(((uint64(1) << uint(hi-lo+1)) - 1) << uint(lo))
		if mask&m != 0 {
			return e, fmt.Errorf("overlapping bit assignment %s", arg)
		}
		mask |= m
		value |= uint32(v) << uint(lo)
	}
	size := 4
	if mask&3 == 3 && value&3 != 3 {
		size = 2
	}
	if size == 2 && (mask|value)>>16 != 0 {
		return e, fmt.Errorf("compressed encoding has high bits")
	}
	for i := 0; i < size; i++ {
		e.Mask = append(e.Mask, byte(mask>>uint(8*i)))
		e.Value = append(e.Value, byte(value>>uint(8*i)))
	}
	positions := map[string]int{}
	var order []string
	for _, arg := range variables {
		f, ok := lut[arg]
		if !ok {
			return e, fmt.Errorf("unknown operand %s", arg)
		}
		target := arg
		if t, ok := ties[arg]; ok {
			target = t
		}
		name, bits, signed, scale := semantic(target, f)
		if target != arg {
			_, bits, _, _ = semantic(arg, f)
		}
		idx, ok := positions[name]
		if !ok {
			o := codec.Operand{Name: name, Class: target, Kind: "immediate", Signed: signed, Scale: scale}
			configureRegister(&o, target, d.name, value, f.hi-f.lo+1)
			idx = len(e.Operands)
			positions[name] = idx
			e.Operands = append(e.Operands, o)
			if _, tied := ties[arg]; !tied {
				order = append(order, name)
			}
		}
		e.Operands[idx].Bits = append(e.Operands[idx].Bits, bits...)
		if d.name != "c.nop" && (strings.Contains(target, "nzimm") || strings.Contains(target, "nzuimm")) {
			e.Constraints = append(e.Constraints, codec.Constraint{Kind: "ne", Left: name})
		}
	}
	order = preserveUnassignedBits(&e, order)
	configureSpecialOperands(&e)
	e.Syntax = syntax(&e, order, value)
	switch {
	case value&0x7f == 0x63 || d.name == "c.beqz" || d.name == "c.bnez":
		e.FlowControl = "conditional-branch"
	case d.name == "jal" || d.name == "c.jal" || d.name == "c.jalr":
		e.FlowControl = "call"
	case d.name == "jalr" || d.name == "c.j" || d.name == "c.jr":
		e.FlowControl = "branch"
	case d.name == "ret" || strings.HasSuffix(d.name, "ret"):
		e.FlowControl = "return"
	case d.name == "ecall" || strings.Contains(d.name, "ebreak"):
		e.FlowControl = "trap"
	}
	return e, nil
}

// Upstream initializes every instruction bit to '-' (don't care), and its
// match/mask converter leaves unassigned bits outside the mask. Most such bits
// have named operands, but some experimental rows omit those operand names.
// Preserve their physical values explicitly instead of fixing them to zero or
// guessing their architectural meaning. Contiguous fields keep their exact
// instruction-bit ranges in both the public name and class.
func preserveUnassignedBits(e *codec.Encoding, order []string) []string {
	used := append([]byte(nil), e.Mask...)
	for _, o := range e.Operands {
		for _, b := range o.Bits {
			for k := 0; k < b.Width; k++ {
				bit := b.InstructionBit + k
				if bit >= 0 && bit < len(used)*8 {
					used[bit/8] |= 1 << uint(bit%8)
				}
			}
		}
	}
	for hi := len(used)*8 - 1; hi >= 0; hi-- {
		if used[hi/8]&(1<<uint(hi%8)) != 0 {
			continue
		}
		lo := hi
		for lo > 0 && used[(lo-1)/8]&(1<<uint((lo-1)%8)) == 0 {
			lo--
		}
		name := fmt.Sprintf("raw_%d", hi)
		if hi != lo {
			name += fmt.Sprintf("_%d", lo)
		}
		e.Operands = append(e.Operands, codec.Operand{
			Name: name, Class: "RawEncodingBits", Kind: "immediate",
			Bits: []codec.BitSlice{slice(lo, 0, hi-lo+1)},
		})
		order = append(order, name)
		hi = lo
	}
	return order
}

func addCSRAliases(c *codec.Catalog, files map[string][]byte) error {
	aliases := map[string]int64{}
	names := []string{"csrs.csv"}
	if c.Architecture == "riscv32" {
		names = append(names, "csrs32.csv")
	}
	for _, n := range names {
		data, ok := files[n]
		if !ok {
			continue
		}
		r := csv.NewReader(strings.NewReader(string(data)))
		r.TrimLeadingSpace = true
		rows, err := r.ReadAll()
		if err != nil {
			return fmt.Errorf("riscv %s: %w", n, err)
		}
		for _, row := range rows {
			if len(row) != 2 {
				return fmt.Errorf("riscv %s: malformed CSR row", n)
			}
			v, err := strconv.ParseInt(strings.TrimSpace(row[0]), 0, 64)
			if err != nil || v < 0 || v > 4095 {
				return fmt.Errorf("riscv %s: invalid CSR number", n)
			}
			aliases[row[1]] = v
		}
	}
	for i := range c.Encodings {
		for j := range c.Encodings[i].Operands {
			if c.Encodings[i].Operands[j].Name == "csr" {
				c.Encodings[i].Operands[j].RegisterAliases = aliases
			}
		}
	}
	return nil
}
