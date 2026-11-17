package cil

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

//go:embed testdata/opcode.def
var defaultSource string
var defaultOnce sync.Once
var defaultCatalog *Catalog

func Default() *Catalog {
	defaultOnce.Do(func() {
		var err error
		defaultCatalog, err = Parse(strings.NewReader(defaultSource), "cil")
		if err != nil {
			panic(err)
		}
	})
	return defaultCatalog
}

var opdef = regexp.MustCompile(`^OPDEF\(\s*(\w+),\s*"([^"]+)",\s*([^,]+),\s*([^,]+),\s*(\w+),\s*(\w+),\s*(\d+),\s*(\w+),\s*(\w+),\s*(\w+)\s*\)`)
var opalias = regexp.MustCompile(`^OPALIAS\(\s*(\w+),\s*"([^"]+)",\s*(\w+)\s*\)`)

func Parse(r io.Reader, architecture string) (*Catalog, error) {
	if architecture != "cil" && architecture != "dotnet-cil" {
		return nil, fmt.Errorf("unsupported CIL architecture %q", architecture)
	}
	c := &Catalog{Schema: Schema, Architecture: "cil", Source: "dotnet/runtime src/coreclr/inc/opcode.def", Aliases: map[string]uint16{}}
	ids := map[string]uint16{}
	codes := map[uint16]bool{}
	names := map[string]bool{}
	type alias struct{ name, id string }
	var aliases []alias
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	line := 0
	for scanner.Scan() {
		line++
		s := strings.TrimSpace(scanner.Text())
		if m := opalias.FindStringSubmatch(s); m != nil {
			aliases = append(aliases, alias{strings.ToLower(m[2]), m[3]})
			continue
		}
		m := opdef.FindStringSubmatch(s)
		if m == nil {
			if strings.HasPrefix(s, "OPDEF(") || strings.HasPrefix(s, "OPALIAS(") {
				return nil, fmt.Errorf("CIL source line %d: invalid definition", line)
			}
			continue
		}
		size, _ := strconv.Atoi(m[7])
		if m[2] == "unused" || m[6] == "IInternal" || size == 0 {
			continue
		}
		if size != 1 && size != 2 {
			return nil, fmt.Errorf("CIL source line %d: opcode size %d", line, size)
		}
		first, e := strconv.ParseUint(m[8], 0, 8)
		if e != nil {
			return nil, e
		}
		second, e := strconv.ParseUint(m[9], 0, 8)
		if e != nil {
			return nil, e
		}
		op := uint16(second)
		if size == 2 {
			if first != 0xfe {
				return nil, fmt.Errorf("CIL unsupported opcode map")
			}
			op |= 0xfe00
		} else if first != 0xff {
			return nil, fmt.Errorf("CIL invalid single-byte opcode marker")
		}
		kind, ok := operandKind(m[5])
		if !ok {
			return nil, fmt.Errorf("CIL unknown operand class %s", m[5])
		}
		if codes[op] || names[m[2]] {
			return nil, fmt.Errorf("CIL duplicate source opcode %s", m[1])
		}
		codes[op] = true
		names[m[2]] = true
		ids[m[1]] = op
		c.Definitions = append(c.Definitions, Definition{ID: m[1], Opcode: op, Mnemonic: m[2], Size: size, Operand: m[5], OperandKind: kind, Pop: strings.TrimSpace(m[3]), Push: strings.TrimSpace(m[4]), PopCount: stackCount(m[3]), PushCount: stackCount(m[4]), Kind: m[6], Flow: m[10], Prefix: m[6] == "IPrefix"})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(c.Definitions) == 0 {
		return nil, fmt.Errorf("CIL source contains no real opcode definitions")
	}
	for _, a := range aliases {
		op, ok := ids[a.id]
		if !ok {
			return nil, fmt.Errorf("CIL alias %s refers to unknown opcode %s", a.name, a.id)
		}
		if !names[a.name] {
			c.Aliases[a.name] = op
		}
	}
	return c, nil
}
func stackCount(s string) int {
	s = strings.TrimSpace(s)
	if s == "Pop0" || s == "Push0" {
		return 0
	}
	if s == "VarPop" || s == "VarPush" {
		return -1
	}
	return len(strings.Split(s, "+"))
}
func operandKind(s string) (string, bool) {
	switch s {
	case "InlineNone":
		return "none", true
	case "ShortInlineI", "InlineI", "InlineI8":
		return "integer", true
	case "InlineVar", "ShortInlineVar":
		return "variable", true
	case "InlineMethod", "InlineField", "InlineType", "InlineSig", "InlineString", "InlineTok":
		return "token", true
	case "ShortInlineR":
		return "float32", true
	case "InlineR":
		return "float64", true
	case "InlineBrTarget", "ShortInlineBrTarget":
		return "branch", true
	case "InlineSwitch":
		return "switch", true
	}
	return "", false
}
