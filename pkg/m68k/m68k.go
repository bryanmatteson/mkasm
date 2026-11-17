// Package m68k imports the complete GNU m68k opcode table and implements
// big-endian instruction/address-extension framing for M68000 and ColdFire.
package m68k

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const Schema = "mkasm.m68k.v1"
const SourceSHA256 = "d9861be507da2ac77b28207227e0c444bdfe660378d54db1491dbc160f760e0d"

type Opcode struct {
	ID           string `json:"id"`
	Mnemonic     string `json:"mnemonic"`
	Size         int    `json:"size"`
	Opcode       uint32 `json:"opcode"`
	Mask         uint32 `json:"mask"`
	Args         string `json:"args"`
	Features     uint32 `json:"features"`
	OriginalArgs string `json:"original_args,omitempty"`
	OriginalMask uint32 `json:"original_mask,omitempty"`
	Correction   string `json:"correction,omitempty"`
}
type Alias struct {
	Alias   string `json:"alias"`
	Primary string `json:"primary"`
}
type Catalog struct {
	Schema       string   `json:"schema"`
	Architecture string   `json:"architecture"`
	CPU          string   `json:"cpu"`
	Source       string   `json:"source"`
	Opcodes      []Opcode `json:"opcodes"`
	Aliases      []Alias  `json:"aliases"`
}

var flags = map[string]uint32{"m68000": 1, "m68010": 2, "m68020": 4, "m68030": 8, "m68040": 16, "m68060": 32, "m68881": 64, "m68851": 128, "cpu32": 256, "fido_a": 512, "mcfmac": 1024, "mcfemac": 2048, "cfloat": 4096, "mcfhwdiv": 8192, "mcfisa_a": 16384, "mcfisa_aa": 32768, "mcfisa_b": 65536, "mcfisa_c": 131072, "mcfusp": 262144, "m68040up": 48, "m68030up": 56, "m68020up": 60, "m68010up": 830, "m68000up": 831, "mfloat": 112, "mmmu": 184}
var Profiles = map[string]uint32{"68000": 1, "68010": 2, "68020": 4, "68030": 8, "68040": 16, "68060": 32, "68020+68881": 4 | 64, "68020+68851": 4 | 128, "68020+68851+68881": 4 | 128 | 64, "68030+68881": 8 | 64, "68881": 64, "68851": 128, "cpu32": 256, "fido": 512, "m68k-all": 1023, "isa-a-nodiv": 16384, "isa-a": 16384 | 8192, "isa-a+": 16384 | 32768 | 8192 | 262144, "isa-b": 16384 | 65536 | 8192 | 262144, "isa-c": 16384 | 131072 | 8192 | 262144, "isa-a+mac": 16384 | 8192 | 1024, "isa-a+emac": 16384 | 8192 | 2048, "cfv4": 16384 | 8192 | 65536 | 1024, "cfv4e": 16384 | 8192 | 65536 | 262144 | 4096 | 2048, "coldfire-all": 0x7fc00}
var recordRE = regexp.MustCompile(`(?s)\{"([^"]+)",\s*(\d+),\s*(one\([^)]*\)|two\([^)]*\)),\s*(one\([^)]*\)|two\([^)]*\)),\s*"([^"]*)",\s*([^}]+)\}`)
var aliasRE = regexp.MustCompile(`\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,?\s*\}`)

func tableNumber(s string) (uint32, error) {
	i := strings.IndexByte(s, '(')
	if i < 0 {
		return 0, errors.New("invalid opcode expression")
	}
	parts := strings.Split(strings.TrimSuffix(s[i+1:], ")"), ",")
	var result uint32
	for j, p := range parts {
		var n uint64
		for _, term := range strings.Split(p, "|") {
			term = strings.TrimSpace(term)
			v, ok := map[string]uint64{"SCOPE_LINE": 8, "SCOPE_PAGE": 16, "SCOPE_ALL": 24}[term]
			if !ok {
				var e error
				v, e = strconv.ParseUint(term, 0, 32)
				if e != nil {
					return 0, e
				}
			}
			n |= v
		}
		if j == 0 {
			result = uint32(n) << 16
		} else {
			result |= uint32(n)
		}
	}
	return result, nil
}
func Parse(r io.Reader, architecture string) (*Catalog, error) {
	if architecture != "m68k" && architecture != "coldfire" {
		return nil, fmt.Errorf("m68k: unsupported architecture %q", architecture)
	}
	b, e := io.ReadAll(r)
	if e != nil {
		return nil, e
	}
	c := &Catalog{Schema: Schema, Architecture: architecture, Source: "GNU binutils 2.44 m68k-opc.c", CPU: "68000"}
	if architecture == "coldfire" {
		c.CPU = "isa-a"
	}
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		if e := json.Unmarshal(b, c); e != nil {
			return nil, e
		}
		c.Architecture = architecture
	} else {
		if fmt.Sprintf("%x", sha256.Sum256(b)) != SourceSHA256 {
			return nil, errors.New("m68k: unrecognized opcode source; raw input must be pristine GNU binutils 2.44 m68k-opc.c (or use resolved mkasm.m68k.v1 JSON)")
		}
		// The only instruction-producing macros in binutils 2.44 are the
		// twelve CPU32 TBL operations, each with two operand forms.
		source := string(b)
		tbl := regexp.MustCompile(`TBL\("([^"]+)",\s*"([^"]+)",\s*"([^"]+)",\s*([01]),\s*([01])\)`)
		source = tbl.ReplaceAllStringFunc(source, func(call string) string {
			m := tbl.FindStringSubmatch(call)
			signed, _ := strconv.Atoi(m[4])
			round, _ := strconv.Atoi(m[5])
			var out strings.Builder
			for size, name := range m[1:4] {
				ext := signed<<11 | (1-round)<<10 | size<<6
				fmt.Fprintf(&out, "{\"%s\",4,two(0xf800,0x%x),two(0xffc0,0x8fff),\"!sD1\",cpu32},\n", name, ext|0x100)
				fmt.Fprintf(&out, "{\"%s\",4,two(0xf800,0x%x),two(0xfff8,0x8ff8),\"DsD3D1\",cpu32},\n", name, ext)
			}
			return out.String()
		})
		matches := recordRE.FindAllStringSubmatch(source, -1)
		if len(matches) == 0 {
			return nil, errors.New("m68k: input must be GNU m68k-opc.c or resolved mkasm.m68k.v1 JSON")
		}
		for i, m := range matches {
			n, e := tableNumber(m[3])
			if e != nil {
				return nil, e
			}
			mask, e := tableNumber(m[4])
			if e != nil {
				return nil, e
			}
			size, _ := strconv.Atoi(m[2])
			features := uint32(0)
			for _, p := range strings.Split(m[6], "|") {
				p = strings.Trim(strings.TrimSpace(p), "()")
				v, ok := flags[p]
				if !ok {
					return nil, fmt.Errorf("m68k: unknown architecture flag %q", p)
				}
				features |= v
			}
			o := Opcode{ID: fmt.Sprintf("%s_%d", m[1], i), Mnemonic: m[1], Size: size, Opcode: n, Mask: mask, Args: m[5], Features: features}
			// These seven upstream disassembler masks contradict their own
			// assembler operand fields. Retain the original and explain the
			// correction rather than dropping the valid assembler form.
			if o.Mnemonic == "fmovem" && o.Args == "Ii*sL8" && o.Mask == 0xf2c0e3ff {
				o.OriginalMask = o.Mask
				o.Mask = 0xf1c0e3ff
				o.Correction = "coprocessor ID overlaps upstream fixed mask (GNU as emits f210 9000 for fmovem (a0),fpcr)"
			}
			if o.Mnemonic == "pflushs" && strings.HasSuffix(o.Args, "&s") && o.Mask>>16 == 0xfff8 {
				o.OriginalMask = o.Mask
				o.Mask = o.Mask&65535 | 0xffc00000
				o.Correction = "upstream mask fixes variable effective-address mode (GNU as emits f010 3c51 for pflushs #1,#2,(a0))"
			}
			if strings.Contains(o.Args, "iI") && o.Mask&0x600 != 0 {
				o.OriginalMask = o.Mask
				o.Mask &^= 0x600
				o.Correction = "upstream disassembler mask fixes MAC shift bits despite explicit variable shift operand"
			}
			if o.Mnemonic == "fmovem" && strings.Contains(o.Args, "*s") {
				o.OriginalArgs = o.Args
				o.Args = strings.Replace(o.Args, "*s", "*l", 1)
				o.Correction += "; FPU control transfer uses 32-bit immediate size rather than upstream unsized address descriptor"
			}
			c.Opcodes = append(c.Opcodes, o)
		}
		for _, m := range aliasRE.FindAllStringSubmatch(string(b), -1) {
			c.Aliases = append(c.Aliases, Alias{m[1], m[2]})
		}
	}
	if e := c.Validate(); e != nil {
		return nil, e
	}
	return c, nil
}
func (c *Catalog) Validate() error {
	if c.Architecture != "m68k" && c.Architecture != "coldfire" {
		return errors.New("m68k: invalid architecture")
	}
	if c.Schema != Schema || len(c.Opcodes) == 0 {
		return errors.New("m68k: empty/invalid opcode table")
	}
	if _, ok := Profiles[c.CPU]; !ok {
		return errors.New("m68k: invalid CPU profile")
	}
	if c.Architecture == "m68k" && Profiles[c.CPU]&1023 == 0 || c.Architecture == "coldfire" && Profiles[c.CPU]&0x7fc00 == 0 {
		return errors.New("m68k: CPU profile belongs to other architecture")
	}
	ids := map[string]bool{}
	for _, o := range c.Opcodes {
		if o.ID == "" || ids[o.ID] || o.Mnemonic == "" || o.Features == 0 || o.Size < 2 || o.Size > 8 || o.Size%2 != 0 {
			return fmt.Errorf("m68k: invalid opcode %q", o.ID)
		}
		ids[o.ID] = true
		args := strings.TrimPrefix(o.Args, ".")
		if len(args)%2 != 0 {
			return fmt.Errorf("%s: odd operand descriptor", o.ID)
		}
		for i := 0; i < len(args); i += 2 {
			places, ok := operandPlaces[args[i]]
			if !ok || !strings.ContainsRune(places, rune(args[i+1])) {
				return fmt.Errorf("%s: unsupported operand descriptor %s", o.ID, args[i:i+2])
			}
		}

	}
	names := map[string]bool{}
	for _, o := range c.Opcodes {
		names[o.Mnemonic] = true
	}
	aliases := map[string]string{}
	for _, a := range c.Aliases {
		if a.Alias == "" || a.Primary == "" || aliases[a.Alias] != "" {
			return errors.New("m68k: empty or duplicate alias")
		}
		aliases[a.Alias] = a.Primary
	}
	for name := range aliases {
		seen := map[string]bool{}
		cur := name
		for {
			if seen[cur] {
				return fmt.Errorf("m68k: alias cycle at %s", cur)
			}
			seen[cur] = true
			p, ok := aliases[cur]
			if !ok {
				if !names[cur] {
					return fmt.Errorf("m68k: alias %s targets unknown instruction %s", name, cur)
				}
				break
			}
			cur = p
		}
	}
	return nil
}
func (c *Catalog) WithCPU(cpu string) (*Catalog, error) {
	if _, ok := Profiles[cpu]; !ok {
		return nil, fmt.Errorf("unknown m68k CPU profile %s", cpu)
	}
	if c.Architecture == "m68k" && Profiles[cpu]&1023 == 0 || c.Architecture == "coldfire" && Profiles[cpu]&0x7fc00 == 0 {
		return nil, errors.New("CPU profile belongs to other architecture")
	}
	copy := *c
	copy.CPU = cpu
	return &copy, nil
}
func (c *Catalog) WriteJSON(w io.Writer) error {
	if e := c.Validate(); e != nil {
		return e
	}
	return json.NewEncoder(w).Encode(c)
}
func pairs(o *Opcode) []string {
	a := strings.TrimPrefix(o.Args, ".")
	var r []string
	for len(a) > 0 {
		r = append(r, a[:2])
		a = a[2:]
	}
	return r
}
func fixedSize(o *Opcode) int {
	n := 2
	for _, a := range pairs(o) {
		k, p := a[0], a[1]
		if k == '#' {
			if p == 'j' {
				n = max(n, 4)
			} else if p == 'B' {
			} else if p == 'l' {
				n = max(n, 6)
			} else if p != 'C' && p != '8' {
				n = max(n, 4)
			}
		}
		if (k == 'L' || k == 'l') && p == 'w' {
			n = max(n, 4)
		}
		if strings.ContainsRune("123789i", rune(p)) {
			n = max(n, 4)
		}
		if strings.ContainsRune("456", rune(p)) {
			n = max(n, 6)
		}
	}
	if o.Mask&65535 != 0 {
		n = max(n, 4)
	}
	if strings.HasPrefix(o.Args, ".") {
		n = max(n, 4)
	}
	if o.Mnemonic == "lpstop" {
		n = max(n, 6)
	}
	if strings.HasPrefix(o.Mnemonic, "ptrap") && len(o.Args) > 0 {
		n = max(n, o.Size)
	}
	return n
}

var ErrTruncated = errors.New("m68k: truncated instruction")
var ErrUnknown = errors.New("m68k: unknown instruction")

func word(b []byte, p int) (uint16, error) {
	if p+2 > len(b) {
		return 0, ErrTruncated
	}
	return binary.BigEndian.Uint16(b[p : p+2]), nil
}
func setWord(b []byte, p int, n uint16) { binary.BigEndian.PutUint16(b[p:p+2], n) }
func sign(n uint64, bits uint) int64 {
	if bits == 64 {
		return int64(n)
	}
	return int64(n<<uint(64-bits)) >> uint(64-bits)
}
func appendInt(b []byte, n int64, bits int) ([]byte, error) {
	if bits == 8 {
		bits = 16
	}
	if bits < 64 && (n < -(int64(1)<<(bits-1)) || n >= (int64(1)<<bits)) {
		return nil, fmt.Errorf("immediate outside %d-bit range", bits)
	}
	for i := bits - 8; i >= 0; i -= 8 {
		b = append(b, byte(uint64(n)>>uint(i)))
	}
	return b, nil
}
func readInt(b []byte, p *int, bits int) (int64, error) {
	bytes := bits / 8
	if bits == 8 {
		bytes = 2
	}
	if *p+bytes > len(b) {
		return 0, ErrTruncated
	}
	var n uint64
	for i := 0; i < bytes; i++ {
		n = n<<8 | uint64(b[*p+i])
	}
	*p += bytes
	return sign(n, uint(bits)), nil
}

var operandPlaces = map[byte]string{'!': "s", '#': "3BCWbjlw", '$': "bdflsw", '%': "dlsw", '&': "s", '*': "blsw", '+': "1ds", '-': "ds", '/': "s", '0': "8", '1': "8", '2': "8", '3': "8", '4': "/", ';': "Fbflpwx", '<': "s", '>': "s", '?': "s", '@': "s", 'A': "39ds", 'B': "BCLWbcgsw", 'C': "-ds", 'D': "12356Ddks", 'E': "s", 'F': "378t", 'G': "-s", 'H': "-s", 'I': "di", 'J': "j", 'L': "38w", 'M': "hs", 'O': "23", 'Q': "ds", 'R': "134MNmnos", 'S': "ds", 'T': "39s", 'U': "d", 'V': "s", 'W': "8", 'X': "3", 'Y': "8", 'Z': "8", '^': "lw", '_': "L", 'a': "ds", 'b': "s", 'c': "e", 'd': "s", 'e': "FGHf", 'f': "3", 'g': "]", 'i': "I", 'k': "Ck", 'l': "3w", 'm': "ds", 'n': "s", 'o': "blw", 'p': "ds", 'q': "ds", 'r': "14", 's': "8", 't': "8s", 'u': "MNmo", 'v': "s", 'w': "s", 'x': "d", 'y': "s", 'z': "s", '|': "s", '~': "Fblpswx"}
