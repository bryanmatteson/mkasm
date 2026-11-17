package z80

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/bryanmatteson/mkasm/pkg/codec"
	"sort"
	"strings"
)

var ErrTruncated = codec.ErrTruncated
var ErrUnknown = codec.ErrUnknown

type Decoded struct {
	Encoding *codec.Encoding
	Values   map[string]int64
	Length   int
	Prefixes []byte // ignored leading DD/FD bytes, in original order
	Body     []byte // canonical instruction's physical bytes, including effective prefix
	catalog  *Catalog
}

func (c *Catalog) Decode(src []byte) (*Decoded, error) {
	return c.DecodeWithFeatures(src, nil)
}
func (c *Catalog) DecodeWithFeatures(src []byte, features []string) (*Decoded, error) {
	p := 0
	for p < len(src) && (src[p] == 0xdd || src[p] == 0xfd) {
		p++
	}
	if p == len(src) {
		return nil, ErrTruncated
	}
	ignored := p
	body := src[p:]
	if p > 0 && src[p] != 0xed {
		if src[p] == 0xcb {
			if len(src) < p+3 {
				return nil, ErrTruncated
			}
			body = src[p-1:]
			ignored = p - 1
		} else {
			id := fmt.Sprintf("%02x%02x", src[p-1], src[p])
			effective := false
			for _, e := range c.Encodings {
				if e.ID == id {
					effective = true
					break
				}
			}
			if effective {
				body = src[p-1:]
				ignored = p - 1
			}
		}
	}
	// Z180's undefined index-prefix combinations cause an illegal-instruction
	// trap. This profile admits the source's defined prefix grammar only.
	if c.Architecture == "z180" && ignored != 0 {
		return nil, ErrUnknown
	}
	id, err := physicalID(body)
	if err != nil {
		return nil, err
	}
	found := false
	for _, e := range c.Encodings {
		if e.ID == id {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrUnknown
	}
	d, err := c.Catalog.DecodeWithFeatures(body, features)
	if err != nil {
		return nil, err
	}
	return &Decoded{Encoding: d.Encoding, Values: d.Values, Length: ignored + d.Length, Prefixes: append([]byte(nil), src[:ignored]...), Body: append([]byte(nil), body[:d.Length]...), catalog: c}, nil
}
func (d *Decoded) CanonicalFormat(address uint64) string {
	core := codec.Decoded{Encoding: d.Encoding, Values: d.Values, Length: len(d.Body)}
	return strings.ReplaceAll(core.Format((address+uint64(len(d.Prefixes)))&65535), "+-", "-")
}

// Format emits ordinary text for the preferred encoding and an explicit
// enc[id]/prefix[hex] qualifier when needed for exact physical retention.
func (d *Decoded) Format(address uint64) string {
	text := d.CanonicalFormat(address)
	all, err := d.catalog.assembleCore(text, (address+uint64(len(d.Prefixes)))&65535, "")
	if err != nil || len(all) == 0 || !bytes.Equal(all[0], d.Body) {
		text = "enc[" + d.Encoding.ID + "] " + text
	}
	if len(d.Prefixes) > 0 {
		text = "prefix[" + hex.EncodeToString(d.Prefixes) + "] " + text
	}
	return text
}
func (d *Decoded) BranchTarget(address uint64) (uint64, bool) {
	core := codec.Decoded{Encoding: d.Encoding, Values: d.Values, Length: len(d.Body)}
	if target, ok := core.BranchTarget((address + uint64(len(d.Prefixes))) & 65535); ok {
		return target, true
	}
	if strings.Contains(d.Encoding.FlowControl, "branch") || strings.Contains(d.Encoding.FlowControl, "call") {
		for _, o := range d.Encoding.Operands {
			if o.Kind == "address" && o.Name == "target" || o.Name == "vector" {
				return uint64(d.Values[o.Name]) & 65535, true
			}
		}
	}
	switch d.Encoding.Mnemonic {
	case "ldir", "lddr", "cpir", "cpdr", "inir", "indr", "otir", "otdr", "otimr", "otdmr":
		return (address + uint64(len(d.Prefixes))) & 65535, true
	}
	return 0, false
}
func (d *Decoded) Reencode() ([]byte, error) {
	return d.catalog.Encode(d.Encoding.ID, d.Values, d.Prefixes...)
}
func (c *Catalog) Encode(id string, values map[string]int64, prefixes ...byte) ([]byte, error) {
	b, err := c.Catalog.Encode(id, values)
	if err != nil {
		return nil, err
	}
	for _, p := range prefixes {
		if p != 0xdd && p != 0xfd {
			return nil, fmt.Errorf("invalid index prefix %02x", p)
		}
	}
	all := append(append([]byte(nil), prefixes...), b...)
	d, err := c.Decode(all)
	if err != nil {
		return nil, err
	}
	if d.Length != len(all) || len(d.Prefixes) != len(prefixes) || !bytes.Equal(d.Body, b) {
		return nil, fmt.Errorf("prefixes change the selected instruction")
	}
	return all, nil
}
func qualifiers(text string) (prefix []byte, id, body string, err error) {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(strings.ToLower(text), "prefix[") {
		p := strings.IndexByte(text, ']')
		if p < 0 {
			return nil, "", "", fmt.Errorf("unterminated prefix qualifier")
		}
		raw := strings.NewReplacer(" ", "", ",", "", "0x", "").Replace(strings.ToLower(text[7:p]))
		prefix, err = hex.DecodeString(raw)
		if err != nil {
			return
		}
		for _, b := range prefix {
			if b != 0xdd && b != 0xfd {
				return nil, "", "", fmt.Errorf("invalid prefix qualifier")
			}
		}
		text = strings.TrimSpace(text[p+1:])
	}
	if strings.HasPrefix(strings.ToLower(text), "enc[") {
		p := strings.IndexByte(text, ']')
		if p < 0 {
			return nil, "", "", fmt.Errorf("unterminated encoding qualifier")
		}
		id = strings.ToLower(text[4:p])
		text = strings.TrimSpace(text[p+1:])
	}
	return prefix, id, text, nil
}
func assemblyText(text string) string {
	text = strings.ToLower(text)
	text = strings.NewReplacer("sli ", "sll ", "af_", "af'", "ix-", "ix+-", "iy-", "iy+-").Replace(text)
	return text
}
func (c *Catalog) assembleCore(text string, address uint64, id string) ([][]byte, error) {
	return c.assembleCoreWithFeatures(text, address, id, nil)
}
func (c *Catalog) assembleCoreWithFeatures(text string, address uint64, id string, features []string) ([][]byte, error) {
	text = assemblyText(text)
	if id != "" {
		for i := range c.Encodings {
			e := &c.Encodings[i]
			if e.ID != id {
				continue
			}
			v, ok := codec.ParseOperands(e, text, address)
			if !ok {
				return nil, fmt.Errorf("text does not match encoding %s", id)
			}
			b, err := codec.Encode(e, v)
			if err != nil {
				return nil, err
			}
			if _, err := c.Catalog.DecodeWithFeatures(b, features); err != nil {
				return nil, err
			}
			return [][]byte{b}, nil
		}
		return nil, fmt.Errorf("unknown encoding %s", id)
	}
	all, err := c.Catalog.AssembleWithFeatures(text, address, features)
	if err != nil {
		return nil, err
	}
	// Prefer documented indexed BIT's selector six over ignored-selector aliases.
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		rank := func(v []byte) int {
			if len(v) == 4 && (v[0] == 0xdd || v[0] == 0xfd) && v[1] == 0xcb && v[3]&0xc0 == 0x40 && v[3]&7 != 6 {
				return 1
			}
			return 0
		}
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		return bytes.Compare(a, b) < 0
	})
	return all, nil
}
func (c *Catalog) Assemble(text string, address uint64) ([][]byte, error) {
	return c.AssembleWithFeatures(text, address, nil)
}
func (c *Catalog) AssembleWithFeatures(text string, address uint64, features []string) ([][]byte, error) {
	prefix, id, body, err := qualifiers(text)
	if err != nil {
		return nil, err
	}
	all, err := c.assembleCoreWithFeatures(body, (address+uint64(len(prefix)))&65535, id, features)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, b := range all {
		raw := append(append([]byte(nil), prefix...), b...)
		d, err := c.DecodeWithFeatures(raw, features)
		if err == nil && d.Length == len(raw) && len(d.Prefixes) == len(prefix) && bytes.Equal(d.Body, b) {
			out = append(out, raw)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("prefixes change instruction meaning or violate profile")
	}
	return out, nil
}

func physicalID(body []byte) (string, error) {
	if len(body) == 0 {
		return "", ErrTruncated
	}
	switch body[0] {
	case 0xcb, 0xed:
		if len(body) < 2 {
			return "", ErrTruncated
		}
		return fmt.Sprintf("%02x%02x", body[0], body[1]), nil
	case 0xdd, 0xfd:
		if len(body) < 2 {
			return "", ErrTruncated
		}
		if body[1] == 0xcb {
			if len(body) < 4 {
				return "", ErrTruncated
			}
			return fmt.Sprintf("%02xcb%02x", body[0], body[3]), nil
		}
		return fmt.Sprintf("%02x%02x", body[0], body[1]), nil
	default:
		return fmt.Sprintf("00%02x", body[0]), nil
	}
}
