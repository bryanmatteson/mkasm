package dotnet

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

type Stream struct {
	Name   string `json:"name"`
	Offset uint32 `json:"offset"`
	Size   uint32 `json:"size"`
	Data   []byte `json:"-"`
}
type Table struct {
	ID      uint8  `json:"id"`
	Name    string `json:"name"`
	Count   uint32 `json:"count"`
	RowSize uint32 `json:"row_size"`
	Offset  uint64 `json:"offset"`
	Widths  []int  `json:"-"`
}
type PDBHeader struct {
	ID               []byte     `json:"id"`
	EntryPoint       Token      `json:"entry_point"`
	ReferencedTables uint64     `json:"referenced_tables"`
	Rows             [64]uint32 `json:"rows"`
}
type Metadata struct {
	Data      []byte     `json:"-"`
	Version   string     `json:"version"`
	Streams   []Stream   `json:"streams"`
	Tables    [64]Table  `json:"tables"`
	HeapSizes uint8      `json:"heap_sizes"`
	Valid     uint64     `json:"valid"`
	Sorted    uint64     `json:"sorted"`
	PDB       *PDBHeader `json:"pdb,omitempty"`
	tableData []byte
	external  [64]uint32
	owners    map[Token]Token
	generics  map[Token][]GenericParameter
	nested    map[Token]Token
}

func (m *Metadata) Stream(name string) ([]byte, bool) {
	for _, s := range m.Streams {
		if s.Name == name {
			return s.Data, true
		}
	}
	return nil, false
}
func ParseMetadata(b []byte) (*Metadata, error) {
	if len(b) < 20 || !bytes.Equal(b[:4], []byte("BSJB")) {
		return nil, bad("invalid metadata signature")
	}
	versionLen, _ := u32(b, 12)
	if versionLen == 0 || versionLen%4 != 0 {
		return nil, bad("invalid metadata version length")
	}
	v, e := span(b, 16, uint64(versionLen))
	if e != nil {
		return nil, e
	}
	zero := bytes.IndexByte(v, 0)
	if zero < 0 || !utf8.Valid(v[:max(zero, 0)]) {
		return nil, bad("unterminated metadata version")
	}
	m := &Metadata{Data: b, Version: string(v[:zero])}
	r := cursor{b: b, p: 16 + uint64(versionLen)}
	if _, e := r.uint(2); e != nil {
		return nil, e
	}
	n, e := r.uint(2)
	if e != nil {
		return nil, e
	}
	names := map[string]bool{}
	for i := uint32(0); i < n; i++ {
		offset, e := r.uint(4)
		if e != nil {
			return nil, e
		}
		size, e := r.uint(4)
		if e != nil {
			return nil, e
		}
		start := r.p
		found := false
		for j := 0; j < 32; j++ {
			c, e := r.uint(1)
			if e != nil {
				return nil, e
			}
			if c == 0 {
				found = true
				break
			}
		}
		if !found {
			return nil, bad("unterminated metadata stream name")
		}
		name := string(b[start : r.p-1])
		if name == "" || names[name] || !utf8.ValidString(name) {
			return nil, bad("empty/duplicate metadata stream %q", name)
		}
		names[name] = true
		r.p = (r.p + 3) &^ 3
		data, e := span(b, uint64(offset), uint64(size))
		if e != nil {
			return nil, bad("stream %s: %v", name, e)
		}
		m.Streams = append(m.Streams, Stream{name, offset, size, data})
	}
	ranges := make([][2]uint64, 0, len(m.Streams))
	for _, s := range m.Streams {
		if uint64(s.Offset) < r.p {
			return nil, bad("stream overlaps metadata headers")
		}
		if s.Size != 0 {
			ranges = append(ranges, [2]uint64{uint64(s.Offset), uint64(s.Offset) + uint64(s.Size)})
		}
	}
	// Validate a sorted copy so the public stream order stays as encoded.
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
	for i := 1; i < len(ranges); i++ {
		if ranges[i][0] < ranges[i-1][1] {
			return nil, bad("overlapping metadata streams")
		}
	}
	if pdb, ok := m.Stream("#Pdb"); ok {
		if len(pdb) < 32 {
			return nil, ErrBounds
		}
		h := &PDBHeader{ID: append([]byte(nil), pdb[:20]...), EntryPoint: Token(binary.LittleEndian.Uint32(pdb[20:])), ReferencedTables: binary.LittleEndian.Uint64(pdb[24:])}
		r := cursor{b: pdb, p: 32}
		for t := 0; t < 64; t++ {
			if h.ReferencedTables&(uint64(1)<<t) != 0 {
				if t > 44 || Schemas[t] == nil {
					return nil, bad("invalid portable PDB external table")
				}
				count, e := r.uint(4)
				if e != nil {
					return nil, e
				}
				if count > 0xffffff {
					return nil, bad("portable PDB external row count exceeds token limit")
				}
				h.Rows[t] = count
				m.external[t] = count
			}
		}
		if r.p != uint64(len(pdb)) {
			return nil, bad("trailing portable PDB header bytes")
		}
		m.PDB = h
	}
	td, ok := m.Stream("#~")
	if !ok {
		td, ok = m.Stream("#-")
	}
	if !ok {
		return nil, bad("missing metadata tables stream")
	}
	if len(td) < 24 {
		return nil, ErrBounds
	}
	m.tableData = td
	m.HeapSizes = td[6]
	if m.HeapSizes&^byte(0xe7) != 0 {
		return nil, bad("reserved metadata heap size flags")
	}
	m.Valid = binary.LittleEndian.Uint64(td[8:])
	m.Sorted = binary.LittleEndian.Uint64(td[16:])
	r = cursor{b: td, p: 24}
	for t := 0; t < 64; t++ {
		if m.Valid&(uint64(1)<<t) == 0 {
			continue
		}
		if Schemas[t] == nil {
			return nil, bad("unknown metadata table 0x%x", t)
		}
		if m.PDB != nil && t < 48 {
			return nil, bad("portable PDB contains type system table")
		}
		count, e := r.uint(4)
		if e != nil {
			return nil, e
		}
		if count > 0xffffff {
			return nil, bad("metadata row count exceeds token limit")
		}
		m.Tables[t] = Table{ID: uint8(t), Name: Schemas[t].Name, Count: count}
	}
	if m.HeapSizes&0x40 != 0 {
		if _, e := r.uint(4); e != nil {
			return nil, e
		}
	}
	for t := 0; t < 64; t++ {
		table := &m.Tables[t]
		if m.Valid&(uint64(1)<<t) == 0 {
			continue
		}
		for _, c := range Schemas[t].Columns {
			width, e := m.columnSize(c.Kind)
			if e != nil {
				return nil, e
			}
			table.Widths = append(table.Widths, width)
			table.RowSize += uint32(width)
		}
		table.Offset = r.p
		if _, e := r.take(uint64(table.Count) * uint64(table.RowSize)); e != nil {
			return nil, bad("table %s: %v", table.Name, e)
		}
	}
	if e := m.Validate(); e != nil {
		return nil, e
	}
	if m.PDB == nil {
		m.owners = map[Token]Token{}
		for rid := uint32(1); rid <= m.Tables[2].Count; rid++ {
			for _, target := range []uint8{4, 6} {
				col := 4
				if target == 6 {
					col = 5
				}
				items, e := m.Range(2, rid, col, target)
				if e != nil {
					return nil, e
				}
				for _, item := range items {
					if m.owners[item] != 0 {
						return nil, bad("multiply owned member")
					}
					m.owners[item] = Token(2<<24 | rid)
				}
			}
		}
		if uint32(len(m.owners)) != m.Tables[4].Count+m.Tables[6].Count {
			return nil, bad("orphan member rows")
		}
	}
	m.generics = map[Token][]GenericParameter{}
	constraints := map[uint32][]Token{}
	for rid := uint32(1); rid <= m.Tables[44].Count; rid++ {
		r, _ := m.Row(44, rid)
		t, _ := DecodeCoded("TypeDefOrRef", r[1])
		constraints[r[0]] = append(constraints[r[0]], t)
	}
	for rid := uint32(1); rid <= m.Tables[42].Count; rid++ {
		r, _ := m.Row(42, rid)
		owner, _ := DecodeCoded("TypeOrMethodDef", r[2])
		name, _ := m.String(r[3])
		m.generics[owner] = append(m.generics[owner], GenericParameter{Token: Token(42<<24 | rid), Number: r[0], Flags: r[1], Name: name, Constraints: constraints[rid]})
	}
	m.nested = map[Token]Token{}
	for rid := uint32(1); rid <= m.Tables[41].Count; rid++ {
		r, _ := m.Row(41, rid)
		m.nested[Token(2<<24|r[0])] = Token(2<<24 | r[1])
	}
	return m, nil
}
func (m *Metadata) rowCount(t int) uint32 { return max(m.Tables[t].Count, m.external[t]) }
func (m *Metadata) pointerTable(target int) int {
	switch target {
	case 4:
		if m.Tables[3].Count > 0 {
			return 3
		}
	case 6:
		if m.Tables[5].Count > 0 {
			return 5
		}
	case 8:
		if m.Tables[7].Count > 0 {
			return 7
		}
	case 20:
		if m.Tables[19].Count > 0 {
			return 19
		}
	case 23:
		if m.Tables[22].Count > 0 {
			return 22
		}
	}
	return target
}
func (m *Metadata) columnSize(k string) (int, error) {
	switch k {
	case "u2":
		return 2, nil
	case "u4":
		return 4, nil
	case "string", "guid", "blob":
		bit := map[string]uint8{"string": 1, "guid": 2, "blob": 4}[k]
		if m.HeapSizes&bit != 0 {
			return 4, nil
		}
		return 2, nil
	}
	if k[0] == 't' || k[0] == 'l' {
		t, e := strconv.Atoi(k[1:])
		if e != nil || t < 0 || t >= 64 {
			return 0, bad("invalid table column")
		}
		if k[0] == 'l' {
			t = m.pointerTable(t)
		}
		if m.rowCount(t) >= 65536 {
			return 4, nil
		}
		return 2, nil
	}
	c, ok := CodedIndices[k]
	if !ok {
		return 0, bad("unknown column kind %s", k)
	}
	for _, t := range c.Tables {
		if t >= 0 && m.rowCount(t) >= 1<<(16-c.Bits) {
			return 4, nil
		}
	}
	return 2, nil
}
func (m *Metadata) Row(table uint8, rid uint32) ([]uint32, error) {
	if table >= 64 || Schemas[table] == nil || rid == 0 || rid > m.Tables[table].Count {
		return nil, bad("invalid %s row %d", tableName(table), rid)
	}
	t := m.Tables[table]
	r := cursor{b: m.tableData, p: t.Offset + uint64(rid-1)*uint64(t.RowSize)}
	a := make([]uint32, len(t.Widths))
	for j, w := range t.Widths {
		n, e := r.uint(w)
		if e != nil {
			return nil, e
		}
		a[j] = n
	}
	return a, nil
}
func tableName(t uint8) string {
	if t < 64 && Schemas[t] != nil {
		return Schemas[t].Name
	}
	return fmt.Sprintf("table%d", t)
}
func (m *Metadata) ValidateToken(t Token) error {
	if t.RID() == 0 {
		return bad("nil metadata token %s", t)
	}
	if t.Table() == 0x70 {
		_, _, e := m.UserString(t.RID())
		return e
	}
	if t.Table() >= 64 || Schemas[t.Table()] == nil || t.RID() > m.rowCount(int(t.Table())) {
		return bad("out-of-range metadata token %s", t)
	}
	return nil
}
func (m *Metadata) String(index uint32) (string, error) {
	if index == 0 {
		return "", nil
	}
	b, ok := m.Stream("#Strings")
	if !ok || uint64(index) >= uint64(len(b)) {
		return "", bad("string heap index 0x%x out of bounds", index)
	}
	a := b[index:]
	n := bytes.IndexByte(a, 0)
	if n < 0 {
		return "", bad("unterminated heap string")
	}
	if !utf8.Valid(a[:n]) {
		return "", bad("invalid UTF-8 heap string")
	}
	return string(a[:n]), nil
}
func (m *Metadata) Blob(index uint32) ([]byte, error) {
	if index == 0 {
		return []byte{}, nil
	}
	b, ok := m.Stream("#Blob")
	if !ok || uint64(index) >= uint64(len(b)) {
		return nil, bad("blob heap index out of bounds")
	}
	r := cursor{b: b, p: uint64(index)}
	n, e := r.compressed()
	if e != nil {
		return nil, e
	}
	return r.take(uint64(n))
}
func (m *Metadata) GUID(index uint32) ([16]byte, error) {
	var out [16]byte
	if index == 0 {
		return out, nil
	}
	b, ok := m.Stream("#GUID")
	if !ok {
		return out, bad("missing GUID heap")
	}
	a, e := span(b, uint64(index-1)*16, 16)
	if e != nil {
		return out, e
	}
	copy(out[:], a)
	return out, nil
}
func (m *Metadata) UserString(index uint32) (string, []uint16, error) {
	if index == 0 {
		return "", nil, nil
	}
	b, ok := m.Stream("#US")
	if !ok {
		return "", nil, bad("missing user-string heap")
	}
	r := cursor{b: b, p: uint64(index)}
	n, e := r.compressed()
	if e != nil {
		return "", nil, e
	}
	if n == 0 || n%2 != 1 {
		return "", nil, bad("invalid user-string byte length")
	}
	a, e := r.take(uint64(n))
	if e != nil {
		return "", nil, e
	}
	if a[len(a)-1] > 1 {
		return "", nil, bad("invalid user-string terminal flag")
	}
	units := make([]uint16, len(a)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(a[i*2:])
	}
	return string(utf16.Decode(units)), units, nil
}
func (m *Metadata) Validate() error {
	for t := 0; t < 64; t++ {
		table := m.Tables[t]
		previous := make([]uint32, len(table.Widths))
		if table.Count == 0 {
			continue
		}
		for rid := uint32(1); rid <= table.Count; rid++ {
			row, e := m.Row(uint8(t), rid)
			if e != nil {
				return e
			}
			for j, c := range Schemas[t].Columns {
				n := row[j]
				if c.Kind[0] == 't' || c.Kind[0] == 'l' || (c.Kind != "u2" && c.Kind != "u4" && c.Kind != "string" && c.Kind != "blob" && c.Kind != "guid") {
					if n == 0 && !nullableIndex(t, j) {
						return bad("%s[%d].%s: nil required index", table.Name, rid, c.Name)
					}
				}
				if c.Kind[0] == 'l' {
					if rid == 1 && n != 1 || rid > 1 && n < previous[j] {
						return bad("invalid %s list ordering", table.Name)
					}
					previous[j] = n
				}
				var err error
				switch c.Kind {
				case "string":
					_, err = m.String(n)
				case "blob":
					_, err = m.Blob(n)
				case "guid":
					_, err = m.GUID(n)
				case "u2", "u4":
				default:
					if c.Kind[0] == 't' || c.Kind[0] == 'l' {
						target, _ := strconv.Atoi(c.Kind[1:])
						limit := m.rowCount(target)
						if c.Kind[0] == 'l' {
							target = m.pointerTable(target)
							limit = m.rowCount(target) + 1
							if n == 0 {
								err = bad("list starts at nil row")
							}
						}
						if n > limit {
							err = bad("table index %d exceeds %d", n, limit)
						}
					} else {
						tok, e := DecodeCoded(c.Kind, n)
						err = e
						if err == nil && tok != 0 {
							err = m.ValidateToken(tok)
						}
					}
				}
				if err != nil {
					return bad("%s[%d].%s: %v", table.Name, rid, c.Name, err)
				}
			}
		}
	}
	return m.validateGraph()
}

// Range expands a metadata list including unoptimized #- pointer tables.
func (m *Metadata) Range(owner uint8, rid uint32, column int, target uint8) ([]Token, error) {
	if target >= 64 || Schemas[target] == nil {
		return nil, bad("invalid list target table")
	}
	row, e := m.Row(owner, rid)
	if e != nil {
		return nil, e
	}
	if column < 0 || column >= len(row) || Schemas[owner].Columns[column].Kind != "l"+strconv.Itoa(int(target)) {
		return nil, bad("invalid list column")
	}
	actual := m.pointerTable(int(target))
	start := row[column]
	end := m.Tables[actual].Count + 1
	if rid < m.Tables[owner].Count {
		next, _ := m.Row(owner, rid+1)
		end = next[column]
	}
	if start == 0 || start > end || end > m.Tables[actual].Count+1 {
		return nil, bad("invalid metadata list range")
	}
	var a []Token
	for n := start; n < end; n++ {
		value := n
		if actual != int(target) {
			r, e := m.Row(uint8(actual), n)
			if e != nil {
				return nil, e
			}
			value = r[0]
		}
		a = append(a, Token(uint32(target)<<24|value))
	}
	return a, nil
}
func qualify(ns, name string) string {
	if ns == "" {
		return name
	}
	return strings.Join([]string{ns, name}, ".")
}
