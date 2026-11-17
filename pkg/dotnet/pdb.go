package dotnet

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
)

type SequencePoint struct {
	Document    Token  `json:"document"`
	Offset      uint32 `json:"offset"`
	StartLine   uint32 `json:"start_line"`
	StartColumn uint32 `json:"start_column"`
	EndLine     uint32 `json:"end_line"`
	EndColumn   uint32 `json:"end_column"`
	Hidden      bool   `json:"hidden"`
}

func (m *Metadata) SequencePoints(method Token) (Token, []SequencePoint, error) {
	if m.PDB == nil || method.Table() != 6 {
		return 0, nil, bad("not a portable PDB method")
	}
	row, e := m.Row(49, method.RID())
	if e != nil {
		return 0, nil, e
	}
	b, e := m.Blob(row[1])
	if e != nil || len(b) == 0 {
		return 0, nil, e
	}
	r := cursor{b: b}
	local, e := r.compressed()
	if e != nil {
		return 0, nil, e
	}
	var lt Token
	if local != 0 {
		if local > 0xffffff {
			return 0, nil, bad("PDB local signature RID overflow")
		}
		lt = Token(17<<24 | local)
		if e = m.ValidateToken(lt); e != nil {
			return 0, nil, e
		}
	}
	doc := row[0]
	if doc == 0 {
		doc, e = r.compressed()
		if e != nil {
			return 0, nil, e
		}
	}
	validateDoc := func() error {
		if doc == 0 || doc > 0xffffff {
			return bad("invalid PDB document RID")
		}
		return m.ValidateToken(Token(48<<24 | doc))
	}
	if e = validateDoc(); e != nil {
		return 0, nil, e
	}
	var points []SequencePoint
	var off uint32
	var prevLine, prevCol int64
	seenVisible := false
	for r.p < uint64(len(b)) {
		delta, e := r.compressed()
		if e != nil {
			return 0, nil, e
		}
		if len(points) > 0 && delta == 0 {
			doc, e = r.compressed()
			if e != nil {
				return 0, nil, e
			}
			if e = validateDoc(); e != nil {
				return 0, nil, e
			}
			continue
		}
		if uint64(off)+uint64(delta) >= 0x20000000 {
			return 0, nil, bad("PDB IL offset overflow")
		}
		off += delta
		lines, e := r.compressed()
		if e != nil {
			return 0, nil, e
		}
		var cols int64
		if lines == 0 {
			v, e := r.compressed()
			if e != nil {
				return 0, nil, e
			}
			cols = int64(v)
		} else {
			v, e := r.signedCompressed()
			if e != nil {
				return 0, nil, e
			}
			cols = int64(v)
		}
		p := SequencePoint{Document: Token(48<<24 | doc), Offset: off}
		if lines == 0 && cols == 0 {
			p.Hidden = true
			p.StartLine = 0xfeefee
			p.EndLine = 0xfeefee
		} else {
			var line, col int64
			if !seenVisible {
				v, e := r.compressed()
				if e != nil {
					return 0, nil, e
				}
				line = int64(v)
				v, e = r.compressed()
				if e != nil {
					return 0, nil, e
				}
				col = int64(v)
			} else {
				v, e := r.signedCompressed()
				if e != nil {
					return 0, nil, e
				}
				line = prevLine + int64(v)
				v, e = r.signedCompressed()
				if e != nil {
					return 0, nil, e
				}
				col = prevCol + int64(v)
			}
			endLine := line + int64(lines)
			endCol := col + cols
			if line < 0 || endLine >= 0x20000000 || line == 0xfeefee || endLine == 0xfeefee || col < 0 || col >= 65536 || endCol < 0 || endCol >= 65536 || (lines == 0 && endCol <= col) {
				return 0, nil, bad("invalid PDB sequence point")
			}
			p.StartLine = uint32(line)
			p.StartColumn = uint32(col)
			p.EndLine = uint32(endLine)
			p.EndColumn = uint32(endCol)
			prevLine = line
			prevCol = col
			seenVisible = true
		}
		points = append(points, p)
	}
	return lt, points, nil
}

type DebugEntry struct {
	Type       uint32 `json:"type"`
	Timestamp  uint32 `json:"timestamp"`
	Major      uint16 `json:"major"`
	Minor      uint16 `json:"minor"`
	RVA        uint32 `json:"rva"`
	FileOffset uint32 `json:"file_offset"`
	Data       []byte `json:"data"`
}

func (im *Image) DebugEntries() ([]DebugEntry, error) {
	if im.DebugDirectory.Size == 0 {
		return nil, nil
	}
	if im.DebugDirectory.Size%28 != 0 {
		return nil, bad("invalid debug directory size")
	}
	b, e := im.BytesAtRVA(im.DebugDirectory.RVA, im.DebugDirectory.Size)
	if e != nil {
		return nil, e
	}
	var out []DebugEntry
	for p := 0; p < len(b); p += 28 {
		a := b[p:]
		n := binary.LittleEndian.Uint32(a[16:])
		off := binary.LittleEndian.Uint32(a[24:])
		data, e := span(im.Data, uint64(off), uint64(n))
		if e != nil {
			return nil, e
		}
		out = append(out, DebugEntry{binary.LittleEndian.Uint32(a[12:]), binary.LittleEndian.Uint32(a[4:]), binary.LittleEndian.Uint16(a[8:]), binary.LittleEndian.Uint16(a[10:]), binary.LittleEndian.Uint32(a[20:]), off, data})
	}
	return out, nil
}

// EmbeddedPDB bounds decompression by the declared uncompressed size and a caller
// supplied ceiling. It returns nil if the image has no embedded Portable PDB.
func (im *Image) EmbeddedPDB(maxBytes uint32) (*Metadata, error) {
	entries, e := im.DebugEntries()
	if e != nil {
		return nil, e
	}
	for _, v := range entries {
		if v.Type != 17 {
			continue
		}
		if len(v.Data) < 8 || !bytes.Equal(v.Data[:4], []byte("MPDB")) {
			return nil, bad("invalid embedded PDB header")
		}
		n := binary.LittleEndian.Uint32(v.Data[4:])
		if n > maxBytes {
			return nil, bad("embedded PDB exceeds size limit")
		}
		r := flate.NewReader(bytes.NewReader(v.Data[8:]))
		b, e := io.ReadAll(io.LimitReader(r, int64(n)+1))
		r.Close()
		if e != nil {
			return nil, e
		}
		if len(b) != int(n) {
			return nil, bad("embedded PDB size mismatch")
		}
		m, e := ParseMetadata(b)
		if e != nil {
			return nil, e
		}
		if m.PDB == nil {
			return nil, bad("embedded data is not Portable PDB")
		}
		return m, nil
	}
	return nil, nil
}
