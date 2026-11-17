package dotnet

import (
	"bytes"
	"encoding/binary"
	"math"
	"sort"
)

// RewriteOptions makes invalidation of native code and signatures explicit.
// Rewriting retains token identities and metadata; callers supply complete CIL
// method bodies, including their locals, maxstack and exception sections.
type RewriteOptions struct {
	DropNative        bool
	StripStrongName   bool
	StripAuthenticode bool
}

// RewriteMethods returns a new PE image. Bodies may grow; the original image is
// never modified. A new readable IL section is used when headers have room,
// otherwise the final physical/virtual section is extended without moving any
// existing RVA. Debug-directory references are removed because source offsets
// cannot be retained after arbitrary IL edits. Every replacement is validated
// before any output is published.
func (im *Image) RewriteMethods(edits map[Token][]byte, options RewriteOptions) ([]byte, error) {
	if im.Composite {
		return nil, bad("rewrite the component IL image; composite native images have no global CIL metadata")
	}
	if im.Format != "PE32" && im.Format != "PE32+" {
		return nil, bad("rewriting requires a PE image")
	}
	if len(edits) == 0 {
		return append([]byte(nil), im.Data...), nil
	}
	if im.ReadyToRun && !options.DropNative {
		return nil, bad("ReadyToRun rewriting requires DropNative")
	}
	if options.DropNative {
		if !im.ReadyToRun || im.CLI.Flags&0x10 != 0 {
			return nil, bad("DropNative requires ReadyToRun with a managed entry point")
		}
		methods, e := im.Metadata.Methods()
		if e != nil {
			return nil, e
		}
		for _, m := range methods {
			if m.Kind == "native" || (m.RVA == 0 && m.ImplFlags&3 == 0 && m.Flags&(0x400|0x2000) == 0 && m.ImplFlags&0x1000 == 0) {
				return nil, bad("cannot discard native code without a retained IL body for %s", m.Token)
			}
		}
	}
	if (im.CLI.Flags&8 != 0 || im.CLI.StrongNameSignature.Size != 0) && !options.StripStrongName {
		return nil, bad("signed image requires StripStrongName")
	}
	pe := uint64(binary.LittleEndian.Uint32(im.Data[60:]))
	optional := pe + 24
	directory := uint64(96)
	if im.Format == "PE32+" {
		directory = 112
	}
	security := optional + directory + 4*8
	if binary.LittleEndian.Uint32(im.Data[security+4:]) != 0 && !options.StripAuthenticode {
		return nil, bad("Authenticode image requires StripAuthenticode")
	}
	fileAlign := uint64(binary.LittleEndian.Uint32(im.Data[optional+36:]))
	sectionAlign := uint64(binary.LittleEndian.Uint32(im.Data[optional+32:]))
	if fileAlign == 0 || fileAlign&(fileAlign-1) != 0 || sectionAlign == 0 || sectionAlign&(sectionAlign-1) != 0 {
		return nil, bad("invalid PE alignment")
	}
	align := func(v, a uint64) uint64 { return (v + a - 1) &^ (a - 1) }
	keys := make([]Token, 0, len(edits))
	for token, body := range edits {
		if token.Table() != 6 {
			return nil, bad("replacement token is not MethodDef")
		}
		old, e := im.MethodBody(token)
		if e != nil {
			return nil, e
		}
		if old.Kind != "cil" {
			return nil, bad("replacement requires a CIL method")
		}
		parsed, e := ParseMethodBody(body)
		if e != nil {
			return nil, e
		}
		if len(parsed.Raw) != len(body) {
			return nil, bad("replacement has trailing bytes")
		}
		keys = append(keys, token)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	if len(im.Sections) == 0 {
		return nil, bad("image has no sections")
	}
	table := optional + uint64(binary.LittleEndian.Uint16(im.Data[pe+20:]))
	nextHeader := table + uint64(len(im.Sections))*40
	firstRaw := uint64(len(im.Data))
	maxVA := uint64(0)
	last := -1
	for i, s := range im.Sections {
		if s.RawSize != 0 && uint64(s.RawOffset) < firstRaw {
			firstRaw = uint64(s.RawOffset)
		}
		end := uint64(s.VirtualAddress) + uint64(max(s.VirtualSize, s.RawSize))
		if end > maxVA {
			maxVA = end
			last = i
		}
	}
	newSection := nextHeader+40 <= firstRaw && nextHeader+40 <= uint64(im.SizeOfHeaders) && len(im.Sections) < math.MaxUint16
	start := align(uint64(len(im.Data)), fileAlign)
	baseVA := align(maxVA, sectionAlign)
	header := nextHeader
	if !newSection {
		s := im.Sections[last]
		for _, other := range im.Sections {
			if uint64(other.RawOffset)+uint64(other.RawSize) > uint64(s.RawOffset)+uint64(s.RawSize) {
				return nil, bad("no room for an IL section header and final section is not physically last")
			}
		}
		header = table + uint64(last)*40
		// Appending must not consume or shrink an existing zero-fill tail.
		start = align(max(start, uint64(s.RawOffset)+uint64(s.VirtualSize)), fileAlign)
		baseVA = uint64(s.VirtualAddress) + start - uint64(s.RawOffset)
	}
	if start > math.MaxUint32 || baseVA > math.MaxUint32 {
		return nil, ErrBounds
	}
	out := append([]byte(nil), im.Data...)
	out = append(out, make([]byte, int(start)-len(out))...)
	rvas := map[Token]uint32{}
	for _, token := range keys {
		p := align(uint64(len(out)), 4)
		out = append(out, make([]byte, int(p)-len(out))...)
		rva := baseVA + p - start
		if rva > math.MaxUint32 || uint64(len(edits[token])) > math.MaxUint32-rva {
			return nil, ErrBounds
		}
		rvas[token] = uint32(rva)
		out = append(out, edits[token]...)
	}
	virtualEnd := baseVA + uint64(len(out)) - start
	rawEnd := align(uint64(len(out)), fileAlign)
	if rawEnd > math.MaxUint32 || align(virtualEnd, sectionAlign) > math.MaxUint32 {
		return nil, ErrBounds
	}
	out = append(out, make([]byte, int(rawEnd)-len(out))...)
	put := func(p uint64, v uint32) { binary.LittleEndian.PutUint32(out[p:], v) }
	if newSection {
		clear(out[header : header+40])
		copy(out[header:], ".mkil")
		put(header+8, uint32(virtualEnd-baseVA))
		put(header+12, uint32(baseVA))
		put(header+16, uint32(rawEnd-start))
		put(header+20, uint32(start))
		put(header+36, 0x40000040)
		binary.LittleEndian.PutUint16(out[pe+6:], uint16(len(im.Sections)+1))
	} else {
		s := im.Sections[last]
		put(header+8, uint32(virtualEnd-uint64(s.VirtualAddress)))
		put(header+16, uint32(rawEnd-uint64(s.RawOffset)))
		put(header+36, (s.Characteristics|0x40000040)&^uint32(0x02000000))
	}
	put(optional+56, uint32(align(virtualEnd, sectionAlign)))
	initialized := uint64(binary.LittleEndian.Uint32(im.Data[optional+8:]))
	if newSection {
		initialized += rawEnd - start
	} else {
		s := im.Sections[last]
		if s.Characteristics&0x40 == 0 {
			initialized += rawEnd - uint64(s.RawOffset)
		} else {
			initialized += rawEnd - uint64(s.RawOffset) - uint64(s.RawSize)
		}
	}
	if initialized > math.MaxUint32 {
		return nil, ErrBounds
	}
	put(optional+8, uint32(initialized))
	put(optional+64, 0)
	// CodeView, embedded Portable PDB and reproducibility entries describe the
	// original instruction offsets. Retaining them would publish stale symbols.
	put(optional+directory+6*8, 0)
	put(optional+directory+6*8+4, 0)
	metadata, e := im.RVAOffset(im.CLI.Metadata.RVA, im.CLI.Metadata.Size)
	if e != nil {
		return nil, e
	}
	var tablesOffset uint32
	found := false
	for _, s := range im.Metadata.Streams {
		if s.Name == "#~" || s.Name == "#-" {
			tablesOffset = s.Offset
			found = true
			break
		}
	}
	if !found {
		return nil, bad("metadata table stream missing")
	}
	t := im.Metadata.Tables[6]
	for _, token := range keys {
		p := metadata + uint64(tablesOffset) + t.Offset + uint64(token.RID()-1)*uint64(t.RowSize)
		if p+4 > uint64(len(out)) {
			return nil, ErrBounds
		}
		put(p, rvas[token])
	}
	cliRVA := binary.LittleEndian.Uint32(out[optional+directory+14*8:])
	cli, e := im.RVAOffset(cliRVA, 72)
	if e != nil {
		return nil, e
	}
	if options.DropNative {
		put(cli+64, 0)
		put(cli+68, 0)
		put(cli+16, (im.CLI.Flags|1)&^uint32(4))
	}
	if options.StripStrongName {
		if im.CLI.StrongNameSignature.Size != 0 {
			p, e := im.RVAOffset(im.CLI.StrongNameSignature.RVA, im.CLI.StrongNameSignature.Size)
			if e != nil {
				return nil, e
			}
			clear(out[p : p+uint64(im.CLI.StrongNameSignature.Size)])
		}
		put(cli+32, 0)
		put(cli+36, 0)
		put(cli+16, binary.LittleEndian.Uint32(out[cli+16:])&^uint32(8))
	}
	if options.StripAuthenticode {
		put(security, 0)
		put(security+4, 0)
	}
	next, e := Open(out)
	if e != nil {
		return nil, e
	}
	for token, body := range edits {
		b, e := next.MethodBody(token)
		if e != nil || !bytes.Equal(b.Raw, body) {
			return nil, bad("replacement validation failed for %s", token)
		}
	}
	return out, nil
}
