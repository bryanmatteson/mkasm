package dotnet

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

var ErrNotManaged = errors.New("dotnet: PE image has no CLI header")

type Directory struct {
	RVA  uint32 `json:"rva"`
	Size uint32 `json:"size"`
}
type Section struct {
	Name            string `json:"name"`
	VirtualSize     uint32 `json:"virtual_size"`
	VirtualAddress  uint32 `json:"virtual_address"`
	RawSize         uint32 `json:"raw_size"`
	RawOffset       uint32 `json:"raw_offset"`
	Characteristics uint32 `json:"characteristics"`
}
type CLIHeader struct {
	Size                    uint32
	MajorRuntimeVersion     uint16
	MinorRuntimeVersion     uint16
	Metadata                Directory
	Flags                   uint32
	EntryPoint              uint32
	Resources               Directory
	StrongNameSignature     Directory
	CodeManagerTable        Directory
	VTableFixups            Directory
	ExportAddressTableJumps Directory
	ManagedNativeHeader     Directory
}
type Image struct {
	Data           []byte    `json:"-"`
	Format         string    `json:"format"`
	Machine        uint16    `json:"machine"`
	ImageBase      uint64    `json:"image_base"`
	SizeOfHeaders  uint32    `json:"size_of_headers"`
	Sections       []Section `json:"sections"`
	CLI            CLIHeader `json:"cli"`
	Metadata       *Metadata `json:"metadata"`
	ReadyToRun     bool      `json:"ready_to_run"`
	Composite      bool      `json:"composite"`
	HasMetadata    bool      `json:"has_metadata"`
	NativeHeader   Directory `json:"native_header,omitempty"`
	DebugDirectory Directory `json:"debug_directory"`
}

func Open(b []byte) (*Image, error) {
	im := &Image{Data: b}
	if len(b) >= 4 && bytes.Equal(b[:4], []byte("BSJB")) {
		m, e := ParseMetadata(b)
		if e != nil {
			return nil, e
		}
		im.Metadata = m
		im.HasMetadata = true
		im.Format = "metadata"
		if m.PDB != nil {
			im.Format = "portable-pdb"
		}
		return im, nil
	}
	if len(b) < 64 || !bytes.Equal(b[:2], []byte("MZ")) {
		return nil, bad("not a DOS/PE image")
	}
	pe, _ := u32(b, 60)
	head, e := span(b, uint64(pe), 24)
	if e != nil || !bytes.Equal(head[:4], []byte{'P', 'E', 0, 0}) {
		return nil, bad("invalid PE header")
	}
	im.Machine = binary.LittleEndian.Uint16(head[4:])
	sections := binary.LittleEndian.Uint16(head[6:])
	optionalSize := binary.LittleEndian.Uint16(head[20:])
	optional, e := span(b, uint64(pe)+24, uint64(optionalSize))
	if e != nil {
		return nil, e
	}
	magic, e := u16(optional, 0)
	if e != nil {
		return nil, e
	}
	var directoryOffset uint64
	switch magic {
	case 0x10b:
		im.Format = "PE32"
		directoryOffset = 96
		x, e := u32(optional, 28)
		if e != nil {
			return nil, e
		}
		im.ImageBase = uint64(x)
	case 0x20b:
		im.Format = "PE32+"
		directoryOffset = 112
		im.ImageBase, e = u64(optional, 24)
		if e != nil {
			return nil, e
		}
	default:
		return nil, bad("unknown PE optional header magic 0x%x", magic)
	}
	im.SizeOfHeaders, e = u32(optional, 60)
	if e != nil || uint64(im.SizeOfHeaders) > uint64(len(b)) {
		return nil, bad("invalid SizeOfHeaders")
	}
	n, e := u32(optional, directoryOffset-4)
	if e != nil || n < 15 || uint64(n) > ((uint64(len(optional))-min(directoryOffset, uint64(len(optional))))/8) {
		return nil, bad("invalid PE data directory count")
	}
	dir := func(index uint64) Directory {
		p := directoryOffset + index*8
		return Directory{binary.LittleEndian.Uint32(optional[p:]), binary.LittleEndian.Uint32(optional[p+4:])}
	}
	cliDir := dir(14)
	im.DebugDirectory = dir(6)
	sectionTable, e := span(b, uint64(pe)+24+uint64(optionalSize), uint64(sections)*40)
	if e != nil {
		return nil, e
	}
	for n := 0; n < int(sections); n++ {
		a := sectionTable[n*40 : n*40+40]
		s := Section{strings.TrimRight(string(a[:8]), "\x00"), binary.LittleEndian.Uint32(a[8:]), binary.LittleEndian.Uint32(a[12:]), binary.LittleEndian.Uint32(a[16:]), binary.LittleEndian.Uint32(a[20:]), binary.LittleEndian.Uint32(a[36:])}
		if _, e := span(b, uint64(s.RawOffset), uint64(s.RawSize)); e != nil {
			return nil, bad("section %s raw data: %v", s.Name, e)
		}
		im.Sections = append(im.Sections, s)
	}
	compositeDir, e := im.compositeDirectory(dir(0))
	if e != nil {
		return nil, e
	}
	if compositeDir.RVA != 0 {
		im.Composite, im.ReadyToRun, im.NativeHeader = true, true, compositeDir
	}
	if cliDir.RVA == 0 || cliDir.Size == 0 {
		if compositeDir.RVA == 0 {
			return nil, ErrNotManaged
		}
		// Composite images have no global ECMA metadata. Components retain their
		// own contexts; the empty view has zero rows and HasMetadata is false.
		im.Metadata = &Metadata{}
		return im, nil
	}
	if cliDir.Size < 72 {
		return nil, bad("CLI directory shorter than header")
	}
	cli, e := im.BytesAtRVA(cliDir.RVA, cliDir.Size)
	if e != nil {
		return nil, e
	}
	cb := binary.LittleEndian.Uint32(cli)
	if cb < 72 || cb > uint32(len(cli)) {
		return nil, bad("invalid CLI header size")
	}
	d := func(p int) Directory {
		return Directory{binary.LittleEndian.Uint32(cli[p:]), binary.LittleEndian.Uint32(cli[p+4:])}
	}
	im.CLI = CLIHeader{cb, binary.LittleEndian.Uint16(cli[4:]), binary.LittleEndian.Uint16(cli[6:]), d(8), binary.LittleEndian.Uint32(cli[16:]), binary.LittleEndian.Uint32(cli[20:]), d(24), d(32), d(40), d(48), d(56), d(64)}
	md, e := im.BytesAtRVA(im.CLI.Metadata.RVA, im.CLI.Metadata.Size)
	if e != nil {
		return nil, bad("metadata directory: %v", e)
	}
	im.Metadata, e = ParseMetadata(md)
	if e != nil {
		return nil, e
	}
	im.HasMetadata = true
	for _, d := range []Directory{im.CLI.Resources, im.CLI.StrongNameSignature, im.CLI.CodeManagerTable, im.CLI.VTableFixups, im.CLI.ExportAddressTableJumps, im.CLI.ManagedNativeHeader} {
		if d.Size != 0 {
			if _, e := im.BytesAtRVA(d.RVA, d.Size); e != nil {
				return nil, bad("CLI subdirectory: %v", e)
			}
		}
	}
	if im.CLI.ManagedNativeHeader.Size >= 4 {
		a, _ := im.BytesAtRVA(im.CLI.ManagedNativeHeader.RVA, 4)
		im.ReadyToRun = im.Composite || binary.LittleEndian.Uint32(a) == 0x00525452
	}
	if im.CLI.Flags&0x10 == 0 && im.CLI.EntryPoint != 0 {
		if e := im.Metadata.ValidateToken(Token(im.CLI.EntryPoint)); e != nil {
			return nil, bad("entry point: %v", e)
		}
		if Token(im.CLI.EntryPoint).Table() != 6 && Token(im.CLI.EntryPoint).Table() != 38 {
			return nil, bad("entry point token is not MethodDef/File")
		}
	}
	return im, nil
}
func (im *Image) RVAOffset(rva, size uint32) (uint64, error) {
	if uint64(rva)+uint64(size) > 1<<32 {
		return 0, ErrBounds
	}
	if rva < im.SizeOfHeaders {
		if uint64(rva)+uint64(size) > uint64(im.SizeOfHeaders) {
			return 0, ErrBounds
		}
		if _, e := span(im.Data, uint64(rva), uint64(size)); e != nil {
			return 0, e
		}
		return uint64(rva), nil
	}
	found := false
	var offset uint64
	for _, s := range im.Sections {
		start := uint64(s.VirtualAddress)
		end := start + uint64(max(s.VirtualSize, s.RawSize))
		if uint64(rva) < start || uint64(rva) >= end {
			continue
		}
		if found {
			return 0, bad("ambiguous RVA in overlapping sections")
		}
		delta := uint64(rva) - start
		if delta+uint64(size) > uint64(s.RawSize) {
			return 0, bad("RVA lies in unbacked virtual section data")
		}
		offset = uint64(s.RawOffset) + delta
		found = true
	}
	if !found {
		return 0, bad("unmapped RVA 0x%x", rva)
	}
	if _, e := span(im.Data, offset, uint64(size)); e != nil {
		return 0, e
	}
	return offset, nil
}
func (im *Image) BytesAtRVA(rva, size uint32) ([]byte, error) {
	p, e := im.RVAOffset(rva, size)
	if e != nil {
		return nil, e
	}
	return span(im.Data, p, uint64(size))
}
