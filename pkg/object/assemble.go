// Package object assembles complete programs with an explicitly selected target
// toolchain. It complements instruction codecs when source requires symbols,
// sections, ABI relocation expressions, literal pools or relaxation.
package object

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type Options struct {
	Executable string   `json:"executable"`
	Kind       string   `json:"kind"` // llvm, gnu, or command
	Triple     string   `json:"triple,omitempty"`
	CPU        string   `json:"cpu,omitempty"`
	Features   []string `json:"features,omitempty"`
	// Additional arguments are passed directly, never through a shell. Command
	// mode requires {input} and {output}; LLVM/GNU mode supplies these itself.
	Arguments []string `json:"arguments,omitempty"`
}

type Section struct {
	Name    string `json:"name"`
	Address uint64 `json:"address"`
	Flags   uint64 `json:"flags"`
	Size    uint64 `json:"size"`
	Type    uint32 `json:"type"`
	Data    []byte `json:"data"`
}
type Symbol struct {
	Name    string `json:"name"`
	Value   uint64 `json:"value"`
	Size    uint64 `json:"size"`
	Section uint32 `json:"section"`
	Info    uint8  `json:"info"`
	Other   uint8  `json:"other"`
	Table   uint32 `json:"table"`
	Index   uint32 `json:"index"`
}
type Relocation struct {
	Section        string `json:"section"`
	SectionIndex   uint32 `json:"section_index"`
	Offset         uint64 `json:"offset"`
	Type           uint32 `json:"type"`
	Symbol         uint32 `json:"symbol_index"`
	Addend         int64  `json:"addend"`
	HasAddend      bool   `json:"has_addend"`
	SymbolTable    uint32 `json:"symbol_table"`
	OriginalSymbol uint32 `json:"original_symbol_index"`
}
type Object struct {
	Format      string       `json:"format"`
	Machine     uint16       `json:"machine,omitempty"`
	Class       uint8        `json:"class,omitempty"`
	ByteOrder   string       `json:"byte_order,omitempty"`
	ELFType     uint16       `json:"elf_type,omitempty"`
	Flags       uint32       `json:"flags,omitempty"`
	Data        []byte       `json:"data"`
	Sections    []Section    `json:"sections,omitempty"`
	Symbols     []Symbol     `json:"symbols,omitempty"`
	Relocations []Relocation `json:"relocations,omitempty"`
	Diagnostics string       `json:"diagnostics,omitempty"`
}

// Assemble retains the complete relocatable object. LLVM and GNU own target ABI
// semantics; unresolved symbols remain relocations instead of invented zeros.
// Command mode supports vendor assemblers and non-native object formats without
// imposing a CPU-only model on their output.
func Assemble(ctx context.Context, source string, options Options) (*Object, error) {
	if options.Executable == "" {
		return nil, fmt.Errorf("object: explicit assembler executable required")
	}
	dir, e := os.MkdirTemp("", "mkasm-object-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(dir)
	input, output := filepath.Join(dir, "input.s"), filepath.Join(dir, "output.o")
	if e = os.WriteFile(input, []byte(source), 0600); e != nil {
		return nil, e
	}
	args := []string{}
	switch options.Kind {
	case "llvm", "":
		if options.Triple == "" {
			return nil, fmt.Errorf("object: LLVM target triple required")
		}
		args = append(args, "-filetype=obj", "-triple="+options.Triple)
		if options.CPU != "" {
			args = append(args, "-mcpu="+options.CPU)
		}
		if len(options.Features) > 0 {
			args = append(args, "-mattr="+strings.Join(options.Features, ","))
		}
		args = append(args, options.Arguments...)
		args = append(args, "-o", output, input)
	case "gnu":
		if options.Triple != "" || options.CPU != "" || len(options.Features) > 0 {
			return nil, fmt.Errorf("object: GNU target/CPU options must be explicit Arguments for the selected assembler")
		}
		args = append(args, options.Arguments...)
		args = append(args, "-o", output, input)
	case "command":
		if options.Triple != "" || options.CPU != "" || len(options.Features) > 0 {
			return nil, fmt.Errorf("object: command target options belong in Arguments")
		}
		in, out := false, false
		for _, arg := range options.Arguments {
			in = in || strings.Contains(arg, "{input}")
			out = out || strings.Contains(arg, "{output}")
			arg = strings.ReplaceAll(arg, "{input}", input)
			arg = strings.ReplaceAll(arg, "{output}", output)
			args = append(args, arg)
		}
		if !in || !out {
			return nil, fmt.Errorf("object: command arguments require {input} and {output}")
		}
	default:
		return nil, fmt.Errorf("object: unknown assembler kind %q", options.Kind)
	}
	diagnostics, e := exec.CommandContext(ctx, options.Executable, args...).CombinedOutput()
	if e != nil {
		return nil, fmt.Errorf("object: assembler failed: %w\n%s", e, diagnostics)
	}
	data, e := os.ReadFile(output)
	if e != nil {
		return nil, fmt.Errorf("object: assembler did not produce an object: %w", e)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("object: assembler produced an empty object")
	}
	o, e := Parse(data)
	if e != nil {
		return nil, e
	}
	o.Diagnostics = string(diagnostics)
	return o, nil
}

// Parse exposes ELF sections, symbol identities and relocation records while
// preserving all bytes. Other vendor formats remain exact opaque objects.
func Parse(data []byte) (*Object, error) {
	out := &Object{Format: "vendor", Data: append([]byte(nil), data...)}
	if !bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) {
		return out, nil
	}
	f, e := elf.NewFile(bytes.NewReader(data))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	out.Format = "ELF"
	out.Machine = uint16(f.Machine)
	out.Class = uint8(f.Class)
	out.ELFType = uint16(f.Type)
	out.ByteOrder = "little"
	if f.Data == elf.ELFDATA2MSB {
		out.ByteOrder = "big"
	}
	word := 4
	if f.Class == elf.ELFCLASS64 {
		word = 8
	}
	flagsAt := 36
	if word == 8 {
		flagsAt = 48
	}
	out.Flags = f.ByteOrder.Uint32(data[flagsAt:])
	read := func(b []byte) uint64 {
		if word == 8 {
			return f.ByteOrder.Uint64(b)
		}
		return uint64(f.ByteOrder.Uint32(b))
	}
	contents := make([][]byte, len(f.Sections))
	for i, s := range f.Sections {
		size := s.Size
		if s.Type != elf.SHT_NOBITS && s.Type != elf.SHT_NULL {
			// Section.Data transparently decompresses ELF debug sections. The
			// object model instead retains their exact stored payload and flags,
			// matching the dependency-free Rust parser and original object.
			if s.Offset > uint64(len(data)) || s.FileSize > uint64(len(data))-s.Offset {
				return nil, fmt.Errorf("object: truncated section %s", s.Name)
			}
			contents[i] = bytes.Clone(data[s.Offset : s.Offset+s.FileSize])
			size = s.FileSize
		}
		out.Sections = append(out.Sections, Section{Name: s.Name, Address: s.Addr, Flags: uint64(s.Flags), Size: size, Type: uint32(s.Type), Data: contents[i]})
	}
	type tableRange struct{ base, count uint32 }
	tables := map[uint32]tableRange{}
	for ti, s := range f.Sections {
		if s.Type != elf.SHT_SYMTAB && s.Type != elf.SHT_DYNSYM {
			continue
		}
		if int(s.Link) >= len(f.Sections) || f.Sections[s.Link].Type != elf.SHT_STRTAB {
			return nil, fmt.Errorf("object: invalid symbol string table for %s", s.Name)
		}
		stringsData := contents[s.Link]
		name := func(offset uint32) (string, error) {
			if uint64(offset) >= uint64(len(stringsData)) {
				return "", fmt.Errorf("object: invalid symbol name offset")
			}
			b := stringsData[offset:]
			end := bytes.IndexByte(b, 0)
			if end < 0 {
				return "", fmt.Errorf("object: unterminated symbol name")
			}
			return string(b[:end]), nil
		}
		width := 16
		if word == 8 {
			width = 24
		}
		b := contents[ti]
		if s.Entsize != uint64(width) || len(b)%width != 0 {
			return nil, fmt.Errorf("object: malformed symbol table %s", s.Name)
		}
		if uint64(len(out.Symbols))+uint64(len(b)/width) > uint64(^uint32(0)) {
			return nil, fmt.Errorf("object: too many symbols")
		}
		tables[uint32(ti)] = tableRange{uint32(len(out.Symbols)), uint32(len(b) / width)}
		var extended []byte
		for xi, x := range f.Sections {
			if x.Type == elf.SHT_SYMTAB_SHNDX && x.Link == uint32(ti) {
				if extended != nil || len(contents[xi]) != len(b)/width*4 {
					return nil, fmt.Errorf("object: malformed extended symbol section indices")
				}
				extended = contents[xi]
			}
		}
		for p := 0; p < len(b); p += width {
			h := b[p : p+width]
			n, err := name(f.ByteOrder.Uint32(h))
			if err != nil {
				return nil, err
			}
			var value, size uint64
			var info, other uint8
			var section uint32
			if word == 8 {
				info = h[4]
				other = h[5]
				section = uint32(f.ByteOrder.Uint16(h[6:]))
				value = read(h[8:])
				size = read(h[16:])
			} else {
				value = read(h[4:])
				size = read(h[8:])
				info = h[12]
				other = h[13]
				section = uint32(f.ByteOrder.Uint16(h[14:]))
			}
			if section == uint32(elf.SHN_XINDEX) {
				if extended == nil {
					return nil, fmt.Errorf("object: missing extended symbol section indices")
				}
				section = f.ByteOrder.Uint32(extended[p/width*4:])
				if uint64(section) >= uint64(len(f.Sections)) {
					return nil, fmt.Errorf("object: invalid extended symbol section")
				}
			} else if section < uint32(elf.SHN_LORESERVE) && uint64(section) >= uint64(len(f.Sections)) {
				return nil, fmt.Errorf("object: invalid symbol section")
			}
			out.Symbols = append(out.Symbols, Symbol{Name: n, Value: value, Size: size, Section: section, Info: info, Other: other, Table: uint32(ti), Index: uint32(p / width)})
		}
	}
	for si, s := range f.Sections {
		if s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA {
			continue
		}
		table, ok := tables[s.Link]
		if !ok || int(s.Info) >= len(f.Sections) {
			return nil, fmt.Errorf("object: invalid relocation links for %s", s.Name)
		}
		b := contents[si]
		hasAddend := s.Type == elf.SHT_RELA
		width := word * 2
		if hasAddend {
			width += word
		}
		if s.Entsize != uint64(width) || len(b)%width != 0 {
			return nil, fmt.Errorf("object: malformed relocation section %s", s.Name)
		}
		for p := 0; p < len(b); p += width {
			offset, info := read(b[p:]), read(b[p+word:])
			symbol, kind := uint32(info>>8), uint32(info&255)
			if word == 8 {
				symbol, kind = uint32(info>>32), uint32(info)
			}
			// MIPS64EL stores the symbol index little-endian and the compound
			// relocation type as four ordered bytes, unlike generic ELF64 r_info.
			if f.Machine == elf.EM_MIPS && word == 8 && f.ByteOrder == binary.LittleEndian {
				symbol = binary.LittleEndian.Uint32(b[p+8:])
				kind = binary.BigEndian.Uint32(b[p+12:])
			}
			if symbol >= table.count {
				return nil, fmt.Errorf("object: relocation symbol outside linked table")
			}
			addend := int64(0)
			if hasAddend {
				addend = int64(read(b[p+2*word:]))
				if word == 4 {
					addend = int64(int32(addend))
				}
			}
			out.Relocations = append(out.Relocations, Relocation{Section: f.Sections[s.Info].Name, SectionIndex: s.Info, Offset: offset, Type: kind, Symbol: table.base + symbol, Addend: addend, HasAddend: hasAddend, SymbolTable: s.Link, OriginalSymbol: symbol})
		}
	}
	return out, nil
}
