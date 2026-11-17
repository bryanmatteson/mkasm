package object

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func llvmMC(t *testing.T) string {
	t.Helper()
	path := os.Getenv("MKASM_LLVM_MC")
	if path == "" {
		t.Skip("set MKASM_LLVM_MC to llvm-mc")
	}
	return path
}

func sectionNamed(t *testing.T, o *Object, name string) (uint32, Section) {
	t.Helper()
	for i, section := range o.Sections {
		if section.Name == name {
			return uint32(i), section
		}
	}
	t.Fatalf("missing section %s", name)
	return 0, Section{}
}

func TestRelocationTargetSectionIdentity(t *testing.T) {
	b, err := os.ReadFile("testdata/multi-table.elf")
	if err != nil {
		t.Fatal(err)
	}
	// ELF permits distinct sections with identical names. The target index,
	// just like the linked symbol table, is part of relocation identity.
	copy(b[64+2*64:64+2*64+4], b[64+1*64:64+1*64+4])
	binary.LittleEndian.PutUint32(b[64+7*64+44:], 2)
	o, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if o.Relocations[0].Section != o.Relocations[1].Section || o.Relocations[0].SectionIndex != 1 || o.Relocations[1].SectionIndex != 2 {
		t.Fatalf("lost duplicate-name section identity: %+v", o.Relocations)
	}
}

func TestRejectMalformedELFHeaders(t *testing.T) {
	fixture, err := os.ReadFile("testdata/multi-table.elf")
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { b[6] = 0 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[20:], 2) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[40:], 0) },
		func(b []byte) { binary.LittleEndian.PutUint16(b[60:], 0) },
	} {
		b := bytes.Clone(fixture)
		mutate(b)
		if _, err := Parse(b); err == nil {
			t.Fatal("accepted inconsistent ELF header")
		}
	}
	if _, err := Parse(fixture[:63]); err == nil {
		t.Fatal("accepted truncated ELF64 header")
	}
}

func TestLLVMHexagonPoolsAndRelaxation(t *testing.T) {
	source, err := os.ReadFile("testdata/hexagon-program.s")
	if err != nil {
		t.Fatal(err)
	}
	o, err := Assemble(context.Background(), string(source), Options{Executable: llvmMC(t), Triple: "hexagon", CPU: "hexagonv60"})
	if err != nil {
		t.Fatal(err)
	}
	if o.Machine != 164 || o.Class != 1 || o.ByteOrder != "little" || o.ELFType != 1 || o.Flags != 0x60 {
		t.Fatalf("unexpected Hexagon ELF identity: %+v", o)
	}
	textIndex, text := sectionNamed(t, o, ".text")
	_, pool32 := sectionNamed(t, o, ".gnu.linkonce.l4.CONST_12345678")
	_, pool64 := sectionNamed(t, o, ".gnu.linkonce.l8.CONST_1122334455667788")
	if len(pool32.Data) != 4 || binary.LittleEndian.Uint32(pool32.Data) != 0x12345678 || len(pool64.Data) != 8 || binary.LittleEndian.Uint64(pool64.Data) != 0x1122334455667788 {
		t.Fatal("literal pools were not retained or duplicate CONST32 was emitted twice")
	}
	// LLVM relaxes the paired unresolved calls by adding two immext words.
	wantCalls := []byte{0, 0x40, 0, 0, 0, 0x41, 0, 0x5d, 0, 0x40, 0, 0, 0, 0xc1, 0x20, 0x5d}
	if len(text.Data) != 28 || !bytes.Equal(text.Data[12:], wantCalls) || len(o.Relocations) != 7 {
		t.Fatalf("relaxation/pool relocations lost: text=%x relocations=%+v", text.Data, o.Relocations)
	}
	if o.Relocations[0].Symbol != o.Relocations[1].Symbol {
		t.Fatal("the two CONST32 uses do not share a pool symbol")
	}
	for _, r := range o.Relocations {
		if r.SectionIndex != textIndex || !r.HasAddend || r.SymbolTable != o.Symbols[r.Symbol].Table {
			t.Fatalf("bad Hexagon relocation identity: %+v", r)
		}
	}
	for i, name := range []string{"external_a", "external_a", "external_b", "external_b"} {
		r := o.Relocations[i+3]
		kind := uint32(16)
		if i%2 != 0 {
			kind = 19
		}
		if o.Symbols[r.Symbol].Name != name || r.Offset != uint64(12+4*i) || r.Addend != int64(4*i) || r.Type != kind {
			t.Fatalf("bad relaxed branch relocation: %+v", r)
		}
	}
}

func TestLLVMBPFAndBTF(t *testing.T) {
	source, err := os.ReadFile("testdata/bpf-program.s")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ triple, order string }{{"bpfel-unknown-none", "little"}, {"bpfeb-unknown-none", "big"}} {
		t.Run(tc.triple, func(t *testing.T) {
			o, err := Assemble(context.Background(), string(source), Options{Executable: llvmMC(t), Triple: tc.triple})
			if err != nil {
				t.Fatal(err)
			}
			if o.Machine != 247 || o.Class != 2 || o.ByteOrder != tc.order {
				t.Fatalf("lost BPF ELF byte order: %+v", o)
			}
			textIndex, text := sectionNamed(t, o, ".text")
			_, btf := sectionNamed(t, o, ".BTF")
			extIndex, ext := sectionNamed(t, o, ".BTF.ext")
			var order binary.ByteOrder = binary.LittleEndian
			if tc.order == "big" {
				order = binary.BigEndian
			}
			if len(text.Data) != 16 || len(btf.Data) != 115 || len(ext.Data) != 80 || order.Uint16(btf.Data) != 0xeb9f || order.Uint16(ext.Data) != 0xeb9f || order.Uint32(btf.Data[4:]) != 24 || order.Uint32(ext.Data[4:]) != 32 || !bytes.Contains(btf.Data, []byte("entry\x00.text\x00")) {
				t.Fatal("BTF type, function or line information changed")
			}
			entry, external, btfRelocations := false, false, 0
			for _, s := range o.Symbols {
				entry = entry || s.Name == "entry" && s.Other&3 == 2 && s.Section == textIndex && s.Size == 16
			}
			for _, r := range o.Relocations {
				s := o.Symbols[r.Symbol]
				if r.SectionIndex == textIndex && r.Type == 10 && s.Name == "external" && s.Section == 0 {
					external = true
				}
				if r.SectionIndex == extIndex {
					if r.Type != 4 || r.HasAddend || s.Section != textIndex {
						t.Fatalf("bad BTF instruction-offset relocation: %+v", r)
					}
					btfRelocations++
				}
			}
			if !entry || !external || btfRelocations != 2 {
				t.Fatal("BPF hidden function, external call or BTF relocation identity lost")
			}
			for _, r := range o.Relocations {
				if r.Section != o.Sections[r.SectionIndex].Name || r.SymbolTable != o.Symbols[r.Symbol].Table || r.OriginalSymbol != o.Symbols[r.Symbol].Index {
					t.Fatal("ELF references do not resolve to their original section and symbol table")
				}
			}
			if strings.Contains(string(o.Data), "mkasm-object-") {
				t.Fatal("temporary assembly path leaked into BTF/DWARF fixture")
			}
		})
	}
}

func TestLLVMCompressedSectionBytes(t *testing.T) {
	o, err := Assemble(context.Background(), ".text\nnop\n.section .debug_info,\"\",@progbits\n.rept 256\n.long 0x12345678\n.endr\n", Options{
		Executable: llvmMC(t), Triple: "x86_64-unknown-linux-gnu", Arguments: []string{"--compress-debug-sections=zlib"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := elf.NewFile(bytes.NewReader(o.Data))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i, section := range f.Sections {
		if section.Name != ".debug_info" {
			continue
		}
		if section.Flags&elf.SHF_COMPRESSED == 0 {
			t.Fatal("LLVM did not compress the section")
		}
		stored := o.Data[section.Offset : section.Offset+section.FileSize]
		if o.Sections[i].Size != section.FileSize || !bytes.Equal(o.Sections[i].Data, stored) {
			t.Fatalf("section flags describe stored compressed bytes, but model reports size=%d data=%d; file size=%d", o.Sections[i].Size, len(o.Sections[i].Data), section.FileSize)
		}
		return
	}
	t.Fatal("missing compressed .debug_info")
}
