package object

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"testing"
)

func TestELFSymbolTableIdentity(t *testing.T) {
	b, err := os.ReadFile("testdata/multi-table.elf")
	if err != nil {
		t.Fatal(err)
	}
	o, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(o.Data, b) || len(o.Symbols) != 4 || len(o.Relocations) != 2 {
		t.Fatalf("lost object records: %+v", o)
	}
	if o.Sections[2].Size != 0x20000000 || len(o.Sections[2].Data) != 0 || o.Sections[2].Type != 8 {
		t.Fatal("NOBITS size or storage changed")
	}
	for i, name := range []string{"static", "dynamic"} {
		r := o.Relocations[i]
		s := o.Symbols[r.Symbol]
		if s.Name != name || s.Table != uint32(4+i) || s.Index != 1 || s.Section != 1 || r.SymbolTable != s.Table || r.OriginalSymbol != 1 {
			t.Fatalf("relocation resolved through wrong symbol table: %+v %+v", r, s)
		}
	}
	if o.Relocations[1].Addend != -4 {
		t.Fatal("signed addend lost")
	}
	// Each corrupt reference must fail before it can select another table,
	// silently discard an entry, or allocate NOBITS storage.
	for _, tc := range []struct {
		name  string
		at    int
		value uint32
	}{
		{"relocation-link", 64 + 6*64 + 40, 3},
		{"relocation-target", 64 + 6*64 + 44, 99},
		{"symbol-strings", 64 + 4*64 + 40, 1},
		{"symbol-entry-size", 64 + 4*64 + 56, 16},
		{"extended-section-index", int(binary.LittleEndian.Uint64(b[64+8*64+24:])) + 4, 99},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := bytes.Clone(b)
			binary.LittleEndian.PutUint32(changed[tc.at:], tc.value)
			if _, err := Parse(changed); err == nil {
				t.Fatal("accepted corrupt ELF reference")
			}
		})
	}
	changed := bytes.Clone(b)
	reloc := int(binary.LittleEndian.Uint64(b[64+6*64+24:]))
	binary.LittleEndian.PutUint64(changed[reloc+8:], uint64(9)<<32|1)
	if _, err := Parse(changed); err == nil {
		t.Fatal("accepted relocation outside linked symbol table")
	}
}

func TestLLVMProgramObjects(t *testing.T) {
	mc := os.Getenv("MKASM_LLVM_MC")
	if mc == "" {
		t.Skip("set MKASM_LLVM_MC to llvm-mc")
	}
	for _, tc := range []struct {
		triple, text string
		machine      uint16
		relocs       int
	}{
		{"aarch64-unknown-linux-gnu", ".text\nstart: adrp x0, external\nadd x0,x0,:lo12:external\nbl external\n", 183, 3},
		{"x86_64-unknown-linux-gnu", ".text\ncall external\nlea external(%rip),%rax\n", 62, 2},
		{"powerpc64le-unknown-linux-gnu", ".text\naddis 3,2,target@tprel@ha\naddi 3,3,target@tprel@l\n", 21, 2},
		{"sparcv9-unknown-linux-gnu", ".text\nsethi %hi(external), %g1\nor %g1, %lo(external), %g1\ncall external\nnop\n", 43, 3},
		{"riscv64-unknown-linux-gnu", ".text\nla a0, external\ncall external\n", 243, 2},
		{"bpfel-unknown-none", ".text\nr1 = external ll\nexit\n", 247, 1},
	} {
		t.Run(tc.triple, func(t *testing.T) {
			o, e := Assemble(context.Background(), tc.text, Options{Executable: mc, Triple: tc.triple})
			if e != nil {
				t.Fatal(e)
			}
			if o.Machine != tc.machine || len(o.Relocations) < tc.relocs {
				t.Fatalf("%+v", o)
			}
			found := false
			for _, s := range o.Symbols {
				found = found || s.Name == "external" || s.Name == "target"
			}
			if !found {
				t.Fatal("unresolved symbol identity lost")
			}
			for _, r := range o.Relocations {
				if r.Section != ".text" || int(r.Symbol) >= len(o.Symbols) {
					t.Fatalf("bad relocation %+v", r)
				}
			}
		})
	}
}

func TestRejectIncompleteToolConfiguration(t *testing.T) {
	for _, o := range []Options{{}, {Executable: "unused"}, {Executable: "unused", Kind: "command", Arguments: []string{"{input}"}}, {Executable: "unused", Kind: "gnu", CPU: "guessed"}} {
		if _, e := Assemble(context.Background(), "nop", o); e == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
}
