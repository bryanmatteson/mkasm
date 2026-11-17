package mips

import (
	"bytes"
	"compress/gzip"
	"context"
	"github.com/bryanmatteson/mkasm/pkg/object"
	"os"
	"testing"
)

func TestCompressedGNUOracle(t *testing.T) {
	as := os.Getenv("MKASM_MIPS_AS")
	if as == "" {
		t.Skip("set MKASM_MIPS_AS to GNU MIPS assembler")
	}
	for _, mode := range []string{"micromips32", "micromips32el", "mips16", "mips16el"} {
		t.Run(mode, func(t *testing.T) {
			f, e := os.Open("testdata/llvm22-compressed.json.gz")
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			gz, e := gzip.NewReader(f)
			if e != nil {
				t.Fatal(e)
			}
			defer gz.Close()
			c, e := Parse(gz, mode)
			if e != nil {
				t.Fatal(e)
			}
			flag := "-mmicromips"
			texts := []string{"addiu $2, $2, 257", "lw $2, 132($3)", "sw $4, 256($sp)", "andi $2, $2, 65534", "lbu $2, -1($3)", "lhu $2, 30($3)", "lw $2, 60($3)", "sb $2, 15($3)", "sh $2, 30($3)", "sw $2, 60($3)", "jr16 $31", "nop"}
			if mode == "mips16" || mode == "mips16el" {
				flag = "-mips16"
				texts = []string{"li $2, 17", "addiu $2, 4", "lw $2, 12($3)", "sw $4, 16($sp)", "move $2, $3", "jr $31", "nop"}
			}
			endian := "-EB"
			if mode == "micromips32el" || mode == "mips16el" {
				endian = "-EL"
			}
			for _, text := range texts {
				o, e := object.Assemble(context.Background(), ".text\n.set noreorder\n"+text+"\n", object.Options{Executable: as, Kind: "gnu", Arguments: []string{flag, endian, "-32", "-O0"}})
				if e != nil {
					t.Fatal(text, e)
				}
				var code []byte
				for _, s := range o.Sections {
					if s.Name == ".text" {
						code = s.Data
					}
				}
				d, e := c.Decode(code)
				if e != nil {
					t.Fatalf("%s %x: %v", text, code, e)
				}
				b, e := c.Encode(d.Encoding.ID, d.Values)
				if e != nil || !bytes.Equal(b, code[:len(b)]) {
					t.Fatalf("decode %s %x: %v", text, code, e)
				}
				spell := d.Format(0)
				encoded, e := c.Assemble(spell, 0)
				found := false
				for _, b := range encoded {
					found = found || bytes.Equal(b, code[:len(b)])
				}
				if e != nil || !found {
					t.Fatalf("text %s => %s: %v", text, spell, e)
				}
				// The independently assembled source operands must also encode
				// to those bytes, not merely decode and reproduce a shared mistake.
				encoded, e = c.Assemble(text, 0)
				found = false
				for _, b := range encoded {
					found = found || len(b) <= len(code) && bytes.Equal(b, code[:len(b)])
				}
				if e != nil || !found {
					t.Fatalf("source %s: got %x, GNU %x: %v", text, encoded, code, e)
				}
			}
		})
	}
}
