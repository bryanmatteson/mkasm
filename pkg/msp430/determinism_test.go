package msp430

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

func TestImportedCatalogGenerationIsDeterministic(t *testing.T) {
	for _, arch := range []string{"msp430", "msp430x"} {
		t.Run(arch, func(t *testing.T) {
			var wantJSON []byte
			var wantFiles map[string][]byte
			for trial := 0; trial < 8; trial++ {
				c := load(t, arch)
				var data bytes.Buffer
				if err := c.WriteJSON(&data); err != nil {
					t.Fatal(err)
				}
				if trial == 0 {
					wantJSON = append([]byte(nil), data.Bytes()...)
				} else if !bytes.Equal(wantJSON, data.Bytes()) {
					t.Fatalf("%s import %d changed the exported instruction metadata", arch, trial)
				}
				if trial != 0 && trial != 7 {
					continue
				}
				// Independent destinations ensure a preceding generation cannot
				// hide missing or stale files in a later generation.
				out := t.TempDir()
				if err := c.GenerateRust(out); err != nil {
					t.Fatal(err)
				}
				files := map[string][]byte{}
				if err := filepath.WalkDir(out, func(path string, entry fs.DirEntry, err error) error {
					if err != nil || entry.IsDir() {
						return err
					}
					name, err := filepath.Rel(out, path)
					if err != nil {
						return err
					}
					files[name], err = os.ReadFile(path)
					return err
				}); err != nil {
					t.Fatal(err)
				}
				if trial == 0 {
					wantFiles = files
				} else if !reflect.DeepEqual(wantFiles, files) {
					for name, want := range wantFiles {
						got, exists := files[name]
						if !exists || !bytes.Equal(want, got) {
							t.Errorf("%s regeneration changed %s", arch, name)
						}
						delete(files, name)
					}
					for name := range files {
						t.Errorf("%s regeneration added %s", arch, name)
					}
				}
			}
		})
	}
}

func TestExtendedSharedAddressHighFieldsAreOrdered(t *testing.T) {
	c := load(t, "msp430")
	checked := 0
	for _, base := range c.Encodings {
		if base.AssemblyOnly || len(base.Value) < 6 || base.Value[1]>>4 < 4 {
			continue
		}
		before := cloneEncoding(base)
		ext := extendEncoding(base, base.Mnemonic+"x.w", "w")
		if !reflect.DeepEqual(base, before) {
			t.Fatalf("extension mutated original encoding %s", base.ID)
		}
		for i, original := range base.Operands {
			var source, destination bool
			for _, bit := range original.Bits {
				source = source || bit.InstructionBit >= 16 && bit.InstructionBit < 32
				destination = destination || bit.InstructionBit >= 32
			}
			if !source || !destination {
				continue
			}
			checked++
			got := ext.Operands[i].Bits[len(original.Bits):]
			want := []codec.BitSlice{{InstructionBit: 0, ValueBit: 16, Width: 4}, {InstructionBit: 7, ValueBit: 16, Width: 4}}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s operand %s: extension slices %+v, want %+v", base.ID, original.Name, got, want)
			}
		}
	}
	if checked == 0 {
		t.Fatal("source corpus did not exercise an operand shared by two address words")
	}
	t.Logf("checked %d source operands shared by two address words", checked)
}
