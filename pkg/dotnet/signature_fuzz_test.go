package dotnet

import (
	"os"
	"testing"
)

// Mutating individual signatures reaches the recursive type grammar without
// spending the fuzz budget repeatedly parsing an entire PE and its metadata.
func FuzzSignatures(f *testing.F) {
	b, err := os.ReadFile("testdata/anycpu.dll")
	if err != nil {
		f.Fatal(err)
	}
	im, err := Open(b)
	if err != nil {
		f.Fatal(err)
	}
	m := im.Metadata
	for _, source := range [][2]uint8{{4, 2}, {6, 4}, {10, 2}, {17, 0}, {23, 2}, {27, 0}, {43, 1}} {
		table, column := source[0], source[1]
		for rid := uint32(1); rid <= m.Tables[table].Count; rid++ {
			row, err := m.Row(table, rid)
			if err != nil {
				f.Fatal(err)
			}
			blob, err := m.Blob(row[column])
			if err != nil {
				f.Fatal(err)
			}
			f.Add(blob)
		}
	}
	for _, seed := range [][]byte{{}, {8}, {0, 0, 1}, {0x14, 8, 1, 1, 2, 1, 0x80, 1}, {0x1b, 0, 0, 1}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if signature, err := m.ParseSignature(b); err == nil {
			_ = signature.Format(m)
		}
		if typ, err := m.TypeSignature(b); err == nil {
			_ = typ.Format(m)
		}
	})
}
