package dotnet

import (
	"encoding/binary"
	"testing"
)

func TestSequencePointsRejectInvalidRIDs(t *testing.T) {
	for _, tt := range []struct {
		name    string
		initial bool
		blob    []byte
	}{
		{"local overflow", false, []byte{0xc1, 0, 0, 1, 0, 0, 0}},
		{"initial document overflow", true, []byte{0, 0xc1, 0, 0, 1, 0, 0, 0}},
		{"changed document overflow", false, []byte{0, 0, 0, 0, 0, 0xc1, 0, 0, 1, 1, 0, 0}},
		{"changed document nil", false, []byte{0, 0, 0, 0, 0, 0}},
		{"changed document out of range", false, []byte{0, 0, 0, 0, 0, 127}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := fixture(t, "anycpu.pdb")
			im, err := Open(data)
			if err != nil {
				t.Fatal(err)
			}
			m := im.Metadata
			for rid := uint32(1); rid <= m.Tables[49].Count; rid++ {
				row, err := m.Row(49, rid)
				if err != nil {
					t.Fatal(err)
				}
				blob, err := m.Blob(row[1])
				if err != nil {
					t.Fatal(err)
				}
				if row[0] == 0 || len(blob) < len(tt.blob) {
					continue
				}
				heap, _ := m.Stream("#Blob")
				_, prefix, err := CompressedInteger(heap[row[1]:])
				if err != nil || prefix != 1 {
					continue
				}
				heap[row[1]] = byte(len(tt.blob))
				copy(heap[row[1]+1:], tt.blob)
				if tt.initial {
					if m.Tables[49].Widths[0] != 2 {
						t.Fatal("unexpected fixture document index width")
					}
					offset := m.Tables[49].Offset + uint64(rid-1)*uint64(m.Tables[49].RowSize)
					binary.LittleEndian.PutUint16(m.tableData[offset:], 0)
				}
				im, err = Open(data)
				if err != nil {
					t.Fatal(err)
				}
				if _, points, err := im.Metadata.SequencePoints(Token(6<<24 | rid)); err == nil {
					t.Fatalf("accepted invalid RID: %+v", points)
				}
				return
			}
			t.Fatal("fixture has no suitable sequence point blob")
		})
	}
}
