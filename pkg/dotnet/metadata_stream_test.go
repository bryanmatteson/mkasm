package dotnet

import (
	"encoding/binary"
	"fmt"
	"testing"
)

func metadataWithStreams(count int) []byte {
	start := 24 + count*16 - 4
	b := make([]byte, start+32)
	copy(b, "BSJB")
	binary.LittleEndian.PutUint32(b[12:], 4)
	binary.LittleEndian.PutUint16(b[22:], uint16(count))
	for i := 0; i < count; i++ {
		p := 24 + i*16
		name := fmt.Sprintf("S%05d", i)
		if i == 0 {
			name = "#~"
			binary.LittleEndian.PutUint32(b[p+4:], 24)
		} else {
			p -= 4
		}
		binary.LittleEndian.PutUint32(b[p:], uint32(start))
		copy(b[p+8:], name)
	}
	return b
}

func TestMetadataManyEmptyStreams(t *testing.T) {
	m, err := ParseMetadata(metadataWithStreams(65535))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Streams) != 65535 || m.Streams[1].Name != "S00001" || m.Streams[65534].Name != "S65534" {
		t.Fatal("stream order or count changed")
	}
}

func TestMetadataStreamRangeValidation(t *testing.T) {
	for _, overlap := range []bool{false, true} {
		b := metadataWithStreams(3)
		start := binary.LittleEndian.Uint32(b[24:]) + 24
		// Header order differs from physical order, and empty ranges may share offsets.
		binary.LittleEndian.PutUint32(b[36:], start+4)
		binary.LittleEndian.PutUint32(b[40:], 4)
		binary.LittleEndian.PutUint32(b[52:], start)
		binary.LittleEndian.PutUint32(b[56:], 4)
		if overlap {
			binary.LittleEndian.PutUint32(b[56:], 5)
		}
		m, err := ParseMetadata(b)
		if overlap {
			if err == nil {
				t.Fatal("accepted overlapping ranges")
			}
		} else if err != nil {
			t.Fatal(err)
		} else if m.Streams[1].Offset != start+4 || m.Streams[2].Offset != start {
			t.Fatal("physical sorting changed public stream order")
		}
	}
}
