package x86

import (
	"os"
	"os/exec"
	"testing"
)

func BenchmarkDecode(b *testing.B) {
	decoder, err := NewDecoder(codecCatalog())
	if err != nil {
		b.Fatal(err)
	}
	words := [][]byte{
		{0x90},
		{0x48, 0x01, 0xc8},
		{0x48, 0x01, 0x4c, 0x24, 0x08},
		{0xf3, 0x0f, 0x1e, 0xfa},
		{0xc5, 0xed, 0xfe, 0xcb},
		{0x62, 0xf1, 0x7d, 0x48, 0xef, 0xc0},
	}
	b.ReportAllocs()
	b.ResetTimer()
	var checksum uint32
	for i := 0; i < b.N; i++ {
		decoded, decodeErr := decoder.Decode(words[i%len(words)], Mode64)
		if decodeErr != nil {
			b.Fatal(decodeErr)
		}
		checksum += decoded.CatalogIndex
	}
	if checksum == ^uint32(0) {
		b.Fatal(checksum)
	}
}

func BenchmarkEncode(b *testing.B) {
	encoding := &codecCatalog().Encodings[4]
	fields := EncodeFields{Mode: Mode64, Mod: 3, Reg: 1, RM: 3, VVVV: 2}
	var dst [15]byte
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Encode(dst[:], encoding, fields); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeCorpus(b *testing.B) {
	path := os.Getenv("MKASM_X86_OPCODESDB")
	if path == "" {
		b.Skip("set MKASM_X86_OPCODESDB to the opcodesDB v3 .json.xz corpus")
	}
	command := exec.Command("xz", "-dc", path)
	pipe, err := command.StdoutPipe()
	if err != nil {
		b.Fatal(err)
	}
	if err := command.Start(); err != nil {
		b.Fatal(err)
	}
	catalog, err := ParseOpcodesDB(pipe)
	if err != nil {
		b.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		b.Fatal(err)
	}
	decoder, err := NewDecoder(catalog)
	if err != nil {
		b.Fatal(err)
	}
	probes := [][]byte{
		{0x90},
		{0x48, 0x01, 0xc8},
		{0x48, 0x01, 0x4c, 0x24, 0x08},
		{0xf3, 0x0f, 0x1e, 0xfa},
		{0xc5, 0xed, 0xfe, 0xcb},
		{0x62, 0xf1, 0x7d, 0x48, 0xef, 0xc0},
	}
	b.ReportAllocs()
	b.ResetTimer()
	var checksum uint32
	for i := 0; i < b.N; i++ {
		decoded, decodeErr := decoder.Decode(probes[i%len(probes)], Mode64)
		if decodeErr != nil {
			b.Fatal(decodeErr)
		}
		checksum += decoded.CatalogIndex
	}
	if checksum == ^uint32(0) {
		b.Fatal(checksum)
	}
}
