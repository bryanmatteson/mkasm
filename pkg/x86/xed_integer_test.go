package x86

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

func TestXEDIntegerPhysicalSource(t *testing.T) {
	c := &Catalog{}
	report, err := SupplementXEDInteger(c)
	if err != nil {
		t.Fatal(err)
	}
	if report.Imported != 144 || report.OtherClasses == 0 {
		t.Fatalf("source accounting: %+v", report)
	}
	dec, err := NewDecoder(c)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for i := range c.Encodings {
		e := &c.Encodings[i]
		counts[e.SourceISA]++
		for _, mode := range []Mode{Mode16, Mode32, Mode64} {
			fields := EncodeFields{Mode: mode, Mod: 3, Reg: 0, RM: 2, VVVV: 1}
			if e.Mod == ModMemory {
				fields.Mod = 0
				fields.RM = 0
			}
			for _, bcst := range []bool{false, true} {
				if bcst && (e.Kind != EncodingEVEX || e.Mod != ModMemory) {
					continue
				}
				fields.Broadcast = bcst
				var out [15]byte
				n, err := Encode(out[:], e, fields)
				if err != nil {
					t.Fatalf("%s %v: %v", e.FormID, mode, err)
				}
				d, err := dec.Decode(out[:n], mode)
				if err != nil {
					t.Fatalf("%s %v %x: %v", e.FormID, mode, out[:n], err)
				}
				got := d.Encoding(dec)
				if got.Mnemonic != e.Mnemonic || got.Kind != e.Kind || got.VectorLength != e.VectorLength {
					t.Fatalf("source mismatch: %+v => %+v", e, got)
				}
			}
		}
	}
	if counts["AVX_IFMA"] != 8 || counts["AVX_VNNI"] != 16 || counts["AVX_VNNI_INT8"] != 24 || counts["AVX_VNNI_INT16"] != 24 {
		t.Fatalf("VEX accounting: %v", counts)
	}
	for _, fixture := range []struct {
		bytes []byte
		name  string
	}{
		{[]byte{0xc4, 0xe2, 0xf1, 0xb4, 0xc2}, "VPMADD52LUQ"}, {[]byte{0xc4, 0xe2, 0x71, 0x50, 0xc2}, "VPDPBUSD"}, {[]byte{0xc4, 0xe2, 0x73, 0x50, 0xc2}, "VPDPBSSD"}, {[]byte{0xc4, 0xe2, 0x72, 0xd2, 0xc2}, "VPDPWSUD"}, {[]byte{0x62, 0xf2, 0x76, 0x48, 0xd2, 0xc2}, "VPDPWSUD"},
	} {
		d, err := dec.Decode(fixture.bytes, Mode64)
		if err != nil {
			t.Fatal(err)
		}
		if d.Encoding(dec).Mnemonic != fixture.name {
			t.Fatalf("%x: wrong identity", fixture.bytes)
		}
	}
	before := len(c.Encodings)
	if _, err := SupplementXEDInteger(c); err == nil {
		t.Fatal("duplicate supplement accepted")
	}
	if len(c.Encodings) != before {
		t.Fatal("failed install mutated catalog")
	}
}

func TestXEDIntegerRequirementsAndClosedGrammar(t *testing.T) {
	c := &Catalog{}
	if _, err := SupplementXEDInteger(c); err != nil {
		t.Fatal(err)
	}
	for _, e := range c.Encodings {
		req := e.Requirements.Expression
		if req == nil {
			t.Fatal("missing requirement")
		}
		ctx := ir.RequirementContext{Features: map[string]bool{e.SourceISA: true}}
		if e.Kind == EncodingVEX {
			if req.Evaluate(ctx) != ir.Satisfied {
				t.Fatal(e.FormID)
			}
			delete(ctx.Features, e.SourceISA)
			if req.Evaluate(ctx) != ir.Unsatisfied {
				t.Fatal("missing VEX feature admitted")
			}
		} else {
			ctx.Features = map[string]bool{"AVX10_ENABLED": true}
			ctx.Fields = map[string]uint64{"CPUID.24.0.EBX": 2}
			if req.Evaluate(ctx) != ir.Satisfied {
				t.Fatal("AVX10 version2 rejected")
			}
			ctx.Fields["CPUID.24.0.EBX"] = 1
			if req.Evaluate(ctx) != ir.Unsatisfied {
				t.Fatal("AVX10 version1 admitted")
			}
			ctx.Features = map[string]bool{"AVX10_V1_AUX": true}
			ctx.Fields = nil
			if req.Evaluate(ctx) != ir.Satisfied {
				t.Fatal("FBIT alternative rejected")
			}
		}
	}
	source, err := xedIntegerFiles.ReadFile("testdata/intel-xed-integer/avx-ifma-isa.xed.txt")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(string(source), "VV1 0xB5", "VV1 UNKNOWN() 0xB5", 1), strings.Replace(string(source), "ISA_SET:     AVX_IFMA", "ISA_SET:     UNKNOWN_INTEGER", 1)} {
		if _, _, err := ParseXEDInteger(strings.NewReader(bad)); err == nil {
			t.Fatal("unknown selected constraints ignored")
		}
	}
	dir := t.TempDir()
	if err := GenerateRust(c, dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"INTEL-XED-LICENSE", "INTEL-XED-INTEGER-SOURCE"} {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err != nil || len(data) == 0 {
			t.Fatalf("missing notice %s: %v", name, err)
		}
	}
}
