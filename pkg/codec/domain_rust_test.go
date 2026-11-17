package codec

import "testing"

func TestRustPrecomputedDomains(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    Operand
		want rustOperandDomain
	}{
		{"implicit", Operand{Implicit: true}, rustOperandDomain{"0", "0", "1", true}},
		{"dependent", Operand{BiasOperand: "r"}, rustOperandDomain{"-170141183460469231731687303715884105728", "170141183460469231731687303715884105727", "1", false}},
		{"scaled signed", Operand{Signed: true, Bits: []BitSlice{{0, 0, 8}}, Scale: 4, Bias: 3}, rustOperandDomain{"-509", "511", "4", true}},
		{"split", Operand{Bits: []BitSlice{{0, 1, 2}, {3, 4, 2}}}, rustOperandDomain{"0", "54", "2", false}},
		{"xor sign", Operand{Signed: true, Bits: []BitSlice{{0, 0, 3}}, Xor: 4}, rustOperandDomain{"-4", "3", "1", true}},
		{"fixed xor", Operand{Bits: []BitSlice{{0, 1, 2}}, Xor: 1}, rustOperandDomain{"1", "7", "2", true}},
		{"names", Operand{Bits: []BitSlice{{0, 0, 3}}, Names: []string{"a", "", "b", "", "c"}, Scale: 2, Bias: -1}, rustOperandDomain{"-1", "7", "4", true}},
		{"sparse names", Operand{Bits: []BitSlice{{0, 0, 3}}, Names: []string{"a", "b", "", "c"}}, rustOperandDomain{"0", "3", "1", false}},
		{"unrepresented names", Operand{Bits: []BitSlice{{0, 1, 1}}, Xor: 1, Names: []string{"a", "b", "c", "d"}}, rustOperandDomain{"1", "3", "2", true}},
		{"empty names", Operand{Bits: []BitSlice{{0, 0, 1}}, Names: []string{"", ""}}, rustOperandDomain{"1", "0", "1", true}},
		{"lookup", Operand{Bits: []BitSlice{{0, 0, 2}}, Lookup: []int64{7, -2, 7, 4}}, rustOperandDomain{"-2", "7", "3", true}},
		{"lookup duplicates", Operand{Bits: []BitSlice{{0, 0, 1}}, Lookup: []int64{7, 7}}, rustOperandDomain{"7", "7", "1", false}},
		{"short lookup", Operand{Bits: []BitSlice{{0, 0, 2}}, Names: []string{"a", "b", "c"}, Lookup: []int64{5}}, rustOperandDomain{"5", "5", "1", true}},
		{"signed names", Operand{Signed: true, Bits: []BitSlice{{0, 0, 2}}, Names: []string{"a", "b", "c", "d"}}, rustOperandDomain{"-2", "1", "1", true}},
		{"u64", Operand{Bits: []BitSlice{{0, 0, 64}}}, rustOperandDomain{"0", "18446744073709551615", "1", true}},
		{"i64", Operand{Signed: true, Bits: []BitSlice{{0, 0, 64}}}, rustOperandDomain{"-9223372036854775808", "9223372036854775807", "1", true}},
		{"wide scaled", Operand{Bits: []BitSlice{{0, 0, 64}}, Scale: 9223372036854775807, Bias: 9223372036854775807}, rustOperandDomain{"9223372036854775807", "170141183460469231713240559642174554112", "9223372036854775807", true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := prepareRustOperandDomain(tc.o); got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestRustOperandDomainIndexWidth(t *testing.T) {
	for _, count := range []int{0, 1, 65535, 65536, 65537, 1000000} {
		want := "u16"
		if count > 65536 {
			want = "u32"
		}
		if got := rustOperandDomainIndexType(count); got != want {
			t.Fatalf("%d domains: %s want %s", count, got, want)
		}
	}
}
