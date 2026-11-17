package codec

import (
	"math/rand"
	"strings"
	"testing"
)

func TestRustLiteralFingerprintHasNoFalseNegatives(t *testing.T) {
	rng := rand.New(rand.NewSource(71912))
	operands := []Operand{{Name: "x"}, {Name: "y"}, {Name: "π"}}
	for _, pattern := range []string{"", "save{frame},$ra,$s0-$s8", "{x}=add({y},#{π})", "{{literal}}{x}{{π}}", "op{x}{y}end", "éİπ{x}long"} {
		for n := 0; n < 100; n++ {
			e := Encoding{Syntax: pattern, Operands: operands}
			s := prepareRustSyntax(e)
			// Reproduce literal matching, with arbitrary inserted operand bytes. This
			// includes UTF-8, escaped braces, and holes adjacent to other holes.
			var text strings.Builder
			for i := 0; i < len(s.Pattern); i++ {
				c := s.Pattern[i]
				if c == 255 {
					i++
					if s.Pattern[i] == 255 {
						i += 4
					}
					for j := rng.Intn(20); j > 0; j-- {
						text.WriteByte(byte(32 + rng.Intn(95)))
					}
					continue
				}
				if c == 1 {
					c = '{'
				} else if c == 2 {
					c = '}'
				}
				text.WriteByte(c)
			}
			required := rustLiteralFingerprint(s.Pattern)
			actual := rustLiteralFingerprint([]byte(text.String()))
			// Random operand bytes cannot contain 0xff, so they form a literal program.
			if actual&required != required {
				t.Fatalf("%q fingerprint rejected matching %q", pattern, text.String())
			}
		}
	}
	wide := make([]Operand, 257)
	wide[256].Name = "wide"
	p := rustMatchProgram("begin{wide}end", wide)
	want := rustLiteralFingerprint([]byte("begin")) | rustLiteralFingerprint([]byte("end"))
	if got := rustLiteralFingerprint(p); got != want {
		t.Fatalf("wide operand program mask %x want %x", got, want)
	}
}
