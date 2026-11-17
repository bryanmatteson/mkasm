package semantics

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestRustArm64ScalableEnhancedBFloat(t *testing.T) {
	path := filepath.Join("..", "..", "..", "binary-toolkit", "crates", "isa", "core", "src", "floating_point", "bfloat16.rs")
	native, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("native BF16 consumer checkout unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/arm64_scalable_bfloat.rs")
	if err != nil {
		t.Fatal(err)
	}
	// Recheck the committed numerical witnesses with an independent exact-
	// rational oracle, so the shared generated fixture is not a kernel snapshot.
	block := strings.Index(string(fixture), "const CASES:")
	if block < 0 {
		t.Fatal("missing BF16 numerical witnesses")
	}
	numbers := regexp.MustCompile(`0x[0-9a-f]+`).FindAllString(string(fixture)[block:], -1)
	if len(numbers) != 45*9 {
		t.Fatalf("got %d BF16 witness fields", len(numbers))
	}
	for i := 0; i < len(numbers); i += 9 {
		var v [9]uint32
		for j := range v {
			n, err := strconv.ParseUint(numbers[i+j], 0, 32)
			if err != nil {
				t.Fatal(err)
			}
			v[j] = uint32(n)
		}
		if v[0]&(1<<13) == 0 {
			continue
		}
		dot := func(acc uint32, negative bool) uint32 {
			a, b := uint16(v[2]), uint16(v[3])
			if negative {
				a ^= 0x8000
				b ^= 0x8000
			}
			return bfEnhanced(acc, a, b, uint16(v[4]), uint16(v[5]), v[0])
		}
		expected := [3]uint32{dot(v[1], false), dot(v[1], true), dot(dot(v[1], false), false)}
		for j, want := range expected {
			if v[6+j] != want {
				t.Fatalf("BF16 witness%d projection%d got%08x want%08x", i/9, j, v[6+j], want)
			}
		}
	}

	source := "#[allow(dead_code)]#[path=\"runtime.rs\"]mod semantics;\n" + string(fixture)
	nativeText := strings.ReplaceAll(string(native), "crate::", "crate::native_contract::")
	runBFloatRust(t, source, map[string]string{"native_bfloat.rs": nativeText})
}
