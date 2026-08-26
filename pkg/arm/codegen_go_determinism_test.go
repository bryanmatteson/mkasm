package arm

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bryanmatteson/mkasm/pkg/ir"
)

func TestEncodeDecodeCorpusGenerationIsIndependentOfInputOrder(t *testing.T) {
	zero, one := uint64(0), uint64(1)
	a := &ir.InstructionIR{
		EncodingID: "A", BitPattern: strings.Repeat("0", 31) + "x",
		Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{
			{Name: "bit", Start: 0, End: 0},
			{Name: "fixed", Start: 1, End: 1, Fixed: &zero},
		}},
	}
	b := &ir.InstructionIR{
		EncodingID: "B", BitPattern: strings.Repeat("0", 30) + "1x",
		Encoding: ir.EncodingMask{Width: 32, Fields: []ir.BitField{
			{Name: "bit", Start: 0, End: 0},
			{Name: "fixed", Start: 1, End: 1, Fixed: &one},
		}},
	}

	forward, reverse := t.TempDir(), t.TempDir()
	if err := writeEncodeDecodeCorpusTest(forward, "aarch64", []*ir.InstructionIR{a, b}); err != nil {
		t.Fatal(err)
	}
	if err := writeEncodeDecodeCorpusTest(reverse, "aarch64", []*ir.InstructionIR{b, a}); err != nil {
		t.Fatal(err)
	}
	forwardSource, err := os.ReadFile(filepath.Join(forward, "roundtrip_corpus_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	reverseSource, err := os.ReadFile(filepath.Join(reverse, "roundtrip_corpus_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(forwardSource, reverseSource) {
		t.Fatal("round-trip corpus depends on input order")
	}
}
