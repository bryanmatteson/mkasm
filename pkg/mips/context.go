package mips

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bryanmatteson/mkasm/pkg/codec"
)

// Catalog retains the shared instruction codec and adds explicit MIPS16
// execution-PC context. Ordinary APIs keep their normal-instruction semantics.
type Catalog struct{ *codec.Catalog }

// ExecutionContext supplies architectural state that cannot be recovered from
// isolated instruction bytes. PCBase is the executing JAL/JALX or JR/JALR
// address for a MIPS16 PC-relative data operation in its delay slot; otherwise
// it is InstructionAddress. Both are physical byte addresses without ISA bits.
type ExecutionContext struct {
	InstructionAddress uint64
	PCBase             uint64
}

func mips16DataPC(e *codec.Encoding, o codec.Operand) bool {
	return has(e.Features, "InMips16Mode") && o.Relative && o.PCAlignBits > 0 && o.PCRegionBits == 0
}

func contextEncoding(e *codec.Encoding, context ExecutionContext) codec.Encoding {
	bound := *e
	bound.Operands = append([]codec.Operand(nil), e.Operands...)
	for i := range bound.Operands {
		if mips16DataPC(e, bound.Operands[i]) {
			bound.Operands[i].PCPreAlignBias += int64(context.PCBase - context.InstructionAddress)
		}
	}
	return bound
}

func contextualDecoded(d *codec.Decoded, context ExecutionContext) *codec.Decoded {
	bound := contextEncoding(d.Encoding, context)
	return &codec.Decoded{Encoding: &bound, Values: d.Values, Length: d.Length}
}

func (c *Catalog) FormatWithContext(d *codec.Decoded, context ExecutionContext) string {
	return contextualDecoded(d, context).Format(context.InstructionAddress)
}

func (c *Catalog) DescribeWithContext(d *codec.Decoded, context ExecutionContext) codec.Described {
	return contextualDecoded(d, context).Describe(context.InstructionAddress)
}

func (c *Catalog) AddressReferencesWithContext(d *codec.Decoded, context ExecutionContext) []codec.AddressReference {
	return contextualDecoded(d, context).AddressReferences(context.InstructionAddress)
}

func (c *Catalog) RewriteReferenceWithContext(d *codec.Decoded, context ExecutionContext, operandIndex int, target uint64, output []byte) (int, error) {
	return contextualDecoded(d, context).RewriteReference(context.InstructionAddress, operandIndex, target, output)
}

func (c *Catalog) AssembleWithContext(text string, context ExecutionContext, features []string) ([][]byte, error) {
	var out [][]byte
	seen := map[string]bool{}
	for i := range c.Encodings {
		e := &c.Encodings[i]
		active := true
		if features != nil {
			for _, f := range e.Features {
				if !has(features, f) {
					active = false
					break
				}
			}
		}
		if !active {
			continue
		}
		bound := contextEncoding(e, context)
		values, ok := codec.ParseOperands(&bound, text, context.InstructionAddress)
		if !ok {
			continue
		}
		b, err := codec.Encode(&bound, values)
		if err != nil || seen[string(b)] {
			continue
		}
		seen[string(b)] = true
		out = append(out, b)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no encoding for %q", text)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) < len(out[j]) })
	return out, nil
}

//go:embed context.rs.tmpl
var rustContext []byte

//go:embed testdata/context-consumer.rs
var rustContextConsumer string

func (c *Catalog) GenerateRust(output string) error {
	if err := c.Catalog.GenerateRust(output); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(output, "src", "execution_context.rs"), rustContext, 0644); err != nil {
		return err
	}
	if strings.HasPrefix(c.Architecture, "mips16") {
		consumer := strings.ReplaceAll(rustContextConsumer, "__CRATE__", strings.ReplaceAll(c.Architecture, "-", "_"))
		if err := os.WriteFile(filepath.Join(output, "tests", "execution_context.rs"), []byte(consumer), 0644); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(filepath.Join(output, "src", "lib.rs"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString("\npub mod execution_context;\npub use execution_context::{ExecutionContext, assemble_with_context};\n")
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}
