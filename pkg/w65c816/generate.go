package w65c816

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed context.rs
var contextRuntime string

func (c *Catalog) GenerateRust(output string) error {
	if e := c.Catalog.GenerateRust(output); e != nil {
		return e
	}
	p := filepath.Join(output, "src/lib.rs")
	b, e := os.ReadFile(p)
	if e != nil {
		return e
	}
	if e = os.WriteFile(p, append(b, contextRuntime...), 0644); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(output, "README.md"), []byte(readme), 0644)
}

const readme = `# W65C816

The complete cc65 V2.19 256-opcode table, with physical BRK/JSL framing,
long indirect jumps and block move fields corrected against ca65 and the WDC
W65C816S reference dated March 13, 2024. All four M/X width profiles are emitted.
The opcode source and Zlib notice are retained with the importer.

Use decode_with_context and assemble_with_context with the actual E/M/X state.
Generic decode_with_features and templates accept profile("m8x8"), "m8x16",
"m16x8", "m16x16" or "emulation". The unfiltered catalog is a union of widths.
Instruction-relative branches wrap within PBR; 16-bit direct jumps retain PBR.
Long direct addresses carry all 24 bits. Encoded data-address fields retain
their offsets; effective data addresses require DBR, D, registers and memory.
ExecutionContext::next tracks REP/SEP and sequential PC wrapping. PLP, RTI and
XCE require the actual next state rather than an inferred linear decode.

All shared exact encoding, assembly, templates, spans, domains, positions,
editing, relocation, effects metadata and explicit object assembler APIs are
available. Decoding an opcode does not imply emulating its runtime effects.
`
