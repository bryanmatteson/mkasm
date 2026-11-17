# W65C816 instruction codec

`Parse(reader, "w65c816")` imports cc65 V2.19's complete
`OpcTable_65816[256]` from `opc65816.c`. The canonical CLI target is `w65c816`;
`65816`, `65c816` and `w65816` are CLI aliases. The input must contain the complete
ordered table; missing, duplicate or reordered opcode rows are errors.
The catalog uses the shared Go and generated dependency-free Rust runtime for
exact encoding, decoding, formatting, text assembly, structured operands,
templates, operand spans/domains, edits, positions and relocation.

## Execution context and addresses

Every one-byte opcode is represented. Immediate framing depends on the actual
E/M/X state: M selects accumulator immediate width and X selects index immediate
width. Emulation forces both widths to eight bits. Use `DecodeWithContext` and
`AssembleWithContext` in Go, or `decode_with_context` and
`assemble_with_context` in generated Rust:

```go
c, err := w65c816.Parse(source, "w65c816")
if err != nil { panic(err) }
ctx := w65c816.ExecutionContext{
    PC: 0x12fffe, Emulation: false, Accumulator8: false, Index8: true,
}
d, err := c.DecodeWithContext([]byte{0xa9, 0x34, 0x12}, ctx)
if err != nil { panic(err) }
// LDA's immediate occupies two bytes because M=0; d.Length == 3.
next, err := ctx.Next(d)
_, _ = next, err
```

`Profile()` selects `m8x8`, `m8x16`, `m16x8` or `m16x16`; `emulation` selects
`m8x8`. These profiles are also available through the shared feature APIs and
`--cpu`. Default Go `Decode` uses emulation framing. The unfiltered catalog is a
union of width variants, so context must be selected when walking native code.

`ExecutionContext.Next` advances the sequential PC within its 64 KiB program
bank and tracks REP/SEP changes to M/X. It rejects PLP, RTI and XCE because their
next status depends on runtime state; supply the actual next context. This is
sequential framing support, not execution or control-flow following. Use decoded
branch targets to follow explicit control transfers.

Relative branches wrap within PBR, and 16-bit direct jumps retain PBR. Long
direct addresses carry all 24 bits. Relocation rejects targets outside the
selected form's bank/range instead of silently changing an instruction.
Encoded data-address fields remain offsets: effective data addresses can also
require DBR, D, index registers and memory. The codec does not simulate those
registers or infer E/M/X after arbitrary control flow.

BRK, COP and WDM consume their signature byte and are two bytes long. Long
addressing instructions such as JSL consume four bytes. These framing facts
follow WDC's W65C816S datasheet (2024-03-13, tables 5-1 and 5-7), correcting
historical da65 display-table lengths. PEI and absolute-indirect-long operand
classes are preserved separately.

## Generation and validation

```sh
mkasm --arch w65c816 --codegen rust --output ./w65c816-rs ./opc65816.c
mkasm --arch w65c816 --cpu m16x8 --json ./opc65816.c > w65c816-ir.json
go test ./pkg/w65c816
MKASM_MOS6502_CC65=/absolute/cc65/bin go test ./pkg/w65c816 -run TestCC65FullCorpusOracle -v
```

The self-contained corpus tests decode and exactly reencode all 256 opcodes in
each of the four M/X contexts, and check text assembly candidates. Context tests
cover REP/SEP, signature-byte and long-address lengths, bank wrapping and
rejected cross-bank relocation. Generated Rust retains public context APIs and
consumer tests alongside the shared catalog tests.

The native ca65/ld65 oracle covers 1,024 opcode/context cases. WDM is a reserved
escape absent from ca65's mnemonic table, so its case uses explicit bytes
`$42,$21`, with framing established separately from the WDC reference. The other
cases use ca65 instruction assembly. This distinction keeps the assembler's
actual scope visible; the case count does not imply independent mnemonic
assembly of WDM or execution testing.

The pinned cc65 source and Zlib notice are retained in `testdata/opc65816.c` and
`testdata/CC65-LICENSE`. Generated runtime code uses MIT; upstream source notices
remain separate. This backend inspects and edits instructions; it does not
provide a CPU emulator, linker, or automatic status-state analysis.
