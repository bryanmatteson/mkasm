# MOS 6502 and CMOS 65C02 instruction codec

`Parse` imports the four complete cc65 **V2.19** da65 opcode tables:
`OpcTable_6502`, `OpcTable_6502X`, `OpcTable_65SC02` and `OpcTable_65C02`.
All 1,024 source rows are checked for sequential opcode numbering and complete
documented/invalid coverage. Common forms are merged, producing **361 unique
forms**: 212 documented, 105 undocumented NMOS, and 44 WDC reserved NOP forms.
There are 84 one-byte, 171 two-byte and 106 three-byte forms.

The input is the original four C files concatenated in any order, as retained
in `testdata/opcodes.c`. Source notices remain intact. The canonical architecture
is `mos6502`; `6502`, `6502x`, `65sc02`, `65c02` and `w65c02` also parse the same
complete catalog. Select a named profile for a particular processor:

| Profile | Decodable opcode bytes | Source-defined behavior |
| --- | ---: | --- |
| `6502` | 151 | Documented NMOS instructions |
| `6502x` | 256 | NMOS, including all 105 undocumented encodings |
| `65sc02` | 178 | Original CMOS extensions |
| `65c02` | 210 | Rockwell bit operations and bit branches |
| `w65c02` | 212 | Rockwell forms plus WDC WAI and STP |
| `w65c02+nops` | 256 | WDC instructions plus all reserved NOP frames |

**A profile is necessary to disambiguate NMOS and CMOS encodings.** The generic
unfiltered API admits their union and chooses one matching entry; it cannot
infer a processor from bytes. For example, opcode `12` is NMOS JAM and CMOS
ORA `(zp)`, with different lengths. Use `DecodeWithFeatures`,
`AssembleWithFeatures`, and `ParseTemplateWithFeatures` in Go, or their Rust
equivalents with `profile(name)`. `OpcodeStatus` / `opcode_status` distinguishes
`documented`, `undocumented`, `reserved-nop`, and `invalid` for a chosen profile.

The WDC W65C02S datasheet dated **February 16, 2024** supplies two explicit
corrections/supplements to the assembler tables:

- BRK consumes its second signature byte, as specified in table 4-1 note 5.
  It is represented as `brk #signature`, with a structured `signature` operand.
  Bare `brk` means signature zero. One-byte input containing only `00` is
  truncated. The source da65 table and Ghidra use a one-byte display convention;
  their convention is not substituted for hardware instruction consumption.
- Table 7-1 defines the lengths of every WDC reserved NOP opcode. Their ignored
  bytes are preserved as structured `padding` operands and explicit text when
  present. These forms require `w65c02+nops`; they are not undocumented NMOS
  instructions and do not inherit NMOS addressing modes.

The codec handles all source addressing modes, including accumulator, immediate,
zero page, absolute, indexed, indirect, indexed indirect, indirect indexed, CMOS
zero-page indirect, absolute indexed indirect, relative, and bit branches. A
relative `target` value is a signed byte displacement from the following
instruction; formatted targets and text assembly wrap in the 16-bit address
space. Bit branches use their three-byte instruction length as the PC bias.
Immediate values are unsigned bytes; text also accepts signed byte spellings.

Text accepts `$` hexadecimal and `%` binary literals, optional accumulator
spelling for accumulator instructions, and the ca65 aliases ANE/XAA and SHA/AHX.
When a low address fits both zero-page and absolute forms, assembly returns all
valid byte sequences, ordered by size. Exact `Encode` uses a stable form ID,
such as `lda_a9_Immediate` or `lda_ad_Absolute`. Repeated undocumented NOP/JAM
opcodes likewise remain distinct exact encodings even when their text is equal.

Go `ParseTemplate` / `ParseTemplateWithFeatures` accepts named `${hole}`
operands. `Template.Encode` binds semantic operand values, and `Template.Match`
extracts the same values. Rust exposes `Template::parse_at`,
`Template::parse_with_features`, `encode` and `matches`. Template holes bind raw
semantic displacements for relative operands; fixed numeric branch text uses
absolute targets, just like ordinary assembly.

`ResolveOperand` / `resolve_operand` optionally computes effective addresses
from X, Y and a memory reader. It models 16-bit address wrapping, zero-page
index and pointer wrapping, indexed page crossing, relative page crossing, and
the NMOS JMP-indirect page-boundary behavior. Its processor argument distinguishes
that NMOS behavior from CMOS. This helper performs address arithmetic, not
instruction execution, timing, hidden stack access or undocumented silicon
effects. This family has no bank register; **65816 is not imported**. Its
state-dependent M/X widths and bank semantics need a separate coherent backend;
the pinned da65 65816 table is insufficient for that job.

Validation uses the actual cc65 assembler, linker, disassembler and simulator,
plus installed Ghidra **12.1.2**:

- ca65 matches **282 exact encodings** and selects equivalent canonical opcode
  bytes for **35 redundant undocumented NMOS forms**. Every one of the 317
  non-reserved forms is recognized by da65 and its text reproduces the intended
  bytes through this codec. BRK's signature is emitted as `brk` followed by an
  explicit byte because ca65's BRK syntax emits only the opcode.
- Ghidra matches **209 documented forms** through independent assembly and
  decoding. It displays BRK as one byte and does not support WAI/STP. The 105
  undocumented NMOS and 44 reserved WDC NOP forms are outside its language.
- A 29-instruction, 51-byte CMOS routine computes a sum, calls a subroutine,
  uses stack operations and conditional branches, checks CMOS instructions,
  and exits the real sim65 executable with status zero. The Go and Rust
  consumers decode and re-encode the actual assembled routine and its targets.
- Every imported form has byte/text tests, bounds and truncation checks;
  profile/status, template, malformed input and address-wrap tests are included.
  The generated crate contains the complete retained reference corpus and
  real-routine tests by default, with no dependencies.

Run offline checks with `go test ./pkg/mos6502`. Full external validation uses:

```sh
MKASM_MOS6502_CC65=/path/to/cc65-V2.19/bin \
MKASM_MOS6502_GHIDRA=1 MKASM_MOS6502_RUST=1 \
MKASM_MOS6502_ARTIFACT_DIR=/path/to/artifacts \
go test ./pkg/mos6502 -count=1 -v
```

The Rust consumer uses the normal `cargo test --lib --test consumer` command.
The generated crate preserves cc65's Zlib license notice, the runtime's MIT
notice, and the source references; its SPDX license expression is
`MIT AND Zlib`.
