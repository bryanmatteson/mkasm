# MIPS instruction codecs

`Parse(reader, architecture)` imports a resolved LLVM `llvm-tblgen --dump-json`
MIPS description and returns `*mips.Catalog`, which embeds `*codec.Catalog`.
MIPS16 catalogs also import every non-macro machine row from the retained GNU
binutils 2.44 opcode table. The microMIPS64 catalogs additionally import all 85
non-macro 64-bit-only rows from GNU's microMIPS table, which LLVM's microMIPS
backend omits. These include 64-bit arithmetic, shifts, bitfields, memory and
coprocessor operations, with native operand descriptors and feature predicates.

| Architecture names | Physical framing | Address arithmetic |
| --- | --- | --- |
| `mips32`, `mips32el` | Four-byte standard MIPS | 32 bits |
| `mips64`, `mips64el` | Four-byte standard MIPS | 64 bits |
| `micromips32`, `micromips32el` | Two- and four-byte microMIPS | 32 bits |
| `micromips64`, `micromips64el` | Two- and four-byte microMIPS | 64 bits |
| `mips16`, `mips16el` | Two-byte MIPS16 and four-byte EXTEND/JAL | 32 bits |
| `mips16-64`, `mips16-64el` | Two-byte MIPS16 and four-byte EXTEND/JAL | 64 bits |

Names ending in `el` use little endian byte order. Compressed instructions keep
halfwords in stream order: little endian does not reverse an entire four-byte
instruction. Decode does not infer execution-mode switches from bytes. The
caller selects the mode in which the instructions execute. A `64` name selects
64-bit address arithmetic; ISA extensions remain separately feature gated.

The embedded shared catalog supplies structured encoding/decoding, text assembly,
templates, operand domains, effects, control flow, address references and Rust
source generation. Relative structured operands are byte displacements or
PC-region fragments; their text uses absolute physical targets. GNU spellings
that explicitly print `$pc` retain their immediate-displacement convention.
Decoded MIPS16 PC-relative data operations prefer GNU's address spellings.
Code addresses omit the MIPS16 ISA marker bit. JAL/JALX use a four-byte instruction,
a word-scaled 26-bit fragment and a 28-bit PC region, with one separate delay
slot. Assembly of an individual transfer does not append or fill its delay slot.

Operand reconstruction includes compact/full register maps, register pairs and
lists, signed index/offset fields, non-linear microMIPS immediates, the LBU16
`-1` sentinel, MIPS16 EXTEND fields, SAVE/RESTORE frame and register lists,
ENTRY/EXIT lists, 64-bit MIPS16 arithmetic, MIPS16e2 bitfields, MT operations and
InterAptiv COPYW/UCOPYW. The GNU importer covers all 221 non-macro opcode rows and
59 real operand descriptors. It retains the original row numbers in encoding
IDs, even when a row expands into multiple fixed register-list configurations.
Reserved list masks, overlapping saved argument lists, out-of-range frames and
invalid bitfield position/size combinations are rejected.

Ignored EXTEND payload bits have an explicit `encoding_bits:N` spelling when
nonzero, preserving exact bytes and instruction length. MIPS16e2 reserves some
bits ignored by older MIPS16 implementations. Those legacy exact forms require
`NotMips16e2`, derived from GNU's preceding MIPS16e2 `SHORT_ONLY` override. With
MIPS16e2 selected, a rejected extended form can decode as the source-defined
standalone two-byte `extend` instruction. This is an ISA-dependent framing rule.

The importer corrects five LLVM 22 microMIPS DSP fixed layouts against GNU:
the three `CMPGU` forms and the two `SHLLV.PH` forms. Independent GNU boundary
tests check Go, actual CLI generation and fresh Rust consumers in all four
microMIPS selectors. See [reference testing](../../docs/reference-testing.md)
for the live tools, coverage counts and explicit oracle limits.

LLVM predicate names are retained as positive feature requirements. Unfiltered
methods admit the union of imported extensions, including conflicting revisions.
Use `DecodeWithFeatures` and `AssembleWithFeatures` with a complete set of positive
predicate names. There is no CPU-name implication table. GNU forms require
`InMips16Mode` and, where specified by their actual rows, `HasMips3`, `HasMips32`,
`HasMips64`, `HasMips16e2`, `HasMips16e2MT` or `HasInterAptivMR2`. `NotMips16e2`
must be supplied explicitly for the affected legacy ignored-bit forms. Selecting
a 64-bit address mode does not itself imply any of those feature names.

Source read/write flags and known implicit registers are retained as partial
effect metadata. GNU's opcode rows do not establish complete memory, register-list
or flag effects; absent facts remain unknown. The GNU microMIPS64 rows retain
explicit load/store flags as well as source register/HI/LO effects. LLVM MIPS16 layout defects that
would shadow real GNU instructions are corrected against the retained machine
rows, including extended branches, selected loads, SP-relative register placement,
compact jumps, NEG, variable-shift operand placement and word-shift widths.

For the complete LLVM 22.1.8 dump, the current catalogs contain 1,311 standard
MIPS32 forms, 1,527 standard MIPS64 forms, 871 microMIPS32 forms, 956 microMIPS64
forms, and 3,652 MIPS16
forms per address mode/byte order. Counts include machine aliases, exact ignored
fields and fixed register-list configurations. The three reported standard-mode
exclusions are malformed upstream aliases (`sub,`, `subu,` and the literal
`$$rs` in `sgtu`). Pseudo instructions, GNU macros and parser-only records are
not machine encodings. Records from other execution modes are filtered.

## Explicit MIPS16 execution PC

The PC base for an unextended MIPS16 PC-relative load/add in a JAL/JALX or
JR/JALR delay slot is the transfer instruction's address. Isolated instruction
bytes cannot establish that history. The normal shared APIs use the instruction's
own address; callers with execution context use:

```go
context := mips.ExecutionContext{
    InstructionAddress: 0x1006, // two-byte data instruction after a four-byte JAL
    PCBase:             0x1002, // actual executing transfer's address
}
text := catalog.FormatWithContext(decoded, context)
choices, err := catalog.AssembleWithContext(text, context, nil)
```

`DescribeWithContext`, `AddressReferencesWithContext` and
`RewriteReferenceWithContext` retain the same base in operand positions and
relocation. For ordinary instructions, set both context addresses to the
instruction address. Extended PC-relative data instructions cannot be used as
architectural delay-slot instructions; their normal PC base is their own address.
The context API supplies address calculation, not delay-slot legality checking,
scheduling or history inference. It does not change a transfer's own code target.
Address wrapping follows the selected 32- or 64-bit mode.

Generated Rust exposes `ExecutionContext`, `assemble_with_context` and
`Decoded::{format_with_context,describe_with_context,address_references_with_context,
rewrite_reference_with_context}` with equivalent behavior. Generation installs
`tests/execution_context.rs` for all four MIPS16 names, exercising only the public
crate API, delay-slot bases, descriptions, references, rewriting and address wraps.

There is no GNU macro expansion, object relocation resolution, instruction
scheduling, execution or link-time mode conversion. An empty `Unsupported` list
means the selected machine source records imported successfully; it does not
establish behavior for undocumented hardware outside the pinned sources.

LLVM 22.1.8 is pinned to `ca7933e47d3a3451d81e72ac174dcb5aa28b59d1` and licensed
Apache-2.0 WITH LLVM-exception. GNU binutils 2.44 definitions and copied GNU gas
corpora are GPL-3.0-or-later. Original notices and `testdata/COPYING3` are retained;
catalog and generated Rust output carry the combined license. See
[testdata/README.md](testdata/README.md) for source generation and actual tool tests.
