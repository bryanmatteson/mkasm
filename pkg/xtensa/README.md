# Xtensa instruction and FLIX codecs

This backend reads the complete resolved LLVM 22.1.8 Xtensa `--dump-json`
corpus and supplements it with GNU binutils 2.44's real Xtensa configuration.
The pinned input fixture retains all 284 LLVM physical records and 10 assembly
aliases. The GNU configuration describes 530 opcode names across five formats;
690 opcode/slot combinations include 184 FLIX slot forms. Shared mnemonics use
the LLVM operand model, with architecture constraints checked against GNU gas.
Special/user register alternatives expand into feature-specific forms.

`Parse(reader, "xtensa")` selects little endian; `"xtensaeb"` selects big endian.
The bundled scalar framing is 16 or 24 bits, selected by the architectural
opcode prefix.
The GNU little-endian configuration also defines two eight-byte FLIX formats,
containing three and two slots. `Decode`, `Encode`, `Format`, and `Assemble`
operate on complete scalar instructions or bundles. Bundle text uses braces
and semicolon-separated slots, for example `{ add a2,a3,a4; nop; nop }`.
Each decoded instruction keeps a stable encoding ID and semantic operand map.
Byte consumption is reported as `Decoded.Length`.

`Parse` also accepts a resolved `mkasm.xtensa.v1` processor configuration written
by `WriteJSON`. It validates scalar and TIE encoding fields, format masks and
values, unique format/encoding names, slot ownership, complete physical bit
coverage and unambiguous framing. Supplied formats may be 1–256 bytes long;
they are not restricted to the bundled eight-byte FLIX layouts. Byte order and
slot placement must be explicitly described. Both endian targets can load a
matching validated configuration; reversing another processor's bytes does not
construct that description.

```sh
mkasm --arch xtensa --codegen rust --output ./processor-rs ./processor.json
mkasm --arch xtensaeb --json ./processor-big-endian.json > processor-ir.json
```

Registers denote the visible architectural window (`a0` through `a15`), with
`sp` accepted for `a1`; the codec does not translate through runtime WINDOWBASE.
The model includes floating, boolean, MAC16 and sparse special/user registers,
nonlinear immediate tables, scaled and signed offsets, call window variants,
flow classifications, source feature predicates, and CPU profiles `generic`,
`esp32`, and `esp8266`. `all` admits the imported extension union and `gnu-config`
selects the supplemental configuration. `WithCPU(name)` returns a selected copy
of both scalar and bundle tables for CLI generation. A nil feature filter accepts the union;
a nonnil empty filter selects the base ISA. Special-register read/write/exchange
permissions and timer/interrupt level alternatives are preserved from LLVM.
GNU-only register forms retain their configuration predicate.

Relative operand values are byte displacements. Text accepts absolute targets,
using PC+4 for branches and loops, `(PC & ~3)+4` for calls, and
`(PC+3)&~3` for backward literal loads. Targets wrap in the 32-bit address space.
Literal load offsets are always negative and word aligned. The ordinary APIs
use PC-relative literal addressing. Supply `ExecutionContext{PC, LITBASE}` to
`FormatWithContext`, `AssembleWithContext` or `RelocateWithContext` when literal
addressing depends on runtime state. If LITBASE bit zero is set, L32R uses
`LITBASE & 0xfffff000` plus the negative scaled displacement. Relocation can
preserve a target across changes in both PC and LITBASE, rejecting destinations
outside the representable region. The generated Rust context APIs provide the
same behavior. Numeric lookup
operands include signed/unsigned branch constants, MOVI.N and compact ADDI.N.
Illegal boolean groups, field alignment, zero-length shifts and EXTUI field
spans are rejected.

`GenerateRust` emits a standalone dependency-free crate. Public `decode` returns
`Decoded { format, instructions, length }`; `Decoded::encode` reconstructs complete
bytes and `Decoded::format(address)` prints text. `assemble_at` and feature-aware
variants handle scalar and bundle text. `Template::parse_at` compiles fixed text,
`$name` operand bindings and `_` wildcards across complete bundles, including
repeated bindings across slots. The explicitly named `DecodedField`,
`decode_field`, `FieldTemplate`, and `encode` APIs expose underlying source fields;
a FLIX slot encoded alone is not a complete instruction. `ENCODINGS`, `profile`,
`FEATURE_SETS`, and `UNSUPPORTED` expose metadata. Generated tests exercise every
field form and every FLIX slot in a complete bundle.

The codec validates framing, legal slot membership, operand domains, register
access predicates and represented cross-operand constraints. It does not execute
instructions, schedule slots, prove all pipeline/resource/register hazards,
resolve object relocations, synthesize literal pools, or lower compiler pseudos.
The caller supplies runtime LITBASE state and any additional TIE/designer
CUST0/CUST1 physical descriptions. Proprietary meanings cannot be recovered
from opcode numbers alone. The bundled GNU FLIX layout is little endian;
big-endian FLIX requires a matching supplied configuration. Configuration
validation establishes framing and represented operand constraints, not every
processor's scheduling rules. Coverage of supplied physical source corpora does
not establish coverage of every configurable Xtensa processor or proprietary
extension.

The LLVM input is Apache-2.0 WITH LLVM-exception. GNU configuration data retains
its GPL-2.0-or-later notice; `testdata/extract-gnu.c` reproduces the factual encoding
and numeric operand tables from binutils. Ghidra's Apache-2.0 format definitions
supply initial big-endian field layouts. Live GNU/QEMU vendor field functions
validate the corrected Boolean/loop and user-register layouts. Upstream notices are retained in
`testdata/LICENSE-*` and emitted with the crate. The generated runtime implementation
uses the MIT license in `LICENSE`.

Run `go test ./pkg/xtensa`. Optional source/consumer evidence uses
`XTENSA_SOURCE`, `XTENSA_ARTIFACTS`, and `XTENSA_RUST_OUTPUT`; see corpus tests.
`testdata/validate-asm.py` assembles retained cases with GNU gas and checks ELF
section bytes. `testdata/validate-ghidra.py` checks both byte orders through the
repository's Ghidra oracle, adapting only documented source text dialects.

`TestIndependentAssemblerCorpus` requires a native byte match for all 4,158
physical operand samples (2,355 LE and 1,803 BE), then exercises Go and both
fresh CLI-generated Rust crates. GNU runs with explicit LE and BE dynamic
processor configurations; ELF headers must identify the correct byte order.
Ghidra disagreements cannot satisfy a byte match and need coverage from another
reference. The BE QEMU configuration has no floating-point extension. Optional
BE formats therefore combine actual LLVM/GNU LE instruction selection with the
unmodified vendor-generated BE field functions. This validates their physical
layout; it does not establish native execution on that QEMU core.

Build these native adapters from explicit source inputs with
`scripts/build-xtensa-reference.py --binutils-source /path/to/binutils-2.44
--qemu-be-core /path/to/qemu/target/xtensa/core-test_kc705_be
--output /path/to/xtensa-reference`. The QEMU core's generated source retains
Tensilica's MIT notice. The adapter embeds no copied opcode or field tables.
See `docs/reference-testing.md` for the corresponding environment variables.

Configuration tests exercise supplied little- and big-endian descriptions,
non-bundled packet lengths, JSON round trips and rejected overlapping or
incomplete layouts. LITBASE tests cover formatting, assembly and relocation
across PC/base changes. These checks are distinct from native GNU/Ghidra oracle
coverage of the bundled source configurations.
