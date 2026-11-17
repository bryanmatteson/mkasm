# SPARC V8/V9 importer

`Parse(reader, architecture)` consumes genuine LLVM `llvm-tblgen --dump-json`
output for `llvm/lib/Target/Sparc/Sparc.td`. Accepted architecture names are
`sparc32` (big endian), `sparc64` (big endian), and `sparc32le` (LLVM's `sparcel`
instruction ordering). It imports machine instructions and declarative
`InstAlias` records rather than substituting a private instruction schema.

The adapter resolves aliases with fixed registers, immediates and tied inputs;
flattens LLVM's memory DAGs into base and displacement/index operands; preserves
signed immediate widths; and uses four-byte-aligned, signed PC-relative byte
displacements for branch/call operands. Text assembly accepts absolute targets
at the supplied address; formatting emits absolute targets. LLVM's numeric
branch-operand convention differs from this architectural byte-offset API.

Integer register windows retain `%gN`, `%oN`, `%lN`, `%iN`, `%sp`, `%fp`, and `%rN`
aliases. Register classes constrain paired integer and coprocessor registers,
privileged and ancillary state registers, FCC registers, and floating-point
registers. V9 D/Q fields are remapped from their encoded bank bit to physical
`%f0` through `%f62` register numbers; alignment is enforced by the class.
V8 profiles reject the V9 upper FP register bank through explicit predicate-bearing
register-bank variants. Condition suffixes use source-family condition tables, with fixed condition
variants for conventional branch/move/trap syntax. Reserved CBcond conditions
are rejected. Annul and prediction modifiers remain in each source syntax and
fixed bit masks. `DelaySlots` preserves LLVM's `hasDelaySlot` metadata.

Source predicates preserve V8/V9, 32/64-bit mode, VIS/VIS2/VIS3, hard quad,
cryptographic, LEON, UA and OSA facilities. Use `Catalog.FeatureSets["v8"]`,
`["v9"]` or `["v9-all"]` with feature-aware codec methods. V8 is available on the
32-bit catalogs; SPARC64 exposes V9 profiles. A nil feature set admits every
imported source facility. This does not model privileged execution or register
window rotation; the structured register values identify the instruction's
architectural window-relative registers.

## Source coverage and validation

`testdata/llvm22-sparc.json` retains 21 real source instructions, 217 aliases,
and their operand/register records; its upstream license is included. The full
LLVM 22.1.8 source corpus is exercised with:

```sh
SPARC_TABLEGEN_JSON=/path/to/sparc.json \
SPARC_LLVM_PARITY=1 \
SPARC_REPORT_DIR=/path/to/artifacts \
go test ./pkg/sparc -v
```

`LLVM_MC` overrides the Homebrew `llvm-mc` executable path. The full corpus test
checks three register/immediate samples for every emitted encoding through byte
decode/re-encode and format/text assembly. Its oracle assembles every emitted
form into a separate ELF section and compares the actual section bytes. Local
symbolic labels make branch/call targets independently resolvable; they also
avoid an LLVM 22.1.8 crash on numeric `call` operands. Oracle-rejected forms are
reported by ID and text rather than counted as independent parity passes.

The complete dump currently emits 2,528 forms for each SPARC32 byte order and
3,091 SPARC64 forms. Every emitted form recognized by LLVM is checked: 2,494
forms per SPARC32 byte order and all 3,091 SPARC64 forms. LLVM's 32-bit assembler
rejects 34 forms involving `%asi` addressing or quad register-conditional moves;
those source encodings remain available with their original predicates and are
covered by the exhaustive model round trips. Their exact IDs/text are retained
in the oracle report.

Seven SPARC32 and nine SPARC64 asm-parser-only records are explicitly reported
as unsupported because their extra operands carry ABI argument counts or
relocation metadata without instruction bits (`CALLi`, indirect CALL count
variants, and TLS/GOT relocation variants). Their ordinary instruction-byte
forms are imported separately. This fixed-instruction codec does not create
relocations, link symbols, or expand multi-instruction assembler macros. Real
LLVM pseudo instructions and aliases targeting them are outside the machine
instruction catalog.
