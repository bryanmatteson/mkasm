# ARC source importer

`Parse(io.Reader, architecture)` returns the shared `codec.Catalog`. It accepts
LLVM's original `llvm-tblgen --dump-json` output or a GNU binutils source
tar/tar.gz containing `arc-tbl.h`, `arc-opc.c`, and `arc-fxi.h`. `ParseGNU`
explicitly selects the GNU format. GNU input provides the broader specification
and CPU distinctions. The importer reads C opcode tables, symbolic operand and
flag definitions, and insertion functions; importing does not invoke a compiler.

| GNU architecture | Source-selected CPU |
| --- | --- |
| `arc600` | ARC600 |
| `arc700` | ARC700 |
| `arcem` | ARCv2 EM, including source-provided Quark SE extensions |
| `arc32`, `archs` | ARCv2 HS |
| `arcv3-32` | ARCv3 32-bit, GNU hs5x |
| `arc64` | ARCv3 64-bit, GNU hs6x |
| `arcnps400` | ARC700 core plus NPS400 vendor instructions |

Append `be` to any GNU architecture for big endian. `arc` and `arcv2` alias
`arc32`; `arceb` aliases `arc32be`. LLVM input supports `arc32` and `arc32be`
and describes a smaller union without the complete GNU CPU distinctions.

The instruction codec covers 16/32-bit core opcodes, 48/64-bit NPS400 opcodes,
32-bit inline immediates, and ARC's halfword ordering within little endian
instructions. Operand support includes compact register banks, split registers,
register aliases and exclusions, numeric auxiliary registers, signed/aligned
immediates, lookup and biased immediates, duplicated long immediates, NPS bit
positions and correlated fields, condition/update/cache/size/address suffixes,
branch prediction, delay slots, loop/system instructions, and enter/leave lists.
ARC64 long compact branches use signed 34-bit byte displacements in 32 inline
bits, scaled by four. Acquire/release flags share a source-defined bit; an
absent optional suffix does not erase another suffix's value.

PC-relative operands calculate from `PCL = instruction_address & ~3`. They use
32-bit wrapping for the 32-bit CPUs and 64-bit wrapping for ARC64. The shared Go
and generated Rust runtimes use the same position metadata for branch targets,
formatting, assembly, and fixed/open templates, including halfword addresses.
`base` and `all` feature sets select source instruction subclasses after CPU
selection. Generated Rust exposes the shared public encoder, decoder, formatter,
text assembler, and structured `Template` APIs.

## Source preparation

The literal binutils 2.44 core tables import directly. ARCv3 and the separate
NPS400/extension tables contain C macros, so resolve those tables first:

```
python3 scripts/export-arc64.py PINNED_ARCV3_SOURCE arcv3-resolved.tar.gz
python3 scripts/export-arc-nps400.py BINUTILS_244_SOURCE binutils244-nps400.tar.gz
```

The ARCv3 source is the GNU ARC64 branch at commit
`e3f952f340d16cbee94277d023273a42b47b6648`. Its 4,289 expanded C opcode rows
include both ARCv3 CPUs. The exporter checks that complete row count, retains
the original macro inputs and source notices, and resolves integer expressions
with a restricted AST interpreter. The NPS exporter resolves all 352 vendor
rows and all 58 Quark SE extension rows from binutils 2.44; the extension rows
select ARC EM, rather than NPS400. Both exporters retain symbolic operand/flag
names, the upstream GPL license, and a `SOURCE-PIN` file. Their tar and gzip
headers are deterministic. They use the C preprocessor during export; consumers
need no C toolchain. Archives containing unresolved vendor/extension macros
fail explicitly instead of importing only their literal rows.

The retained test fixtures are `testdata/arcv3-resolved.tar.gz`,
`testdata/binutils244-nps400.tar.gz`, the smaller literal GNU core archive, and
unmodified LLVM 22.1.8 records. LLVM notices are in `testdata/LICENSE-LLVM`;
GNU archives retain `COPYING3`. The ARCv3 archive also retains the
unmodified macro input files as `UPSTREAM-*` members. The importer ignores these
additional members. GNU source metadata's GPL-3.0-or-later license is retained
in generated `UPSTREAM-LICENSE`; the shared generated runtime is MIT licensed.

## Coverage and checks

Run the self-contained tests and static checks with:

```
go test ./pkg/arc -count=1
go vet ./pkg/arc
```

The default suite exercises every expanded ARCv3 and NPS400 form with three
value samples through encoding, per-form decoding, formatting, and assembly.
It additionally checks all 58 Quark SE source expansions, union decoding of
NPS 48/64-bit instructions, truncation, exact acquire/release and `wkup`
images, ARC64 register exclusions, both LIMM34 limits, alignment, and 64-bit
PC wrap. Union checks append a following instruction to verify consumption.

Expanded forms include suffix aliases, compact register banks, prediction
directions, and register-list combinations. They are not counts of distinct
machine instructions. Every selected row in these pinned inputs imports with
zero unsupported records:

| CPU / source | Selected source rows | Mnemonics | Expanded forms per endian |
| --- | ---: | ---: | ---: |
| ARC600 / binutils 2.44 core | 1,884 | 175 | 32,105 |
| ARC700 / binutils 2.44 core | 2,126 | 198 | 37,477 |
| ARCv2 EM / binutils 2.44 core | 4,795 | 369 | 73,281 |
| ARCv2 HS / binutils 2.44 core | 4,731 | 376 | 68,174 |
| ARCv3 32-bit / pinned ARC64 branch | 2,316 | 224 | 33,947 |
| ARCv3 64-bit / pinned ARC64 branch | 4,218 | 500 | 62,646 |
| NPS400 plus ARC700 / binutils 2.44 | 2,478 | 305 | 38,104 |

The older core figures exclude the separate Quark SE extension table. All
422,074 core forms across both endians have 1,266,222 compiled-binutils
insertion comparisons, with zero mismatches. The six ARCv3/NPS400 profiles
contain 269,394 expanded forms and have 808,182 such comparisons, also with
zero mismatches. Three samples include zero/ordinary values and a register or
immediate boundary. LLVM's 438 real records expand to 1,549 forms per endian,
with no unresolved records.

GNU assembler comparisons use actual ELF section bytes and distinguish exact
images, equivalent alternate images accepted by the catalog, and rejections:

| Profile | Exact images | Alternate images | Rejected by assembler | Mismatches |
| --- | ---: | ---: | ---: | ---: |
| ARC64 little endian | 48,930 | 11,923 | 1,793 | 0 |
| ARCv3 32-bit little endian | 32,023 | 966 | 958 | 0 |
| NPS400 little endian | 28,064 | 826 | 9,214 | 0 |
| NPS400 big endian | 28,064 | 826 | 9,214 | 0 |

These are source-form checks, so alternate aliases can produce the same ELF
bytes. GNU's ARCv3 assembler has no big-endian option; its big-endian codec
coverage comes from compiled upstream insertion functions, not assembler
acceptance. The assembler also rejects some defined forms, including the
large numeric `bl_s` LIMM34 cases exercised by the independent insertion
oracle. GNU 2.44 confuses the `nt` condition suffix with prediction and can
crash; those forms are excluded from assembler execution and reported as
rejections. LLVM 22.1.8 has an ARC disassembler but no working ARC assembler.

For an independent full-source rerun, set `ARC_GNU_SOURCE` to an original core
or resolved complete source archive and `ARC_MODES` to comma-separated CPU
names, for example `arc64,arc64be,arcv3-32,arcv3-32be` or
`arcnps400,arcnps400be`. `ARC_TABLEGEN_JSON` selects a complete LLVM dump.
`ARC_GAS` selects GNU `gas/as-new`; `ARC_REPORT_DIR` retains unsupported rows,
comparison results, source, and real ELF objects. `ARC_GENERATE_NATIVE` emits
the complete GNU Rust crate; `ARC_REPORT_DIR` emits LLVM crates too.

A second oracle calls the compiled upstream insertion functions for every
expanded form. Build `testdata/native-oracle.c` against the corresponding
configured source/build pair, then run:

```
cc -I BINUTILS_SOURCE/include pkg/arc/testdata/native-oracle.c \
  BINUTILS_BUILD/opcodes/arc-opc.o -o ARTIFACT_DIR/native-oracle
ARC_GNU_SOURCE=SOURCE_TAR ARC_NATIVE_ORACLE=ARTIFACT_DIR/native-oracle \
  ARC_MODES=arc64,arc64be,arcv3-32,arcv3-32be \
  go test ./pkg/arc -run TestGNUFullCorpus -count=1 -v
```

The ARC64 branch uses `arc64-opc.o` instead of `arc-opc.o`. NPS400 needs a
binutils build whose `arc_opcodes` includes the vendor rows. The retained
native oracle inputs/results and GNU ELF parity reports are under
`~/Documents/Developer/go-mkasm/complete-support/` in `arcv3-gas`, `nps-gas`,
and the `arcv3-native2.log` report. Focused source/export and boundary checks
are under `~/Documents/Developer/go-mkasm/architecture-expansion/arc/review/`.

## Exact remaining boundaries

Coverage is bounded to the selected upstream tables and CPU profiles. Runtime
`.extInstruction`/`.extCondCode` definitions and arbitrary user ISA extensions
are not interpreted. Symbolic auxiliary-register names, relocatable symbols,
linker relaxation, and symbol resolution are not provided; numeric auxiliary
addresses and concrete instruction targets are accepted. The codec does not
execute instruction semantics or model delay-slot execution. A zero unsupported
count describes the pinned source corpus, rather than every implementation or
extension ever shipped under the ARC name.

Binutils 2.44's NPS `wkup 0,RC` row marks its register field as fixed even though
the insertion function and assembler encode that field. The importer corrects
only that exact mnemonic/value/mask/operand tuple so register bits decode and
round trip; it leaves other source masks unchanged.
