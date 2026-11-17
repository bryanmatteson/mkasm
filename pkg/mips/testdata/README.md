`llvm22-mips.json` is a reduced, resolved LLVM TableGen dump, generated from
LLVM 22.1.8 (`llvmorg-22.1.8`, commit `ca7933e`). Its instruction records,
operand classes, register classes and register encodings are source data rather
than a hand-authored encoding table. The reduction keeps 42 machine instruction
records and 22 associated aliases, plus the operand/register records needed by
the importer tests. The source fields retain their TableGen names and values;
debug location and superclass metadata were removed.

LLVM source is licensed Apache-2.0 WITH LLVM-exception. Original target source:
https://github.com/llvm/llvm-project/tree/llvmorg-22.1.8/llvm/lib/Target/Mips

Generate the complete source dump with:

```sh
llvm-tblgen --dump-json \
  -I llvm-project/llvm/include \
  -I llvm-project/llvm/lib/Target/Mips \
  llvm-project/llvm/lib/Target/Mips/Mips.td -o mips.json
```

Run complete-source import and independent LLVM validation with:

```sh
MKASM_MIPS_TABLEGEN_JSON=/absolute/path/mips.json go test ./pkg/mips -short -v
MKASM_MIPS_TABLEGEN_JSON=/absolute/path/mips.json MKASM_MIPS_VALIDATE_ALL=1 \
  go test ./pkg/mips -short -run TestLLVMWholeCorpus -v
MKASM_MIPS_TABLEGEN_JSON=/absolute/path/mips.json MKASM_MIPS_VALIDATE_ALL=1 \
  MKASM_MIPS_AUDIT_ARCH=micromips32el \
  go test ./pkg/mips -short -run TestLLVMWholeCorpus -v
MKASM_MIPS_AS=/absolute/path/mips-as MIPS_LD=/absolute/path/ld.lld \
  go test ./pkg/mips -short -run 'TestCompressedGNU' -v
```

`LLVM_MC` selects the independent assembler executable. The whole-corpus audit
uses `mips64el` by default; set `MKASM_MIPS_AUDIT_ARCH=mips32el` to audit MIPS32.
The LLVM 22.1.8 complete source produces 1,311 standard MIPS32 encodings and
1,527 standard MIPS64 encodings, including machine aliases. The three explicitly
unsupported standard-mode records are malformed upstream aliases (`sub,`,
`subu,`, and the literal `$$rs` in `sgtu`). Compressed records are imported in
their separate execution-mode catalogs.

`llvm22-compressed.json.gz` retains the resolved LLVM records for microMIPS and
MIPS16, together with their operand/register dependencies and machine aliases.
The records retain their complete source fields, including implicit effects.
The importer yields 871 microMIPS32 forms (861 source forms plus four derived
commuted text spellings and six GNU memory spellings), 956 microMIPS64 forms
(the same source union plus all 85 GNU 64-bit-only machine rows), and 3,652 MIPS16 forms
per address mode/byte order, including every non-macro GNU machine row. `TestRealCompressedTableGenCorpus` compares every encoding's
metadata with the full dump in all eight compressed target names.

`mips16-opc.c` is the original GNU binutils 2.44 opcode table, with its GPL-3.0-or-later
notice intact; `COPYING3` contains the license. All 221 non-macro machine rows are imported through `gnu-mips16.json`,
which is produced by compiling the original operand decoder rather than
transcribing its layouts. The package [README](../README.md) describes the precise GNU coverage
limits and execution-mode/feature contracts.

The full LLVM audit accepts `mips32el`, `mips64el`, `micromips32el`, and the
corresponding big endian names. It compares every source form's
sample against LLVM's independent assembler; source aliases such as 16/32-bit
`nop` may select another equivalent imported encoding. Four adapter-derived
commuted microMIPS spellings are checked separately, since LLVM's reversed
BEQC/BNEC operands can emit another physical opcode. GNU tests compare selected
memory spellings to independently assembled short encodings, while LLVM can
choose their 32-bit equivalents. GNU tests also compare
real instruction bytes, the LBU16 sentinel, MIPS16 JAL, and branch targets after
linking microMIPS relocations. `LLVM_MC`, `MKASM_MIPS_AS`, and `MIPS_LD` select
the independent tools. GNU tests require the assembler environment variable;
the full dump/audit tests require their explicit opt-in variables. `-short`
omits the generated Rust Cargo consumer checks in `TestCompressedModes`.

LLVM rejects a microMIPS64 target and GNU rejects microMIPS with a MIPS64r6 CPU.
`TestIndependentMicroMIPS64Corpus` therefore names both reference layers
explicitly: 856 physical source forms in the 64-bit catalog are compared to
LLVM's microMIPS32 instruction encoder with the reference ABI's register names;
five corrected DSP forms and twelve additional vectors use GNU's actual ELF64 microMIPS assembler. This does
not claim that LLVM implements a microMIPS64 execution backend. Run either byte
order with:

```sh
MKASM_MIPS_TABLEGEN_JSON=/absolute/path/mips.json \
LLVM_MC=/absolute/path/llvm-mc MKASM_MIPS_AS=/absolute/path/mips-as \
MKASM_MIPS_AUDIT_ARCH=micromips64el \
  go test ./pkg/mips -run '^TestIndependentMicroMIPS64Corpus$' -count=1 -v
```

`micromips-opc.c` retains the original GNU 2.44 table and license notice.
`export-micro64.c` compiles its actual operand decoder to produce
`gnu-micromips64.json`. Native GNU assembly/linking checks 688 r5 source forms
per byte order, including all 85 GNU-only rows. `gnu-micro64-oracle.c` invokes
the unmodified upstream operand printer for 13,216 register, list, index,
integer and bitfield boundary samples per byte order. Go and fresh CLI-generated
Rust must assemble those native operand texts to the same physical words.
The complete raw sweep also checks 3,405 native assembler rejections in Go and
Rust. GNU 2.44 admits 93 zero-size DINS patterns because its `match_msb_operand`
checks `size < 0`; the codecs reject these architecturally UNPREDICTABLE
`lsb > msb` patterns. This exact native discrepancy is counted explicitly.
No candidates are filtered with the codec before asking GNU about admission.
`generate-gnu.sh` builds both the exporter and oracle from explicitly supplied
`GNU_SOURCE`, `GNU_BUILD` and `GNU_OUTPUT` directories. Set
`MKASM_MICRO64_EXPORTER` and `MKASM_MICRO64_ORACLE` to the resulting executables;
`TestIndependentGNUMicro64OperandBoundaries` runs the native operand comparison.
Its generated crate can be retained with `MKASM_MICRO64_BOUNDARY_RUST`.

GNU assembly and disassembly expose five incorrect LLVM 22 DSP source layouts:
`CMPGU_EQ_QB_MM`, `CMPGU_LT_QB_MM`, `CMPGU_LE_QB_MM`, `SHLLV_PH_MM` and
`SHLLV_S_PH_MM`. The importer corrects their fixed opcode bits against GNU's
`micromips-opc.c` while retaining source fields/features. The whole-corpus audit
uses GNU for these five forms in all four microMIPS selectors. The additional
`TestIndependentMicroDSPConsumers` checks 60 native GNU boundary samples through
Go and four actual CLI-generated Rust crates; it requires `MKASM_REFERENCE_CLI`
in addition to the corpus and GNU assembler paths.


`gnu-mips16.json` retains 221 non-macro machine rows, their original row numbers,
source ISA/ASE flags, register read/write flags and all 59 operand descriptors.
Its boundary samples are computed by upstream `mips_insert_operand`,
`mips_extract_operand` and `mips_decode_int_operand`. `export-gnu.c` includes the
retained original `mips16-opc.c` and compiles against the matching GNU headers.
`gnu-disassemble.c` includes upstream `opcodes/mips-dis.c` directly and links the
actual libopcodes/libbfd build. It accepts `be|le address_hex bytes_hex` lines;
optional fourth/fifth fields select a byte offset into the supplied instruction
history and legacy MIPS16 without MIPS16e2. It supplies `$` register prefixes so
printed GNU instructions can be fed back to the assembler.

Build those independent tools against an extracted and configured/built GNU
binutils **2.44** MIPS target:

```sh
GNU_SOURCE=/absolute/path/binutils-2.44 \
GNU_BUILD=/absolute/path/binutils-mips \
GNU_OUTPUT=/absolute/path/mips-audit \
  sh pkg/mips/testdata/generate-gnu.sh
cmp /absolute/path/mips-audit/gnu-mips16.json pkg/mips/testdata/gnu-mips16.json
```

The script writes artifact files only. After reviewing a changed source export,
copy it to `testdata/gnu-mips16.json` explicitly. Run the source export check,
all-row decoder oracle, execution-context/history checks and six actual GNU gas
corpora in both byte orders with:

```sh
MKASM_MIPS_TABLEGEN_JSON=/absolute/path/mips.json \
MKASM_MIPS16_EXPORTER=/absolute/path/mips-audit/export-gnu \
MKASM_MIPS16_DISASSEMBLER=/absolute/path/mips-audit/gnu-disassemble \
MKASM_MIPS_AS=/absolute/path/binutils-mips/gas/as-new \
MIPS_LD=/absolute/path/ld.lld \
  go test ./pkg/mips -short -count=1 -v
```

`gnu-gas/` contains original GNU 2.44 `gas/testsuite/gas/mips/` files:
`mips16.s`, `mips16e.s`, `mips16e-64.s`, `mips16e2.s`, `mips16e2-copy.s`,
and `save.s`. These retained GNU source inputs, the opcode table, their compiled
export and the GNU oracle adapter are distributed under GPL-3.0-or-later; see
`COPYING3`. The source files preserve their original contents. The corpus test
invokes real GNU gas, then the compiled upstream decoder to determine framing
and printed operands. Its sections contain 5,576 bytes and 1,603 decoded
instructions/words per byte order; this includes padding/data embedded in the
upstream tests and is not a count of distinct opcode forms.

The complete-row oracle currently checks 2,259 canonical/exact representative
configurations per MIPS16 catalog, including every SAVE/RESTORE register-list
configuration and the nonzero ignored-field forms. Invalid list/frame/bitfield
boundaries and MIPS16/MIPS16e/MIPS16e2 gates have focused regressions.
`TestGNU16LLVMFormsAgree` also compares every retained LLVM MIPS16 form under
five physical operand-bit patterns against the separately validated GNU model.
The public Rust context consumer is retained in `context-consumer.rs` and is
installed by `mips.Catalog.GenerateRust`; its crate import is expanded for
`mips16`, `mips16el`, `mips16_64` and `mips16_64el`.
