# V850 instruction codec

`Parse` reads the complete, unmodified GNU binutils **2.44**
`opcodes/v850-opc.c`. The matching operand flags and assembler register aliases
come from the retained `include/opcode/v850.h` and `gas/config/tc-v850.c`.
The importer checks all 86 operand definitions and imports all **403** opcode
rows, including GNU aliases and optional extension instructions. No source row
is skipped or replaced with a curated instruction list.

The canonical architecture is `v850`. The names `v850e`, `v850e1`, `v850e2`,
`v850e2v3`, and `v850e3v5` also parse this same complete catalog. Select a
processor with `FeatureSets[name]` and `DecodeWithFeatures` or
`AssembleWithFeatures`. Every processor has a second profile named
`name+extension`, corresponding to GNU's `-mextension` option. Omitting the
feature filter admits the union of all source processors.

The catalog has 93 two-byte, 276 four-byte, 33 six-byte and one eight-byte
encoding/syntax forms. The source's alias-only entries remain available to
exact encoding and text assembly; decoding prefers actual instruction entries.
The source tables determine the instruction frames, masks, register classes,
split fields, even-register pairs, condition names, memory syntax and profiles.
Unused fields are required to contain their defined reserved-zero values.

Operand names `op0`, `op1`, etc. follow the source operand positions; fixed
`sp` and `ep` operands are represented directly in syntax. Structured register
values are physical register numbers, including even numbers for register
pairs. A prepare/dispose list is a compact twelve-bit mask whose bit zero is
`r20` and bit eleven is `r31`. Text accepts ranges, explicit lists and the GNU
register aliases; duplicate or out-of-range list entries are errors.

Displacements use byte units. Relative branches are signed offsets from the
current instruction, and formatted targets wrap at 32 bits. `loop` uses a
nonpositive semantic displacement, although its physical field stores the
positive backwards distance. Split fields retain alignment constraints.
`bins` position and width are semantic values, with all 528 legal ranges
accepted. The high-half immediate is represented as its 32-bit value with
the low sixteen bits zero. Full 32-bit immediates use values from zero through
`0xffffffff`; text also accepts their signed 32-bit spellings.

The Go catalog supplies exact encoding, structured decode, formatting,
address-aware text assembly, profiles and ID-based templates (`Template`,
`Set`, `Encode`, `Match`). `GenerateRust` emits a dependency-free crate with
the same catalog, decode/encode/format/assembly APIs and text templates with
named holes. It preserves the GNU metadata notice and license separately
from the generated runtime's MIT notice. The combined crate declares
`GPL-3.0-or-later`.

Validation includes retained independent GNU assembler bytes for every one
of the 403 forms, 619 additional boundary cases (including all 528 `bins`
ranges), every prepare/dispose list bitmap, truncation of every non-alias
oracle instruction, invalid register/field constraints, and a real GNU
assembled routine with a prologue, mixed instruction sizes, backwards loop,
conditional branch, call, memory accesses and epilogue. The generated Rust
consumer compares the same independent GNU corpus and boundary bytes and
consumes the actual routine, including its relative targets.

Ghidra **12.1.2**, using its installed `V850:LE:32:default` language, provides
a second independent oracle: 331 forms decode with matching lengths and
308 decode/reassemble to exactly the original bytes. Of the other matching
length forms, 23 reassemble to shorter equivalent encodings. Four E3
`ld.dw`/`st.dw` forms are misframed by this older language and 68 forms are
unsupported. The newer checked-out Ghidra source has an E3 language, but it
is not installed and was not substituted for the pinned executable. These
are limits of that independent oracle; all 403 forms match GNU 2.44 bytes.

The codec does not resolve ELF relocations or evaluate instruction semantics.
Flow metadata classifies opcode forms. A register-indirect `jmp` is classified
as a branch, including `jmp [lp]`; no runtime register analysis is implied.

Run the offline corpus and behavior checks with `go test ./pkg/v850`.
Optional integration checks use:

```sh
MKASM_V850_AS=/path/to/binutils-2.44/build/gas/as-new \
MKASM_V850_RUST=1 MKASM_V850_GHIDRA=1 \
MKASM_V850_ARTIFACT_DIR=/path/to/artifacts \
go test ./pkg/v850 -count=1 -v
```

The integration test invokes the normal `cargo test --lib --test behavior`
command. GNU oracle assembly uses the source-selected processor and explicit
long-form aliases/relocation expressions where the assembler would otherwise
choose a shorter equivalent instruction.
