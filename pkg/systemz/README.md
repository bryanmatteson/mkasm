# SystemZ / zArchitecture

`Parse(reader, "systemz")` imports the JSON emitted by LLVM TableGen for
`llvm/lib/Target/SystemZ/SystemZ.td`. `s390x` is also accepted and normalizes to
`systemz`. The result uses the shared `codec.Catalog` API for structured
encoding, decoding, assembly, formatting, JSON output, and Rust generation.

The LLVM 22.1.8 corpus contains 2,976 SystemZ Instruction records: 2,742
concrete forms and 234 compiler pseudos. All 2,742 concrete forms and all 52
`InstAlias` records are imported. The importer also creates 1,337 assembly
variants for omitted zero address registers, giving 4,131 catalog encodings
with no unsupported concrete forms. Compiler pseudos require lowering and are
excluded. LLVM's 31 `.insn` format directives are available for assembly and
structured encoding; they do not participate in decoding.

Instruction bytes remain in architectural big endian order. Formats have
two, four, or six bytes. Operand bit slices preserve split fields such as the
signed 20-bit displacement. Reserved bits and operand ranges follow the
upstream instruction and assembler operand definitions.

Structured operands use architectural register numbers. General register
pairs start at an even register. Floating point extended pairs use starts
0, 1, 4, 5, 8, 9, 12, or 13. GNU register spellings are retained, including
floating point aliases for the low sixteen scalar vector registers.
Address fields use literal `0` for an absent base or index; `%r0` is rejected
in those positions, as in LLVM's assembler. Address assembly accepts indexed,
base-only, and unbased forms where the instruction format permits them.

Numeric operands use assembler units. Length fields accept lengths starting
at one, and encode length minus one. PC-relative values in `Encode` and
`Decoded.Values` are signed byte displacements from the instruction address;
their encoded halfword fields scale by two. Text assembly and formatting use
absolute target addresses with the supplied instruction address. Unaligned
branch targets and values outside the encoded range are rejected.

The canonical syntax for a variable conditional mask uses LLVM's numeric
mask spelling where one exists. This preserves all four mask bits even when
a comparison cannot produce every condition code. The named branch and
comparison aliases remain available for assembly. Aliases and optional
address variants are assembly-only, so they cannot weaken reserved-bit checks
or change canonical decoding.

Processor feature profiles are imported from all 17 upstream `ProcessorModel`
records. Pass a selected profile to the shared `AssembleWithFeatures` or
`DecodeWithFeatures` methods. A nil feature selection admits the union of
supported instructions; an empty selection admits instructions without
facility predicates. These profiles describe assembler facilities, without
modeling privileged execution or runtime machine state.

Two upstream dump details are reconciled with LLVM's actual directive parser:
the `vrs` `.insn` syntax includes the two register operands omitted from its
`AsmString`, and the first `ss` `.insn` address uses the parser's indexed
address class. Both follow `SystemZAsmParser.cpp`'s `InsnMatchTable` and are
covered by the LLVM oracle.

`go test ./pkg/systemz` checks every form for exact byte round trips and text
assembly. With LLVM MC installed, it also assembles every form into a real
SystemZ ELF object using `-mcpu=z17` and compares its `.text` bytes against the
catalog, in addition to independent retained byte examples and invalid
register, range, truncation, reserved-field, and profile checks. The oracle
skips explicitly when LLVM MC is unavailable. Set
`MKASM_SYSTEMZ_TABLEGEN_JSON` to an unmodified full dump to compare its imported
catalog against the retained complete corpus, and
`MKASM_SYSTEMZ_ARTIFACT_DIR` to retain the oracle assembly and object file.
Tests establish assembler and codec behavior; no SystemZ hardware execution
is involved.

When managed Cargo is available, the same test command generates the complete
standalone Rust crate and runs its library tests plus a raw-directive consumer
with warnings denied. The consumer covers all 31 source `.insn` formats and
their 32 optional-address variants, including arbitrary raw bytes that the
instruction decoder must reject. Set `MKASM_SYSTEMZ_RUST_DIR` to choose the
generated crate directory; by default it is retained under
`~/Documents/Developer/go-mkasm/architecture-expansion/systemz/generated-rust-regression`.
Short-mode tests skip this Rust build explicitly.
