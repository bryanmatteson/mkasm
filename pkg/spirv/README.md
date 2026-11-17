# SPIR-V grammar backend

`Parse(reader, architecture)` accepts Khronos `spirv.core.grammar.json` and the
architecture names `spirv`, `spirv32`, and `spirv64`. SPIR-V operands remain
structured rather than being reduced to fixed instruction bit fields.

The checked fixture is the complete SPIRV-Headers grammar at commit
`5c6004e758e0c80185ef2cee93ae5c10fa342a5b` (SPIR-V 1.6 revision 7): 879
instructions, 72 operand kinds, and 1,124 enumerants. The original JSON copyright
notice and the upstream license are retained under `testdata/`.

Go APIs include instruction `Decode`, `Encode`, `Format`, and `Assemble`, plus
`DecodeModule`, `EncodeModule`, `FormatModule`, and `AssembleModule`. The module
assembler resolves symbolic IDs and preserves numeric IDs. A `Context` tracks
scalar type widths and result types for wide constants and switch cases.

`Catalog.Template(prototype, holes)` binds named, whole structured operands by
their index in the prototype. `Match` and `MatchBytes` return deep-copied captures;
`Encode` validates replacements against the grammar. Reusing a hole name requires
equal operands at each occurrence. The generated Rust `InstructionTemplate`
provides the same matching and encoding operations, including nested enum and
composite operands.

Enum operands contain their dependent operands in `Parameters`. Composite pairs
also use `Parameters`; optional and variadic operands are represented by zero or
more operands in the instruction's operand list. Embedded `OpSpecConstantOp`
operations use the selected instruction's actual operand grammar. Arbitrary-width
numbers and exact floating-point bit patterns can use standard raw word tokens,
for example `!0x55667788 !0x11223344` for a two-word literal. Decimal integer and
IEEE 16/32/64-bit floating literals are supported; extension-specific floating
encodings other than BFloat16 use raw word tokens.

`GenerateRust(output)` emits a standalone MIT-licensed Rust crate without
dependencies. It includes the complete grammar, the equivalent structured codec
and module/text APIs, full-grammar tests, and an `examples/roundtrip.rs` consumer.
Khronos notices are included separately as `LICENSE-SPIRV-Headers`.

Module import accepts either SPIR-V byte order and checks framing, string
termination/padding/UTF-8, operand grammar, numeric ID bounds, duplicate result
IDs, and declared version/extension/capability requirements (including implied
capabilities). Standalone instruction APIs accept an optional `Environment`;
`nil`/`None` admits the grammar union. Module methods check the declarations.

This is a complete **core-grammar codec**, not a semantic SPIR-V module validator.
Dominance, control-flow structure, execution models, type correctness, legal
`OpSpecConstantOp` operation selection, unresolved IDs, and extended instruction
sets' internal semantics remain the responsibility of `spirv-val` or another
semantic validator. `OpExtInst` is represented according to the supplied core
grammar; additional extended-instruction-set grammars are not synthesized.

Run the independent assembler and module-validator checks with:

```sh
MKASM_SPIRV_TOOLS=/path/to/spirv-tools/build/tools go test ./pkg/spirv -v
```

The byte differential covers all 879 instructions with both minimal and expanded
optional/variadic operands (1,758 cases). Those synthetic instruction streams
test grammar parity; the suite separately runs `spirv-val` on a real compute
module and exercises the generated Rust executable on a complete module.
Set `MKASM_SPIRV_RUST_OUTPUT` to retain the generated crate and consumer artifacts.
