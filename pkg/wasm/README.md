# WebAssembly instruction backend

This package imports **all 626 distinct opcode encodings** from wasm-tools
0.262.0 (`e22db44da4eaf17a0e46ec55b911c7539589a3cc`). It implements instruction
framing, structured operands, encoding, decoding, disassembly, text assembly,
and named operand templates in Go and generated standalone Rust.

`wasm32` uses 32-bit memory offset immediates; `wasm64` uses 64-bit offsets.
Function, type, memory, table, tag and label indices remain unsigned 32-bit
integers. Both modes include all imported feature groups; feature requirements
are metadata on each opcode. The byte stream alone does not establish which
features, memory types, type definitions, or control frames a module permits.

**This is an instruction codec.** Module parsing, type checking, stack checking,
control-flow validation, proposal enablement, symbol resolution and full WAT
module parsing belong to a module toolchain. The integration tests use
wasm-tools separately for module validation.

## Input source

`Parse(reader, "wasm32")` or `Parse(reader, "wasm64")` reads the resolved JSON
grammar produced by `import_wasm_tools.py`. The complete grammar is checked in
at `testdata/wasm-opcodes.json`. The extractor reads actual upstream sources:

- `crates/wasmparser/src/lib.rs`: every operator, operand and proposal group.
- `crates/wasm-encoder/src/core/instructions.rs`: binary opcode values.
- `crates/wast/src/core/expr.rs`: canonical instruction mnemonics.

For crates.io source trees, pass the corresponding paths beneath the
`wasmparser-0.262.0`, `wasm-encoder-0.262.0` and `wast-262.0.0` directories:

```sh
python3 pkg/wasm/import_wasm_tools.py \
  /path/to/wasmparser-0.262.0/src/lib.rs \
  /path/to/wasm-encoder-0.262.0/src/core/instructions.rs \
  /path/to/wast-262.0.0/src/core/expr.rs \
  /path/to/wasm-opcodes.json
```

Source digests are checked against this qualified release. An unmapped
upstream operator, operand kind, mnemonic or duplicate opcode fails extraction.
There is no silently omitted opcode subset. `TypedSelectMulti` and
`TypedSelect` share opcode `0x1c` and the same vector grammar, represented by a
single `TypedSelect` definition accepting the complete vector. All experimental
operators in this upstream release are included alongside standardized ones;
the `feature` field identifies their proposal group.

The imported groups are `mvp`, `sign_extension`, `saturating_float_to_int`,
`reference_types`, `bulk_memory`, `tail_call`, `function_references`, `simd`,
`relaxed_simd`, `threads`, `gc`, `exceptions`, `legacy_exceptions`,
`shared_everything_threads`, `stack_switching`, `custom_descriptors`,
`wide_arithmetic` and `memory_control`.

The source grammar is derived from the Bytecode Alliance wasm-tools project,
which offers MIT, Apache-2.0 and Apache-2.0 WITH LLVM-exception licensing. The
MIT license is included at `testdata/LICENSE-wasm-tools-MIT`.

## Go API and text syntax

```go
catalog, err := wasm.Parse(source, "wasm64")
encoded, err := catalog.Encode("I32Const", []wasm.Value{wasm.S(-17)})
instruction, err := catalog.Decode(encoded)
text := instruction.Format() // i32.const [-17]
encoded, err = catalog.Assemble(text)

load, err := catalog.Template("I32Load")
err = load.Set("memarg", wasm.L(wasm.U(2), wasm.U(16), wasm.U(0)))
encoded, err = load.Encode()
matched, ok := load.Match(encoded)
```

`Decode` consumes one instruction and returns its actual `Length`; trailing
bytes belong to the next instruction. `Disassemble` consumes a sequence.
`AssembleReader` accepts one instruction per line and `;;` comment lines. It
adds no module headers, local declarations or implicit `end` instructions.
Templates capture unbound operands when matching and require bound operands to
have the same binary meaning. `Set` copies nested values so bindings do not
retain caller-owned slices.

Text assembly uses the canonical mnemonic followed by a JSON array of
structured operands. Each operand is an integer, a type-name string or a
nested array. Scalar immediates also accept whitespace-separated integer
literals. This syntax represents every imported instruction and has no module
symbol dependencies; it is distinct from WAT. Explicit opcode IDs can always
be used. Nullable and non-nullable reference test/cast variants format with
their distinct IDs to preserve their opcode selection.

```text
i32.const -17
local.get [3]
block ["i32"]
br_table [[0,300,4]]
i32.load [[2,16,0]]
i8x16.extract_lane_u [4]
try_table [["empty",[[0,1,2],[2,3]]]]
BrOnCast [[3,2,"any","struct"]]
```

Operand representations:

| Kind | Representation |
| --- | --- |
| Unsigned index, signed integer, lane, ordering, reserved byte | Integer; ranges and reserved values checked |
| `f32`, `f64` | Unsigned IEEE bit pattern; preserves signed zero and NaN payloads |
| `v128`, shuffle | Array of exactly sixteen bytes; shuffle lanes must be below 32 |
| Memory argument | `[alignment_exponent, byte_offset, memory_index]` |
| Heap type | Abstract name such as `"func"`, unsigned concrete type index, `["shared","any"]`, or `["exact",3]` |
| Reference type | `["ref",heaptype]` or `["refnull",heaptype]` |
| Value type | `"i32"`, `"i64"`, `"f32"`, `"f64"`, `"v128"`, or a reference type |
| Block type | `"empty"`, value type, or unsigned function type index |
| Branch table | Target array with the default target last; at least one target |
| Typed select | Value-type array |
| Try table | `[blocktype,[catch,...]]`; catch `[0,tag,label]`, `[1,tag,label]`, `[2,label]`, `[3,label]` |
| Resume table | Handle array; `[0,tag,label]` or `[1,tag]` |
| Reference cast branch | `[nullability_flags,label_depth,from_heaptype,to_heaptype]` |

Atomic ordering is `0` (sequentially consistent) or `1` (acquire/release).
Memory alignment is an exponent, and the optional memory index flag is encoded
automatically. Lane limits, shuffle limits, invalid tags, invalid type codes,
LEB overflow, truncated vectors and invalid reserved values are rejected.
Natural memory alignment, valid indices, control depths and operand stack types
require module context and are checked by the module validator.

Encoding uses canonical minimal LEBs and compact type/memory spellings. Decoding accepts valid bounded overlong
LEBs; re-encoding normalizes them. Disassembly therefore preserves operand
values and canonical encodings, rather than retaining redundant byte spellings.

## Generated Rust

`catalog.GenerateRust(outputDirectory)` creates `Cargo.toml` and `src/lib.rs`
with no dependencies, an MIT runtime `LICENSE`, and the separate upstream grammar
notice `UPSTREAM-LICENSE`. The generated public APIs are `decode`, `decode_all`,
`encode`, `assemble`, `Instruction`, `Opcode`, `Field`, `Value` and
`InstructionTemplate`. `Instruction` implements `Display` for the canonical
assembly syntax. `OPCODES` exposes every imported record and its feature group.
`Value` has unsigned, signed, text and recursive list variants.

```rust
let bytes = encode("I32Const", &[Value::I(-17)])?;
let instruction = decode(&bytes)?;
assert_eq!(assemble(&instruction.to_string())?, bytes);
let mut load = InstructionTemplate::new("I32Load")?;
load.set("memarg", Value::List(vec![Value::U(2), Value::U(16), Value::U(0)]))?;
let bytes = load.encode()?;
assert!(load.match_instruction(&bytes).is_some());
```

## Verification

Ordinary `go test ./pkg/wasm` exercises every opcode in both Go modes,
truncation at every instruction byte, malformed LEB/type/tag/lane inputs,
64-bit integer boundaries, memory64 offsets and templates. It generates and
compiles Rust for both modes and executes every opcode through binary and
text roundtrips.

The independent wasm-tools oracle source is checked in at `testdata/oracle.rs`;
its Cargo manifest is `testdata/oracle-Cargo.toml`. Copy those to an artifact
crate's `src/main.rs` and `Cargo.toml`, compile it with normal Cargo, and run:

```sh
WASM_ORACLE=/path/to/oracle/target/debug/mkasm_wasm_oracle \
  go test ./pkg/wasm
```

This additionally compares all 626 opcode samples with wasmparser decoding
and wasm-encoder re-encoding. Control-only opcodes get their required
surrounding frame in the oracle. Four complete WAT modules exercise memory,
SIMD, GC and memory64; their function instruction bytes must match this codec,
and wasm-tools must validate each complete module.
