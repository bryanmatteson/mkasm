# RISC-V opcode importer

`Parse(reader, "riscv32")` and `Parse(reader, "riscv64")` consume the actual
[riscv/riscv-opcodes](https://github.com/riscv/riscv-opcodes) repository as a tar
or gzip-compressed tar archive. An archive from GitHub is accepted directly;
a leading checkout directory is ignored. `ParseDirectory(path, architecture)`
accepts an unpacked checkout. Include `arg_lut.csv`, `extensions/`, and optionally
`csrs.csv` / `csrs32.csv` for symbolic CSR assembly aliases. No Python generation
step or private replacement schema is required.

```sh
git clone https://github.com/riscv/riscv-opcodes.git riscv-opcodes
tar -czf riscv-opcodes.tar.gz -C riscv-opcodes arg_lut.csv csrs.csv csrs32.csv extensions
```

The importer resolves regular definitions, `$pseudo_op`, `$import`, tied
register fields, source extension predicates, XLEN-specific instruction files,
16-bit compressed instructions, and 32-bit instructions. It rejoins B/J/S and
compressed immediate fields, with their architectural signedness and alignment.
The structured encoder uses byte offsets for branches, jumps and memory
addresses; text assembly and formatting use absolute branch targets at the
supplied instruction address. LUI/AUIPC use the conventional unshifted 20-bit
assembler operand. C.LUI retains the signed six-bit structured value and formats
its unsigned 20-bit assembler spelling, so structured `-1` formats as `1048575`.

Integer, floating-point and vector register banks are distinguished, including
ABI register aliases and compressed register windows. `aq`/`rl` fields generate
conventional atomic `.aq`, `.rl`, `.aqrl` assembly variants. Vector masks and
segment counts generate conventional forms, and vector configuration operands
accept `e32,m1,ta,ma` spellings. Dynamic floating-point rounding can be implicit.
Zcmp stack forms use XLEN-dependent stack allocation and register-list variants.
Original source definitions remain addressable by `extension::mnemonic` IDs;
assembly variants append `/orderN`, `/vmN`, `/nfN`, `/dyn`, or another descriptive
suffix. An occasional repeated source mnemonic receives `#2`, etc.

Each encoding carries its original source filename as a required feature, for
example `rv_i`, `rv64_i`, `rv_c`, or `rv_f_zfa`. Unratified definitions additionally
require `unratified`. These are source predicates, not LLVM feature strings.
`FeatureSets` provides `rv32i`, `rv32im`, `rv32imac`, `rv32gc`, `rv32gcv` (or their
RV64 counterparts). Use explicit feature sets when decoding overlapping extension
spaces. A nil feature set intentionally admits all imported encodings.

The importer validates every instruction and records unrepresentable or
overlapping fields in `Catalog.Unsupported`, with the precise reason.
Malformed directives, bit ranges, unknown fields and missing import targets are
errors. Source bits left outside both the fixed mask and named operands remain
explicit unsigned `RawEncodingBits` operands, named by their physical ranges
(`raw_28`, `raw_24_23`, etc.). They are required in structured encoding and text
assembly, so formatting and re-encoding preserve every physical bit. The
importer does not assign architectural meanings or silently choose constants
for those fields.

## Validation and coverage

The always-on tests cover archive parsing, regular/pseudo/import resolution,
XLEN filtering, ABI aliases, signed split-immediate boundaries, alignment,
compressed illegal operands, malformed sources, and tied-register rejection.
Unmodified `arg_lut.csv` and `rv_zvtbase` fixtures retain the pinned upstream
license under `testdata/zvtbase`. The default tests exhaust all 1,024 physical
`msetmtypei` images per XLEN (five destination-register bits and five unnamed
bits), check missing/out-of-range operands, fixed-bit rejection, truncation,
stream consumption, and exact format/assembly round trips.
The external corpus test imports every applicable upstream definition and checks
byte decode/re-encode plus format/text-assemble acceptance for every emitted
encoding. LLVM tests independently compare instruction bytes across scalar,
compressed, floating-point, atomic, vector, CSR and Zcmp examples.

```sh
RISCV_OPCODES_DIR=/path/to/riscv-opcodes go test ./pkg/riscv -v
```

Set `LLVM_MC` to override `/opt/homebrew/opt/llvm/bin/llvm-mc`. Set
`RISCV_REPORT_DIR` to retain JSON coverage counts and generated standalone Rust
crates under that directory. The root shared codec owns the generated Rust
runtime; its generated tests should be run with `cargo test --lib` in each crate.

At upstream revision `f24ac23ec9fa947011781a09cd6fd25a7c36dc45`, the source contains
1,620 applicable RV32 and 1,568 applicable RV64 definitions, with zero
unsupported definitions for either XLEN. Assembly variants add 1,704 RV32 and
1,768 RV64 forms, for 3,324 and 3,336 total emitted encodings, respectively.
Counts describe that revision; the importer does not hardcode a catalog.

The unratified `rv_zvtbase::msetmtypei` definition names only `rd` and leaves
bit 28, bits 24–23, and bits 16–15 unnamed. The upstream Python parser accepts
it with match `0x88407057` and mask `0xee7e707f`; its encoding initializer calls
these unassigned positions "don't care" bits. This importer preserves them as
`msetmtypei {rd}, {raw_28}, {raw_24_23}, {raw_16_15}`. For example,
`msetmtypei a0, 0, 0, 0` encodes as `57 75 40 88`. The source does not supply
semantic matrix-type field names, so those meanings and runtime legality are
not inferred. With `RISCV_OPCODES_DIR` set, the independent oracle test invokes
the actual upstream Python parser and compares its match/mask with the imported
encoding. LLVM 22.1.8 does not recognize this mnemonic; LLVM parity checks do
not establish architectural validity for these experimental raw fields.

This is a fixed-instruction codec, not a linker or a complete GNU assembler.
It does not resolve labels, relocations, instruction relaxation, macro
pseudoinstructions expanding into multiple instructions, RV128, or instruction
lengths above 32 bits. Vendor/experimental packed fields without a conventional
syntax adapter retain explicit source-field operands. Runtime-dependent legality
(e.g. vector LMUL/group overlap or privilege state) requires execution context and
is not inferred. Independent LLVM checks are a representative cross-extension
sample; the exhaustive source tests establish model round trips rather than an
independent architectural oracle for every imported extension.
