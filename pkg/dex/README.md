# Android DEX / Dalvik

`Parse(reader, "dex")` consumes the unmodified AOSP ART
`libdexfile/dex/dex_instruction_list.h` source. The returned `Catalog`
implements the `codec.Backend` JSON and Rust generation contract and owns DEX
instruction framing. The retained Android 16 corpus has all 256 opcode slots:
224 standard instructions and 32 reserved slots. All 26 fixed formats and all
three payload formats are implemented. Compiler/runtime-specific ODEX
quickened opcodes use different opcode assignments and are excluded.

`Decode` / `Encode` use the latest standard version. Their `Version` variants
accept DEX 035, 037, 038, 039, 040, or 041 and reject newer instructions in older
files. `invoke-polymorphic` and `invoke-custom` require 038;
`const-method-handle` and `const-method-type` require 039. Version 036 was not
a released standard format.

`Instruction.Values` contains the named scalar operands listed in each
definition: registers `a`, `b`, `c`, and `literal`, `index`, `proto`, or
`target` as appropriate. Invoke lists use `Registers`; invoke ranges use
`Range`. Structured register values are architectural register numbers.
Wide values occupy adjacent registers without an even-register restriction.
64-bit literals use the full signed `int64` bit pattern. High-16 constants
use their complete shifted value and require the omitted low bits to be zero.

Offsets and relative displacements use **16-bit code units**, while `Length`
uses bytes. A branch `target` is a signed displacement from its opcode.
Packed and sparse switch payload targets are relative to the referring
switch opcode, rather than to the payload. Array payloads preserve raw little
endian element bytes. Payloads require four-byte alignment; array widths are
1, 2, 4, or 8 bytes. Reserved opcode slots, reserved format bits, unused invoke
register fields, padding, out-of-range arguments, oversized invoke ranges,
unordered sparse keys, packed-key overflow, and truncation are rejected.

`Catalog.Format` and `Assemble` use numeric pool references and absolute
code-unit branch targets:

```text
const/4 v0, #-7
const-wide v1, #-81985529216486895
iget v1, v2, field@3
invoke-virtual {v1, v2}, method@5
invoke-static/range {v256 .. v260}, method@7
invoke-polymorphic {v1, v2}, method@5, proto@6
if-eqz v0, 0x28
packed-switch-payload -5, {-3, +2, +8}
sparse-switch-payload {-100:-3, 5000:+2}
array-data-payload 4, {0x11223344, 0xfffffffe, 0x7fffffff}
```

Payload text retains signed displacements because an individual payload has
no unique referring switch. `Templates` supplies an assemblable example for
every standard instruction and payload. Identifier pool names are `string`,
`type`, `field`, `method`, `proto`, `call_site`, and `method_handle`. Pool
indices remain numeric; symbolic resolution belongs to the containing file.

`Catalog.Template(mnemonic)` constructs a reusable `InstructionTemplate`.
`Set` fixes named scalar operands; `SetRegisters`, `SetRange`, and `SetPayload`
bind complete structured operands. `Match(bytes, offset)` captures the decoded
instruction while requiring every fixed operand to match. `Encode(offset)`
requires all operands to be bound and applies normal range and alignment checks.
`TemplateVersion` selects a DEX version. Generated Rust exposes equivalent
`InstructionTemplate::new`, `new_version`, `set`, `set_registers`, `set_range`,
`set_payload`, `match_instruction`, and `encode` methods. Templates copy their
structured values so caller changes cannot alter a previously bound pattern.

`DecodeMethod` validates complete instruction arrays: every branch lands on
an executable instruction boundary; payload references have the right kind;
switch cases land in code; and reachable control flow cannot fall through
into payloads or beyond the method. Unreachable alignment nops are supported.
`DecodeCodeItem` / `EncodeCodeItem` include register/argument frame sizes,
debug-info offsets, try ranges, and typed/catch-all handlers. They check
wide-register bounds, invoke `outs_size`, handler boundaries and reachability,
and sorted nonoverlapping try ranges. `ValidateRegisters` accepts optional
identifier-pool sizes for additional index checks.

`DecodeDEX` walks real class-data method references and validates their code
items and identifier bounds. It handles ordinary little endian single-file
DEX containers; multi-header DEX 041 containers and reverse endian files are
rejected explicitly. It preserves debug-info offsets without rewriting or
interpreting debug programs. The package does not implement Android type,
stack, access-control, or dataflow verification, nor does it execute methods.

`GenerateRust` emits a dependency-free crate with the same opcode metadata,
structured operands, version checks, exact encode/decode, text grammar,
templates, method checks, and code-item reader/writer. The generated crate
does not need a Java or Android runtime.

The default Go tests compare against 230 retained independent dexlib2 byte
vectors, exercise all opcode slots, boundary values and malformed inputs, and
read five methods from a retained smali-built DEX. To regenerate the oracle,
assemble/disassemble the real DEX, and test the standalone Rust consumer:

```sh
MKASM_SMALI_JAR=/path/to/smali-3.0.9-fat-release.jar \
MKASM_BAKSMALI_JAR=/path/to/baksmali-3.0.9-fat-release.jar \
MKASM_DEX_RUST=1 \
MKASM_DEX_ARTIFACT_DIR=/path/to/artifacts \
go test ./pkg/dex -count=1 -v
```

External-tool tests report an explicit skip when their environment variables
are absent. The retained vectors cover every standard opcode, both high-16
literal formats, all invoke forms, switch payloads, and every array width.
The five-method module covers packed/sparse switches, array data, a typed
exception handler, a method invocation, and a full 64-bit constant. Tests also
include bounded random-input checks in Go and Rust and a Go fuzz target.
