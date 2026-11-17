# Hexagon packet backend

`Parse(reader, "hexagon")` accepts LLVM `llvm-tblgen --dump-json` output and returns
`codec.Backend`. It imports the complete LLVM 22.1.8 target rather than selecting
an instruction sample. `Catalog.WriteJSON` retains both physical word fields and
the packet semantics needed to interpret them. `GenerateRust` produces a standalone
MIT Rust crate with packet encode/decode, formatting, text assembly and templates.

The pinned fixture contains all 2,492 non-pseudo Hexagon instruction records and
465 `InstAlias` records, plus their register classes/registers, predicates,
subtarget features and processor definitions. Unused TableGen properties were
removed to keep the fixture small. Source: LLVM `llvmorg-22.1.8`, commit
`ca7933e47d3a3451d81e72ac174dcb5aa28b59d1`; upstream license is retained in
`testdata/LICENSE.LLVM`. These are real target definitions, not hand-written
instruction examples.

The resulting catalog has 2,417 ordinary/extender forms, 52 compact subinstructions,
and 465 aliases. Fifteen legal duplex shell classes are reconstructed from their
paired subinstruction groups. Eight records have explicit unsupported diagnostics:
`CONST32` and `CONST64` require constant-pool lowering;
`TFRI64_V2_ext` and `TFRI64_V4` are assembler parser rewrites without distinct opcodes;
`HI`/`LO` are relocation fragments rather than standalone instructions;
`invalid_decode` is LLVM's internal sentinel; `DuplexIClassF` is reserved.

LLVM's `HexagonAsmParser::processInstruction` rewrites `TFRI64_V2_ext`
(`r1:0 = combine(##high32,#low8)`) to `A2_combineii`. That physical syntax,
including its extender, is already accepted by `AssemblePacket`.
`TFRI64_V4` (`r1:0 = [#]#constant`) splits a constant into signed high32 and
unsigned low32, then emits `A4_combineii` and an optional `A4_ext`. The high32
must fit signed eight bits: this spelling does not materialize arbitrary 64-bit
constants. For example, `r1:0 = ##305419896` lowers to
`r1:0 = combine(#0,##305419896)`. Use that physical combine syntax in the packet
codec. The pair-constant spelling and symbolic operands are available through
`pkg/object.Assemble` with an explicitly selected LLVM Hexagon assembler;
unresolved operands retain the real extender/consumer relocation pair. Neither
parser record provides an independent instruction encoding to decode. Tests
compare both rewrites against native ELF bytes, signed limits, the low32 63/64
extender boundary, and external-symbol relocations through the complete-program
API. These parser rewrites do not require a constant pool; `CONST64` is the separate
pool-producing form.

Go consumers use `DecodePacket`, `EncodePacket`, `FormatPacket`, and
`AssemblePacket`. A `Word` contains one full instruction or two compact
subinstructions. Values are semantic register encodings and assembler immediate values;
branch values are byte displacements relative to the packet address. Words retain their physical order.
The encoder inserts immediate extenders when needed, also accepts explicit extender
words, and resolves `.new` register operands against prior packet producers.
Source register domains include high duplex registers, register pairs, vector pair
rotation and special/control register spellings. 17 CPU profiles and 90 HVX length/FP
variants are exposed through `FeatureSets`; nil features accepts the source union.

The backend validates framing, four-word/four-instruction bounds, legal duplex
class pairings, loop markers, extender adjacency/consumption, immediate alignment
and ranges, new-value references, register domains and solo instructions. It does
not reproduce LLVM's packet scheduler/resource allocator, all predicate producer
and hazard checks, object relocations or compiler lowering. Encoding an explicitly
ordered packet does not establish that arbitrary combinations can execute on a
specific core. These boundaries apply to the Go and generated Rust APIs.

Validation commands:

```
go test ./pkg/hexagon
MKASM_LLVM_MC=/path/to/llvm-mc go test ./pkg/hexagon -run TestLLVMCombineParserLowering -v
HEXAGON_FULL_CORPUS=1 HEXAGON_ARTIFACTS=<artifact-directory> go test ./pkg/hexagon -run TestCompleteLLVMCorpus -v
HEXAGON_RUST=1 HEXAGON_RUST_OUTPUT=<generated-crate> go test ./pkg/hexagon -run TestGeneratedRust -v
```

The full LLVM comparison attempts every imported non-extender form and alias,
with zero, positive bit-pattern and signed/aligned negative representatives:
8,799 cases over 2,933 forms. With v81/HVX/FP and a legacy v60 CABAC object,
8,701 cases match the explicit encoding exactly and LLVM selects alternative
encodings/packet order for 87 others. All 8,788 emitted ELF object packets decode
and re-encode byte-for-byte, covering 2,932 distinct forms. Additional rejected
representatives expose packet register hazards or a narrower alias operand domain;
those do not reduce the distinct form coverage.
One real TableGen source spelling (`V6_vconv_h_hf_rnd`, `v0.h = v1.hf:rnd`) is rejected
by LLVM 22.1.8's assembler; its declarative fields are covered by the generated
full-catalog field round trip, not independent assembler parity. Retained artifacts
contain the assembly, ELF objects, LLVM diagnostics and per-form cases JSON.
