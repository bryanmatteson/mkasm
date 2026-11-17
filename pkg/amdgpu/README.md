# AMD GCN and RDNA instruction streams

`Parse(reader, "amdgpu")` imports resolved LLVM TableGen JSON. `amdgcn` is an
accepted architecture alias. The returned `codec.Catalog` implements structured
encoding, stream decoding, formatting, text assembly, JSON export, and generation
of the dependency-free Rust codec and text-template API.

Select a processor profile from `catalog.FeatureSets`, for example `gfx900`,
`gfx1100`, or `gfx1250`, when decoding or assembling. Encodings overlap between
GPU generations. Explicit `-wave32`, `-wave64`, and `-true16` profile suffixes
select source-supported alternatives. Base profiles follow LLVM's default wave
size and source processor feature closure. Some shared byte prefixes also have
generation-dependent instruction lengths; select the actual processor profile
for reliable stream framing.

The adapter imports source instruction bits and operand DAGs. It accounts for
SGPR/VGPR/AGPR selectors, inline constants and input modifiers, wave-dependent
Boolean registers, True16 half registers, signed/scaled relative branches,
DPP/SDWA controls, exports, cache policies, mandatory/shared literals, 64-bit
literals, MIMG NSA address bytes, and VOPD/VOPD3 streams. Literal operands describe
the physical literal word; a literal shared by multiple sources has one semantic
catalog operand. Register tuple alignment, image data/address domains, and VOPD
bank relations are part of encode and decode validation.

The bundled LLVM 22.1.8 source fixture has 36,223 concrete non-pseudo instruction
records, including concrete `isAsmParserOnly` image definitions. Each source ID is
represented by encoding forms or an explicit `Unsupported` entry. Source records
with impossible image tuple domains, store TFE forms, branch-relaxation
composites and feature conditions satisfied by no source processor profile are
excluded with a reason. LLVM's `NonParsable`
alternate physical definitions remain available with explicit `enc[ID]` syntax
and named operands for otherwise unprinted bits. That syntax preserves physical
fields; it is private codec syntax, not LLVM assembler input. `Unsupported` is also
exported in JSON and generated Rust. The source fixture and generated catalog
retain LLVM's Apache-2.0 WITH LLVM-exception notice.

The source domain rules follow these LLVM implementation symbols:

- `AMDGPUAsmParser::validateMIMGDataSize`, `validateMIMGAddrSize`,
  `validateMIMGAtomicDMask`, `validateMIMGGatherDMask`, and `validateMIMGMSAA` in
  `llvm/lib/Target/AMDGPU/AsmParser/AMDGPUAsmParser.cpp`.
- `AMDGPU::getAddrSizeMIMGOp`, `VOPD::InstInfo::getInvalidCompOperandIndex`, and
  its `banksOverlap` helper in `llvm/lib/Target/AMDGPU/Utils/AMDGPUBaseInfo.cpp`.
  The bank masks are `VOPD_VGPR_BANK_MASKS` and `VOPD3_VGPR_BANK_MASKS` in the
  corresponding header. These rules include 64-bit source spans, scalar-source
  exclusions, tied accumulator sources, and GFX12.5 same-register reuse.
- `AMDGPUAsmParser::validateVGPRAlign`, `validateMAISrc2`, `validateOpSel`, and
  `validateDPP` for processor-dependent operand restrictions.
- `AMDGPUMCCodeEmitter::encodeInstruction`, `getMachineOpValueT16`,
  `getMachineOpValueT16Lo128`, `getAVOperandEncoding`, and the SDWA encoders in
  `llvm/lib/Target/AMDGPU/MCTargetDesc/AMDGPUMCCodeEmitter.cpp`.
- `AMDGPUInstPrinter::printR128A16` uses `FeatureR128A16` for the GFX9
  resource-bit alias. GFX10's separate A16 control keeps a distinct operand.

Numeric forms are used for wait counts, send-message values, delay controls, and
similar encoded immediate fields. Free-form LLVM expressions such as
`vmcnt(0) lgkmcnt(0)` and arbitrary `InstAlias` definitions are not imported.
Source instruction encodings remain available through their numeric syntax.
The input is the GCN/RDNA `AMDGPU.td` corpus; LLVM's separate R600 backend and
code-object containers are outside this stream adapter.

`go test ./pkg/amdgpu` exercises the complete source import, source accounting,
LLVM shader instructions, invalid operand domains, relative targets, and a
load–wait–compute–store kernel stream. See `testdata/README.md` for whole-corpus
LLVM comparison and generated Rust consumer commands. The strict whole-corpus
check sends ordinary parser-supported forms to LLVM assembly and object emission,
and fails on rejected representatives, byte mismatches, encode errors or forms
without a processor profile. Alternate `NonParsable` forms instead use a helper
linked to the installed LLVM library: its compiled disassembler consumes the
original bytes, and its code emitter re-emits the decoded MCInst. The report
separates exact re-emission from normalization and rejected/soft-failed decodes.
Exact codec syntax/bytes and operand maps remain in the report even when LLVM
drops hidden fields. Decoder acceptance with normalization is independent decoder
coverage, not native assembler byte parity. The helper requires matching LLVM
headers/libraries and `llvm-config` (override with `MKASM_AMDGPU_LLVM_CONFIG`),
plus a C++ compiler (`CXX` or `clang++`). LLVM canonicalizes a few valid VOPD
forms to another framing; those original bytes must independently disassemble
to the same text and exact bytes before being accepted as encoding alternatives.
