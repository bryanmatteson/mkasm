`llvm22.json.gz` contains the concrete non-pseudo Instruction records from
LLVM llvmorg-22.1.8 `AMDGPU.td`, resolved by `llvm-tblgen --dump-json`, together
with their operand classes, register classes, predicates, processors, and feature
closure. Source-defined `isAsmParserOnly` records with concrete instruction bits
are retained: MIMG uses these records for legal assembly encodings.

The fixture retains the source bit arrays, operand DAGs and metadata consumed by
the adapter. It does not contain a hand-written opcode list. Production `Parse`
also accepts the unfiltered resolved LLVM JSON dump.

Source: https://github.com/llvm/llvm-project/tree/llvmorg-22.1.8/llvm/lib/Target/AMDGPU
LLVM source license: Apache-2.0 WITH LLVM-exception.

Regenerate the full input with:

    llvm-tblgen --dump-json -I llvm/include -I llvm/lib/Target/AMDGPU \
      llvm/lib/Target/AMDGPU/AMDGPU.td -o amdgpu.json

`MKASM_AMDGPU_TABLEGEN` selects a fresh complete JSON dump for the whole-corpus
LLVM byte comparison. `MKASM_AMDGPU_ARTIFACTS` selects the directory for oracle
assembly, ELF objects, bytes, diagnostics, and `parity.json`; `MKASM_AMDGPU_RUST` additionally
writes the complete generated dependency-free Rust crate there. Normal tests
exercise actual LLVM shader instructions through text assembly, structured
stream decode, formatting, and exact re-encoding.

For example, using a complete resolved dump and a dedicated artifact directory:

    MKASM_AMDGPU_TABLEGEN=/path/to/amdgpu.json \
      MKASM_AMDGPU_ARTIFACTS=/path/to/artifacts \
      MKASM_AMDGPU_RUST=/path/to/artifacts/rust \
      go test ./pkg/amdgpu -run TestFullLLVMCorpus -v -count=1
    cargo test --manifest-path /path/to/artifacts/rust/Cargo.toml --lib --test consumer

The generated library test exercises every emitted form through structured
encoding, stream decoding, formatting, and text assembly. The public consumer
uses independent LLVM bytes for ordinary ALU, True16, NSA image, and 64-bit
literal instructions, and binds and matches a register through the text-template
API, rejects source operand-domain violations, and resolves a relative branch
target. The strict oracle compares ordinary parser-supported samples with both LLVM
encoding annotations and the emitted ELF `.text` section. The `NonParsable`
alternate physical forms never enter LLVM's text parser.
`native-alternates.cpp` links against the installed LLVM library and independently
decodes their original bytes, records status and consumed length, and re-emits
each MCInst with LLVM's code emitter. `parity.json` retains each exact private
spelling, operand map and original bytes alongside LLVM's opcode, text and bytes.
Exact native re-emission, normalization and native rejections are separate result
arrays; normalization does not count as exact byte parity. Hidden SGPR offsets
are sampled at 0, 1, 127, 256 and 511, with exact codec text/byte retention required.
The helper uses `llvm-config` for matching headers/libraries, overridden by
`MKASM_AMDGPU_LLVM_CONFIG`, and `CXX` or `clang++` for compilation. Its report keeps exact
unsupported source IDs and reasons, along with independent LLVM diagnostics.

`MKASM_AMDGPU_NATIVE_ORACLE` can select an already compiled copy of
`native-alternates.cpp` to reuse the same installed LLVM consumer executable.

The complete LLVM 22.1.8 dump run of this workflow covered 64,781 ordinary
representatives with exact LLVM assembly bytes, plus 36 VOPD alternatives whose
original bytes independently disassemble to the same text. All 64,817 ordinary
forms were checked against ELF `.text` bytes. The 670 alternate source records
expand to 916 physical forms; 1,436 native decode/re-emit samples include the
additional hidden-offset values. LLVM consumed every sample at its full length:
916 re-emitted exactly and 520 normalized. None were rejected or soft-failed.
These counts describe physical representatives, not every assembly-only spelling
in the 126,277-form catalog or every possible operand tuple. The 2,044 retained
unsupported source records remain explicit and are not counted as successful
native checks.
