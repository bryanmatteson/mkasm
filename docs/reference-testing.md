# Independent reference tests

`scripts/test-references.py` runs the real backends against separately implemented
assemblers, disassemblers and language runtimes. It includes every canonical
target reported by the supplied `mkasm --list-architectures` executable. A new
target without a reference job makes the runner fail. Additional jobs exercise
.NET metadata/binding/CLI and corrected microMIPS DSP instructions across
consumers, without inventing extra ISA targets.

The runner rejects missing requested tests, skipped parent or child tests, build
failures and nonzero exits. Individual tests report reference limitations and
alias choices separately. A passing job establishes its documented comparisons;
it does not mean that every possible operand, feature combination, program or
execution semantic has been proved correct. Generated round trips alone do not
supply independent evidence.

## Running

Install the independent tools and export the full source corpora first. The
runner never downloads a replacement tool or falls back to a fixture when a live
reference is required. The [example configuration](reference-tools.example.json)
lists the explicit paths. JSON values are literal strings: shell variables and
`~` inside the file are not expanded. Java 21, the fixture-pinned .NET SDK,
Python, Go, the managed Cargo shim and a C compiler must be available on `PATH`.

```sh
go build -o "$HOME/Documents/Developer/go-mkasm/reference-correctness/mkasm" ./cmd/mkasm
python3 scripts/test-references.py \
  --config /absolute/path/reference-tools.json \
  --output "$HOME/Documents/Developer/go-mkasm/reference-correctness/run" \
  --cli "$HOME/Documents/Developer/go-mkasm/reference-correctness/mkasm" \
  --jobs 4
```

There are 45 jobs for the current 90-target registry. Run only affected jobs with
`--only arm32,micromips64,micromips64el`, using a separate output directory to
preserve the original logs. A focused report identifies only its selected jobs;
it does not establish an all-target pass. Each `*.jsonl` contains Go test events
and native tool diagnostics. `summary.json` records commands, target names,
reference implementations, scope, test execution and outcomes.

The installed LLVM must support the corresponding targets. Ghidra tests compile
and execute its actual SLEIGH/assembler implementations through the repository's
oracle adapter. ARC tests compile the original GNU operand insertion routines;
the adapter contains no independently transcribed encoding tables. The native
tools and their source inputs are configured separately, so importing a corpus
does not count as executing its reference implementation.

## Reference and coverage boundaries

| Targets | Independent implementation | Compared behavior |
|---|---|---|
| AArch64 | LLVM MC and Clang | Complete 4,623-encoding Go and Rust exact-encoder ledgers, with zero unverified samples. All 65,408 allocated extended hints checked via native MRS/MSR system syntax; all 128 reserved hint values rejected by the generated checked APIs. |
| ARM32 | LLVM MC | 12,326 vectors from upstream basic A32/Thumb16/Thumb32 and NEON tests plus regression programs, both byte orders, through a fresh CLI-generated full-corpus Rust codec. Raw field re-encoding is exact; formatted output is independently assembled, with equivalent modified-immediate and wrapping/zero ADR spellings counted separately. Regression vectors also check structured register lists, shifts, scaled immediates, alignment and writeback. Native instructions outside the imported XML allocation vocabulary are reported and not counted. |
| x86-32/64 | LLVM MC | 11,788 live upstream scalar/AVX/AVX512 vectors in 16/32/64 modes, decoded by Go and re-encoded by fresh Rust. The strict runner uses CLI generation. Standalone prefixes, relocatable fragments and instructions outside the source catalog are separate from instruction coverage. |
| AVR, eBPF, LoongArch, PowerPC, SystemZ | LLVM MC | Imported physical forms, with target-specific operand profiles and explicit relocation/alias handling. |
| RISC-V | LLVM MC and the upstream opcode parser | Every imported record (1,620 RV32; 1,568 RV64), native match/mask comparison, 255,924 physical boundary/random patterns through Go and fresh Rust, and fixed-bit rejection. LLVM extension vectors separately check semantic operands. The parser is a physical-allocation reference, not an execution engine. |
| SPARC | LLVM MC and GNU assembler | All 2,528 SPARC32 samples and 3,091 SPARC64 samples. GNU covers 34 LLVM32 vocabulary gaps. GNU has no ELF32LE backend: LE checks serialize the native GNU physical instruction word in little endian. Zero uncovered imported samples. |
| AMDGPU | LLVM MC emitter, assembler and disassembler | Assemblable representatives and alternate source layouts; distinguish aliases, normalized encodings and unsupported source records. |
| ARC classic, ARCv3 and NPS400 | Compiled GNU binutils insertion functions | Three operand samples per imported form, in every registered profile and byte order. |
| Hexagon | LLVM MC and ELF objects | All 8,799 samples independently checked: 8,712 exact and 87 legal alternative selections; zero rejections. Three LLVM parser spelling gaps use its real decoder/code emitter. All 8,796 native packet/object comparisons pass. |
| MSP430/MSP430X | GNU assembler and linker | All imported physical forms and complete object bytes. |
| Standard MIPS32/64, both byte orders | LLVM MC | Every source form; choose CPU/features from the source predicates. |
| microMIPS32, both byte orders | LLVM MC and GNU assembler | 856 physical source forms checked against LLVM, five corrected DSP forms checked against GNU; ten derived textual spellings tracked separately. |
| microMIPS64, both byte orders | LLVM microMIPS32 physical ISA and GNU ELF64 assembler/linker | All 946 physical source rows checked with LLVM/GNU, including 85 GNU64-only rows absent from LLVM. Native linked ELF64 checks 688 r5 forms; 13,216 valid native GNU operand boundary samples and 3,405 native-invalid candidates per byte order also pass Go and fresh CLI-generated Rust. An additional 93 zero-size DINS patterns expose a GNU admission defect and remain rejected by the codecs. Twelve additional ABI vectors remain. LLVM has no microMIPS64 backend and GNU rejects microMIPS64r6, so r6 remains explicitly checked against the native physical-ISA reference. Use `MIPS64_LD` for GNU ld: LLD rejects microMIPS64 objects. |
| MIPS16, four selectors | GNU assembler and compiled GNU disassembler | Every machine row, six upstream assembler corpora and context/address-width boundaries. |
| M68K/ColdFire | GNU assembler and disassembler | Source template lengths and independent operand vectors, with explicit upstream exceptions. |
| TriCore/PCP | Ghidra | Native decoding and assembly of physical forms in both modes. |
| PIC/dsPIC, all 16 selectors | Live Ghidra assembler/disassembler/solver and gputils | All 23,607 union forms decoded and assembled: 23,179 exact default selections, 421 independently validated native solver alternatives, seven native gputils checks for unsupported/corrected samples. Expected bytes are never supplied to the solver. |
| V850 | GNU assembler | Full physical corpus and boundary vectors. |
| MOS6502 | ca65/da65 | Documented profiles and independent disassembly; reserved NOPs are identified separately. |
| W65C816 | ca65 | All 256 opcode slots in all four M/X width states; WDM's raw-data escape is explicitly not native mnemonic coverage. |
| Z80/Z180/eZ80/Z80N/R800/Game Boy | GNU assembler | Imported source forms and complete candidate sets for aliases. |
| 8051/DS80C390 | Live SDCC assembler and linker | All 255 defined opcodes, three operand patterns in each target: 1,530 linked native byte comparisons. |
| Xtensa, both byte orders | GNU, LLVM, Ghidra and native vendor fields | All 4,158 physical samples (2,355 LE; 1,803 BE) require independent matches, then pass Go and fresh CLI Rust. Optional BE formats combine native LE instruction selection with vendor BE field functions; this is physical layout validation, not native execution on the BE core. |
| JVM | OpenJDK ASM, javac, javap and JVM | All 201 legal standalone opcodes and 12 wide modifications, four alignments and two operand cases: 1,704 independently emitted vectors. Also verify and execute a rewritten compiler-produced class. |
| .NET CIL | Live Reflection.Emit and PEReader | All 218 opcodes and descriptors, compiler-produced method/EH bodies and prefix execution. |
| .NET metadata and CLI | Roslyn, Reflection, PEReader, PortablePDB reader and CLR | Live cross-assembly/enum/netmodule references; executable rewrite; CLI JSON and fresh CLI-generated Rust for four managed PE images and three Portable PDBs compared to fresh Microsoft-reader output. |
| Android DEX | smali, baksmali and dexlib2 | Non-reserved opcode/payload forms and a real DEX assembly workflow. |
| WebAssembly32/64 | wasmparser, wasm-encoder, WAT parser and Validator | All 626 opcode forms in each target, plus valid memory/SIMD/GC/memory64 modules. |
| SPIR-V | SPIRV-Tools | Every core grammar instruction and complete validated compute modules. |
| PTX | LLVM llc and NVIDIA ptxas | All 594 native NVIDIA RUN configurations from the LLVM22 NVPTX corpus, including 575 static-IR cases and 19 upstream-generated matrix/texture/address-space cases, totaling 300,833 instructions through Go and fresh CLI Rust. The original 37-program/8,188-instruction cohort and PTX9.5/negative cases remain. Native CUDA8, 11.8, 12.9 and current assemblers cover legacy 32-bit PTX and SM20 through modern targets. The unsupported SM90/32-bit ABI RUN must reproduce NVIDIA's explicit rejection in both consumers; accepted programs require native success. This is a complete primary native RUN cohort, not every possible opcode/modifier combination. |

The precise measured counts and remaining reference gaps belong to the run's
logs. For example, an unrecognized A64 instruction is not converted into a byte
match, and a PIC alternate assembly is not counted as an exact assembly match.

The second microMIPS reference detects five incorrect LLVM 22 table layouts:
the `CMPGU` major opcode and the `SHLLV.PH`/`SHLLV_S.PH` function bits. The
importer corrects those fixed bits while preserving source operands and features.
`TestIndependentMicroDSPConsumers` compares 60 GNU boundary vectors through Go
and four fresh CLI-generated Rust crates. It does not accept the known incorrect
LLVM bytes as an alternate encoding. GNU also disassembles the original LLVM
patterns as unknown instructions. LLVM/GNU's unary `wrdsp` alias defaults differ
(`0x1f`/`0x3f`); explicit mask forms retain their actual semantics.

## Independent vectors in generated Rust

The JVM, CIL and PTX tests optionally export fresh crates and reference tests via
`MKASM_JVM_REFERENCE_RUST`, `MKASM_CIL_REFERENCE_RUST` and
`MKASM_PTX_REFERENCE_RUST`. JVM vectors come from the live Java ASM emitter;
CIL vectors come from the live .NET emitter. PTX's generated integration test
calls the configured NVIDIA assembler directly for all three original/rebuilt
and negative modules. The broader PTX job retains its separate crate using
`MKASM_PTX_CORPUS_RUST`; the complete native RUN cohort uses
`MKASM_PTX_UPSTREAM_RUST`. ARM32 and x86 reference jobs build and execute
their freshly generated Rust consumers.

The .NET CLI job always runs a freshly generated managed Rust consumer against
the live Microsoft-reader output, then executes its rewritten assembly in the
real CLR as well as the CLI's rewritten assembly. `MKASM_DOTNET_REFERENCE_RUST` optionally retains
that crate; `MKASM_MIPS_DSP_REFERENCE_RUST` retains the four-crate DSP workspace.

After exporting the three optional crates, put them in an artifact workspace and
run one normal Cargo invocation with explicit targets:

```toml
[workspace]
resolver = "2"
members = ["jvm-rust", "cil-rust", "ptx-rust"]
```

```sh
cargo test --manifest-path /absolute/path/artifacts/Cargo.toml --workspace --lib --tests
```

`MKASM_PTX_VALIDATOR` is a JSON argv array, with `{target}` expanded to the
module's declared SM target. For an installed native tool, use
`["/absolute/path/ptxas","-arch={target}","-","-o","/dev/null"]`.
A container invocation can use the same contract. Copy the NVIDIA executable
into a local image if executing a binary through a host bind mount stalls;
container startup failure is a failed test, never semantic success. No CUDA
driver or GPU is needed to assemble these programs.

Native Xtensa configurations are built from explicit unmodified binutils and
QEMU `core-test_kc705_be` source with `scripts/build-xtensa-reference.py`.
Configure `MKASM_XTENSA_LE_CONFIG`, `MKASM_XTENSA_BE_CONFIG` and
`MKASM_XTENSA_NATIVE_FIELDS` to its three libraries (`.dylib` on macOS, `.so` on
Linux). No source is downloaded by the builder. The optional floating-point
reference calls the actual vendor field functions and contains no copied
encoding masks. Ghidra disagreements need another exact native reference for
the same input and cannot be accepted as alternatives.

`MKASM_PTX_LEGACY_VALIDATOR` is a JSON argv list using the same `{target}`
substitution as `MKASM_PTX_VALIDATOR`, but it must select a native NVIDIA ptxas
version that still supports SM60 (CUDA12.9 was validated). Compiler-generated
external-call modules use native relocatable compilation (`-c`), preserving real
external symbols. No source stubs are invented to satisfy final linking.

`MKASM_PTX_32_VALIDATOR` selects CUDA11.8 for 32-bit PTX programs;
`MKASM_PTX_FERMI_VALIDATOR` selects CUDA8.0 for explicitly requested SM20/35.
The upstream RUN adapter retains every primary compiler option and explicit
NVIDIA target. It strips the normal validator target placeholder, preserving
the primary test's native default when no target flag is present, and supplies
`-m32` for modules with a 32-bit address size. SM101a RUN cases use CUDA12.9,
which retains that target spelling. An unavailable native version fails the
strict job. The test neither rewrites target declarations nor excludes old cases. LLVM's
SM90/32-bit ABI case remains a native negative check because NVIDIA rejects
that combination. Upstream Python generators run with their original options
and task-owned IR/list outputs; no source or FileCheck expected text substitutes
for live LLVM output.

`MKASM_RISCV_REFERENCE_RUST`, `MKASM_XTENSA_REFERENCE_RUST`,
`MKASM_X86_REFERENCE_RUST`, `MKASM_ARM32_REFERENCE_RUST` and `MKASM_MIPS64_REFERENCE_RUST` optionally retain
fresh independent-reference consumers. Without an output override, tests use
and clean their own temporary directories.

The separate ARM crypto semantic checks execute independent scalar algorithms,
published cipher vectors and native fixed-width crypto instructions where
available. They include adversarial SM4 byte selectors, register aliases and
SVE vector lengths through 2,048 bits, with a checked aggregate expression
budget. Run:

```sh
go test ./pkg/semantics -run '^(TestRustA64SVECrypto|TestRustA64CryptoSIMD)$' -count=1 -v
go test ./pkg/arm -run '^TestRustA64SVECryptoCorpus$' -count=1 -v
```

Setting `MKASM_REFERENCE_CLI` makes the latter generate its full AArch64 crate
through that executable; `MKASM_A64_SVE_REFERENCE_RUST` optionally retains the
crate, compiled consumer and fixture. These semantic checks are additional to
the 45-job physical-codec reference run.
