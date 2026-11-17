# Architecture codecs

`mkasm --list-architectures` lists the target names recognized by the current
executable. A target identifies an instruction stream, not the machine running
the generator. Generated Rust projects run on any host supported by Rust.

The Arm XML and x86 opcodesDB backends retain their existing public APIs and
input formats. Additional backends share CLI loading and generation, with
architecture-specific operand and framing models where required.

## Target families

The inventory contains 90 canonical CLI targets. CPU profiles select
source-defined extensions inside a target; they do not infer the instruction set
from the host. Target registration is separate from corpus and consumer validation;
this inventory does not claim an all-target validation pass.

| Family | Targets | Imported specification |
|---|---|---|
| Arm | `aarch64`, `arm32` (A32 and Thumb) | Arm XML |
| x86 | `x86_32`, `x86_64` | opcodesDB v3; both crates retain explicit 16/32/64-bit mode APIs |
| RISC-V | `riscv32`, `riscv64` | riscv-opcodes |
| MIPS | `mips32`, `mips32el`, `mips64`, `mips64el`, `micromips32`, `micromips32el`, `micromips64`, `micromips64el`, `mips16`, `mips16el`, `mips16-64`, `mips16-64el` | LLVM TableGen; complete non-macro GNU MIPS16 table and 85 GNU microMIPS64-only machine rows |
| PowerPC | `powerpc32`, `powerpc32le`, `powerpc64`, `powerpc64le` | LLVM TableGen |
| LoongArch | `loongarch32`, `loongarch64` | LLVM TableGen |
| SPARC | `sparc32`, `sparc32le`, `sparc64` | LLVM TableGen |
| IBM Z | `systemz` | LLVM TableGen |
| ARC | `arc600`, `arc700`, `arcem`, `arc32`, `arc64`, `arcv3-32`, `arcnps400`, and each name suffixed `be` | GNU opcode tables; ARCv2 HS uses `arc32`, ARCv3 uses its resolved source tables |
| Hexagon | `hexagon` | LLVM TableGen, packet/extender/duplex framing |
| V850 | `v850` | GNU binutils |
| TriCore | `tricore`, `tricore-pcp` | Ghidra SLEIGH |
| MSP430 | `msp430`, `msp430x` | LLVM TableGen and retained GNU/Ghidra extension definitions |
| AVR | `avr` | LLVM TableGen |
| Motorola 68k | `m68k`, `coldfire` | GNU binutils |
| Xtensa | `xtensa`, `xtensaeb` | LLVM, GNU and Ghidra scalar/FLIX definitions; validated resolved processor configurations |
| MOS 6502 | `mos6502` | cc65; classic, undocumented and CMOS profiles |
| WDC 65C816 | `w65c816` | cc65 and WDC framing; explicit E/M/X execution context |
| MCS-51 | `mcs51`, `mcs80390` | Ghidra; classic 8051 and DS80C390 flat-24 |
| Zilog and derivatives | `z80`, `z180`, `ez80`, `ez80-adl`, `z80n`, `r800`, `gbz80` | MAME, GNU and Ghidra; separate eZ80 immediate/address-width modes |
| PIC | `pic12`, `pic16c5x`, `pic14`, `pic14-enhanced`, `pic16`, `pic17`, `pic18`, `pic24`, `pic24e`, `pic24f`, `pic24h`, `dspic`, `dspic30f`, `dspic33f`, `dspic33e`, `dspic33c` | Complete Ghidra PIC language exports; `pic16` selects the PIC17 16-bit instruction stream |
| eBPF | `bpfel`, `bpfeb` | LLVM TableGen |
| JVM | `jvm` | OpenJDK bytecode definitions |
| Android DEX | `dex` | AOSP ART instruction definitions |
| .NET | `cil` | .NET opcode definitions, PE/CLI metadata and Portable PDB |
| WebAssembly | `wasm32`, `wasm64` | wasm-tools grammar |
| SPIR-V | `spirv` | Khronos core grammar |
| AMD GPU | `amdgpu` | LLVM GCN/RDNA TableGen and source processor predicates |
| NVIDIA PTX | `ptx` | NVIDIA PTX reference and LLVM NVPTX templates; textual modules |

Each package retains source pins, notices, behavioral tests and its precise
coverage limits. MIPS, microMIPS and MIPS16 are separate instruction streams;
unsuffixed MIPS names select big endian and `el` selects little endian.
`mips16-64` and `mips16-64el` retain the full 64-bit program counter for
MIPS16 execution on MIPS64. MIPS16 PC-relative data accesses in a delay slot use
the preceding branch's PC base; the Go and generated Rust execution-context APIs
accept that base explicitly. W65C816
is separate from MOS 6502 and requires the actual E/M/X state for immediate
framing. Xtensa accepts supplied physical TIE/FLIX descriptions, but cannot infer
proprietary encodings that are absent from the input configuration.

## Generating and inspecting a codec

```sh
mkasm --arch riscv64 --codegen rust --output ./riscv64-rs ./riscv-opcodes
mkasm --arch avr --cpu atmega328p --codegen rust --output ./avr-rs ./avr.json
mkasm --arch jvm --codegen rust --output ./jvm-rs ./bytecodes.cpp
mkasm --arch dex --codegen rust --output ./dex-rs ./dex_instruction_list.h
mkasm --arch wasm64 --codegen rust --output ./wasm-rs ./wasm-opcodes.json
mkasm --arch spirv --codegen rust --output ./spirv-rs ./spirv.core.grammar.json
mkasm --arch cil --codegen rust --output ./cil-rs ./opcode.def
mkasm --arch cil --inspect --json ./Example.dll > Example.managed.json
mkasm --arch ptx --codegen rust --output ./ptx-rs ./ptx-registry.json
mkasm --arch loongarch64 --json ./loongarch.json > loongarch-ir.json
```

Input may be a file, an HTTP(S) URL, or `-` for stdin. RISC-V also accepts an
unpacked upstream directory. Compressed JSON files ending in `.json.gz` are
decoded in the loader. Progress and coverage diagnostics go to stderr; JSON
goes only to stdout. Rust generation writes a standalone project under the
requested output directory.

`--arch x86_32` writes an `x86_32` crate whose `DEFAULT_MODE`, `assemble`,
`assemble_at`, `Template::parse`/`parse_at`, `describe` and default encoding fields
select 32-bit execution. `x86_64` selects 64-bit execution. Both crates retain
the explicit `_in_mode` APIs for 16-, 32- and 64-bit execution. Generator callers
can also choose a 16-bit default with `x86.GenerateRustForMode`.
`Decoded::branch_target`, formatting, absolute-target assembly and relocation
respect the effective instruction-pointer width, including operand-size
overrides. `encode_relative_branch` selects the crate default; its `_in_mode`
counterpart selects an explicit mode. Generic `Position` arithmetic remains a
64-bit address calculation; use the decoded target API when legacy IP wrapping
matters.

Generated x86 crates expose `Decoded::format_intel_into(ip, &mut String)` and
`format_intel_into(&decoded, ip, &mut String)` for repeated formatting. Both
replace the string's contents and retain its capacity; rendering allocates
nothing when that capacity is sufficient. `format_intel` remains the owned
convenience API.

Generated A64 and A32/Thumb crates expose
`Decoded::format_into(address, &mut String)`. A64 also exposes
`format_into(word, address, &mut String)`. They replace the buffer's contents,
retain its capacity, and clear it on formatting errors. With enough capacity
for the unnormalized instruction text, formatting allocates nothing, including
register lists, optional syntax, system registers and complex immediates.
The owned `format` methods share these renderers. A64 uses the structured
analysis candidate buckets and their alias-selection rules. A32 text formatting
skips the operand and register-access collections used by `details` and
`presentation`; those APIs retain their complete projections.

A64, A32/Thumb, x86, x64 and shared fixed-field backends such as RISC-V use
shared stack-based decimal and hexadecimal writers for integer text. Register
indices and small values use immutable digit tables; no temporary strings or
runtime caches are created. Floating-point formatting retains its existing
behavior. Fixed-field format literals resolve escaped braces during generation,
and named operands with an identity transform skip division and lookup during
rendering. For RISC-V, `Decoded::write_to(address, &mut impl fmt::Write)` appends
to the supplied writer; clear a reusable `String` before each instruction.

The generator resolves immutable formatter decisions before runtime: A64 uses
priority-ordered 12-bit candidate buckets and stops at the first legal form;
x86 and x64 intern lowercase mnemonic text and store prefix/decorator flags
while retaining mode-dependent aliases. Mnemonic indices use 16 bits when the
imported set fits, preserving the current encoding record size, and widen to
32 bits for larger sets. A32/Thumb field lookup uses a compact
rejection key in the existing field metadata padding, followed by full name
comparison so collisions preserve correctness. Shared named operand formatting
stores its identity-transform decision in operand metadata. These paths require
no lazily initialized caches or per-instruction heap storage.

Decoders refine source trees with leaves larger than 64 candidates using bounded
bit-based dispatch. Narrow source trees retain direct preferred-candidate slices.
Both paths precompute candidate preference order, stopping
at the first legal match while preserving the original order of the lazy
ambiguity view. A64 formatting borrows operand metadata and evaluates each
optional syntax group once. A32 resolves register values only for register
symbols and evaluates field fallbacks lazily. x86 operand presentation rules
share the existing flags word, with mode checks retained at runtime. Shared
fixed-field writers can combine a small identity-name table with its following
comma into a single write; described operand spans still exclude punctuation.
Fixed-field decoders precompute encoded operand widths and whether dependent
bias or implicit-value checks are needed.

Generated A64 exact/raw encoder tests check field placement independently of
allocation legality. Illegal field combinations must be rejected by the checked
table encoder; additional legal probes test successful encoding where available.
This preserves the unchecked field-placement APIs and the checked encoder's
allocation constraints.

Generated x86 text assembly and templates preserve `{sae}` and all four embedded
rounding decorations printed by the decoder, including descriptions and edited
forms. Operand domains remain conservative for forms that forbid matching source
and destination registers; an interval containing such exclusions is not exact.

`--cpu NAME` selects a source-defined profile where the backend supplies one.
Unknown profiles are errors. `--strict-corpus` rejects fixed-field corpora with
unsupported source records before generation. Without it, unsupported records
remain explicit in the JSON export and generated `UNSUPPORTED` registry.
An unsupported record is never represented by a fabricated encoding.

## Native specification sources

RISC-V consumes the upstream `riscv-opcodes` directory or a tar/tar.gz archive
containing `arg_lut.csv` and `extensions/`. The importer resolves regular
definitions, aliases and imports and filters instructions by XLEN. Physical
bits left unnamed by experimental source definitions are exposed as required
unsigned `RawEncodingBits` operands. Their text spellings retain those values;
the importer does not assign an invented semantic meaning or a constant value.

LLVM-based backends consume **resolved** TableGen JSON, rather than attempting
to interpret `.td` source text. Use the matching release of LLVM's sources and
`llvm-tblgen`:

```sh
python3 scripts/export-tablegen.py \
  --source /path/to/llvm-project \
  --llvm-tblgen /path/to/llvm-tblgen \
  --target loongarch --output ./loongarch.json

mkasm --arch loongarch64 --codegen rust --output ./loongarch64-rs ./loongarch.json
```

The exporter retains all upstream records. Each backend interprets its own
physical bit order, operand classes, transforms, aliases and feature predicates.
The checked LLVM fixtures use release 22.1.8. Package documentation records
source revisions and precise target-specific limitations.

M68k and ColdFire read GNU binutils' actual `opcodes/m68k-opc.c`; `--cpu` selects
their CPU/facility profile. ARC also accepts a binutils source tar containing
`arc-tbl.h`, `arc-opc.c`, and `arc-fxi.h`, covering ARC600/700 and ARCv2 EM/HS in
both byte orders. ARC64/ARCv3-32 use the resolved source export from `scripts/export-arc64.py`, and NPS400
requires the complete macro-resolved table from
`scripts/export-arc-nps400.py`; the older core table alone is insufficient. V850 reads binutils' `v850-opc.c` with the matching pinned
operand header and assembler source retained by the importer. TriCore reads
Ghidra's `tricore.sinc`, and `tricore-pcp` selects its separate peripheral
processor stream. Hexagon imports LLVM instruction records while preserving
complete packet framing, immediate extenders, duplex classes and packet-relative
targets.

MOS 6502 reads cc65's `opcodes.c`; `--cpu` selects its classic, undocumented or
CMOS profile. MCS-51 reads Ghidra's `8051_main.sinc`, and Z80/Z180 read the pinned
MAME `z80.lst`. The `ez80`, `ez80-adl`, `z80n`, `r800` and `gbz80` targets
load the retained resolved GNU variant catalog. W65C816 reads cc65
`OpcTable_65816`, with WDC corrections for signature bytes and long-address
framing; `m8x8`, `m8x16`, `m16x8`, `m16x16` and `emulation` profiles select
M/X widths. PIC reads the `mkasm.pic.sleigh.v1` JSON export produced by its
retained Ghidra exporter, including every constructor of the 13 source languages.
The package READMEs describe each export command and address-unit convention.
Xtensa also reads `mkasm.xtensa.v1` JSON describing scalar/TIE encodings and
FLIX slots with validated physical masks, byte order and packet lengths of
1–256 bytes. Context-aware formatting, assembly and relocation accept runtime
LITBASE; configuration input must supply any proprietary physical encoding.

PTX reads `pkg/ptx/testdata/registry.json`, reproduced from the pinned complete
NVIDIA reference and resolved LLVM NVPTX dump. The generated crate parses,
preserves and edits textual modules, supplies instruction/module templates and
checks source-scoped profiles. `Check` reports `SemanticComplete == false`;
`ValidateWith` invokes an explicitly selected primary assembler and marks
semantic completion only after that tool succeeds for its supported scope.

JVM reads OpenJDK's `bytecodes.cpp`; DEX reads AOSP
ART's `dex_instruction_list.h`. WebAssembly reads the resolved grammar produced
by `pkg/wasm/import_wasm_tools.py`. SPIR-V reads Khronos'
`spirv.core.grammar.json`. CIL reads .NET runtime's `opcode.def`. These parsers preserve instruction framing and context
rather than translating bytecodes into a CPU bit-mask approximation.

`--arch cil --inspect --json` reads an actual .NET PE32/PE32+ managed image,
standalone metadata, or Portable PDB. The managed report includes metadata table
and heap information, assembly/type/member identities, generic signatures,
method bodies, exception regions, decoded CIL and resolved instruction token
references, local signatures, catch types, properties, events, attributes,
resources and debug entries. Portable PDB inputs and embedded PDBs include
document names and method sequence points. Method implementation kinds preserve native, runtime, abstract and
P/Invoke distinctions. Source definitions are used for ordinary CIL generation;
the inspection mode takes the binary itself.

The CIL CLI generator includes a dependency-free `dotnet` Rust module in the
same crate. `inspect_managed_method(&image, token)` joins metadata lookup, CIL
method-body decoding and token resolution. The generated project includes real
PE32/PE32+ assemblies, embedded/standalone Portable PDB fixtures and consumer
tests for that combined API. The Go `pkg/cil` and `pkg/dotnet` packages remain
independently usable; their respective READMEs describe each library surface.

Managed inspection also resolves structured custom attributes, marshal descriptors
and declarative security. Explicit `--references` inputs resolve assembly
forwarders, netmodule `File`/`ExportedType`/`ModuleRef` scopes, escaped type names
and closed enums nested inside generic types. The same context-aware reference
APIs are available in Go and generated Rust. References are never loaded
implicitly; missing or ambiguous identities produce decode diagnostics.
`--native` includes ReadyToRun function bytes and
method mappings, with native ranges for the six .NET CPU families, generic
instances and composite components. Native ranges remain distinct from CIL
bodies; this is inspection, not native-code decompilation or CLR execution.

`--verify` checks CIL stack heights, variable bounds and declared `maxstack`.
Full type verification uses an explicitly selected ILVerify executable:

```sh
mkasm --arch cil --inspect --verify --json ./Example.dll > Example.verified.json
mkasm --arch cil --inspect --type-verifier /path/to/ILVerify \
  --references '/path/to/reference/*.dll' --json ./Example.dll
mkasm --arch cil --rewrite ./method-bodies.json --output ./Example.edited.dll ./Example.dll
```

The rewrite manifest maps MethodDef tokens (for example `"0x06000001"`) to hex
**complete method bodies**, including their headers and any exception sections.
Rewrites verify the replacement bodies before publishing the output file.
`--drop-native` explicitly removes ReadyToRun code when the required IL bodies
remain; `--strip-signatures` explicitly removes invalidated strong-name and
Authenticode signatures. See [managed-image APIs](../pkg/dotnet/README.md) and
[CIL verification](../pkg/cil/README.md) for exact checks and limitations.

## Complete-program object assembly

The Go `object.Assemble(ctx, source, object.Options)` API in `pkg/object`, generated
Rust `object::assemble` API and CLI accept an explicitly selected assembler.
They retain the complete object, including unresolved symbols and relocations:

```sh
mkasm --assemble-object --assembler /path/to/llvm-mc \
  --target-triple x86_64-unknown-linux-gnu --output ./program.o ./program.s
mkasm --assemble-object --assembler /path/to/target-as --assembler-kind gnu \
  --json ./program.s > program.object.json
```

Use exactly one of `--output FILE` and `--json`. LLVM is the default assembler
kind and requires `--target-triple`; GNU receives CPU/ABI switches through
`--assembler-args`, a JSON array of literal arguments. `--assembler-kind command`
supports vendor tools with explicit `{input}` and `{output}` placeholders.
Arguments are passed directly, without a shell. ELF results expose sections,
symbols and relocations structurally; other object formats retain their full
bytes. The selected toolchain supplies pseudo expansion, sections, literal
pools, ABI relocations and relaxation. Instruction assembly APIs continue to
operate on concrete instruction operands.

## Shared Go and generated Rust APIs

Go library callers use `pkg/codec.Catalog` and architecture-specific framing
wrappers for exact encoding, decoding, formatting, text assembly, operand
analysis, templates, edits and relocation. Named operand maps retain source
classes and semantic numeric values. The generated Rust surface below exposes
the corresponding operations without requiring a Go runtime. Shared Go library
APIs do not imply that every backend supports `--codegen go`; consult the
backend's generation options.

Fixed-field backends generate this common surface:

```rust
let (index, form) = catalog_entry("encoding-id").unwrap();
let values = representative(index).unwrap();
let mut buffer = [0u8; 256];
let length = encode_into(index, &values, &mut buffer).unwrap();
let decoded = decode(&buffer[..length]).unwrap();
assert_eq!(decoded.length, length);
let text = decoded.format(0x1000);
assert!(assemble_at(&text, 0x1000).unwrap().contains(&buffer[..length].to_vec()));
```

`ENCODINGS` contains stable IDs, syntax, operand bit placements, register and
enumeration names, feature predicates, flow metadata and constraints. Values
follow each form's operand order. Signed values, scaling and biases are part of
the public operand model, rather than values for callers to guess from text.
Generated source shares identical immutable operand, constraint and feature
lists across forms, keeping large union catalogs practical to compile while
preserving the ordered `ENCODINGS` slice and its public types. Forms marked
`assembly_only`, including raw SystemZ `.insn` directives, support exact encoding
and text assembly without requiring their arbitrary bytes to decode as a named
instruction.
Implicit operands default to zero when omitted from exact encoding calls.
`Lookup` tables map encoded indexes to their numeric meanings before scaling
and bias. PC-relative operands explicitly describe pre-alignment bias,
alignment, post-alignment bias, regional addressing and modular wrapping.
Tuple membership constraints list the exact admitted combinations of semantic
operand values. They apply to encoding, decoding, text assembly and templates;
the generated representative sampler selects values from the admitted domains.
Masked inequality constraints describe register-bank relationships, with optional
register-class gates, consecutive-register spans and same-register exceptions. `Optional` operands default
to zero when omitted but preserve nonzero ignored or container bits through
structured decode/encode; text omitting those bits normalizes them to zero.

`decode` uses generated bit-decision trees and fixed operand storage;
it does not allocate or parse formatted text. `encode_into` writes to
caller-owned storage after validating the operands. `encode` is an allocating
convenience. Text assembly indexes literal mnemonics, and `Template` compiles
open operand patterns for repeated matching and encoding.

For repeated fixed-field text work, reuse output storage and an assembler:

```rust
let mut text = String::with_capacity(128);
let mut assembler = Assembler::with_capacity(128);
for bytes in instruction_stream {
    let decoded = decode(bytes)?;
    text.clear();
    decoded.write_to(0x1000, &mut text)?;
    let length = assembler.assemble_into(&text, 0x1000, &mut buffer)?;
}
```

`write_to` appends to any `std::fmt::Write` and propagates writer errors. It
allocates no codec-owned storage, including for escaped literal braces.
`Assembler` reuses normalized input storage; calls allocate nothing once its
capacity covers the normalized input. Longer input grows that storage without
imposing a fixed text limit. `assemble_with_features_into` accepts the same
feature filter as `assemble_with_features`. Both methods select the first
shortest legal encoding, matching the first result of the allocating assembly
API, and leave the destination unchanged on syntax or buffer-size errors.
Large candidate sets use shared fingerprints of required literal text to reject
unrelated forms before parsing operands. Fingerprint collisions retain extra
candidates and cannot remove a legal match. Small candidate sets omit the table.
The reusable assembler visits candidates in stable length order and stops after
the first legal encoding in each mnemonic group. Dynamic mnemonics replace a
named match only with a shorter encoding, preserving catalog precedence on ties.
The allocating API retains its original all-alternative order. Candidate indices
use 32 bits; already sorted groups reuse their original lists.
Large candidate sets use a bounded stack cache to reuse admission results for
interned feature requirement lists. Each call starts a fresh cache, including
when the active profile changes, and hash collisions require a full slice
identity check. Small sets keep direct checks. Literal delimiters are scanned as
bytes, retaining nested-bracket handling and Unicode boundaries.
The framing wrappers expose this field-level facility as `WordAssembler` for
Hexagon, `FieldAssembler` for Xtensa, and `BodyAssembler` for Z80; packet,
FLIX-slot, and redundant-prefix handling use their existing framing APIs.
`assemble_at` still returns all distinct alternatives; it now normalizes input
once, matches precompiled byte programs, and uses fixed operand storage internally.
Match programs carry operand indices directly, avoiding placeholder parsing and
operand-name searches for each candidate. Operand numeric domains are computed
at generation time and interned, so descriptions and template hole queries do
not enumerate register sets or perform domain arithmetic. They replace the normalized pattern
strings without enlarging the syntax records.
Normalized operand names and aliases are interned in sorted tables at generation
time, so named-operand parsing uses binary search without temporary strings.
Canonical names retain precedence over aliases, including when normalization
makes two spellings identical. The original names remain available for display.
Adjacent operands narrow prefix ranges in these sorted tables instead of
scanning the complete name domain for every possible split; small ranges use
direct prefix comparisons. Numeric splits
stop at the lexical numeric prefix before checking overflow. Both searches
retain the original endpoint order and require no additional tables or storage.
Longer concrete assembly forms match syntax with a bounded stack of backtracking
frames, avoiding recursive closure calls and generic binding clones. Short forms
with at most two operands retain the smaller matcher when their byte program is
at most 32 bytes. The iterative frame capacity
is generated from the maximum placeholder count, including repeated operands.
Failed branches restore newly assigned values; repeated operands still require
equal values. Template parsing retains the generic binding matcher.

`Template::is_match` checks a compiled template without constructing captures.
`matches_into` writes borrowed capture names and values into a caller-owned
slice and returns the instruction length and capture count. It allocates
nothing and leaves that slice unchanged if its capacity is insufficient.
The owned `matches` API validates and collects captures in one traversal;
it does not route through the borrowed matcher and traverse the operands again.

The analysis and editing surface has the same capabilities as the Arm/x86
assembler APIs, expressed in each target's operand model:

```rust
let description = decoded.describe(0x1000);
for span in &description.operands {
    let printed_operand = &description.text[span.start..span.end];
    assert!(span.domain.contains(span.value));
    // span.class and span.kind retain the source operand classification.
    // span.position computes targets and inverse displacement values.
}
let template = Template::for_encoding(form.id, 0x1000).unwrap();
let holes = template.holes();
assert!(template.could_match(&buffer[..length]));
let mut moved = [0u8; 256];
// This exact form can fail if it cannot reach the original target from 0x1010.
let result = decoded.relocate_into(0x1000, 0x1010, &mut moved);
```

`Described` returns byte offsets into its own canonical text, semantic values,
source classes, domains and `Position` arithmetic. Domains include min/max/step;
`exact == false` means necessary bounds rather than a complete legality predicate.
Sparse lookup tables, dependent biases and relational operand constraints remain
conservative, and the actual encoder always checks the complete form.
`branch_target` reports statically encoded control-flow destinations, including
hardware-loop endpoints and opcode-defined constant targets. Target metadata
also applies architectural address masks, including classic MSP430 CALL's
destination alignment. PC-relative data references and indirect call or branch
slots expose their effective addresses through operand `Position` values;
they do not provide a statically known branch destination.
`set_operand` validates before committing an edit; `relocated` and
`relocate_into` preserve statically encoded targets and all other fields. They
retain the exact form, reject unrepresentable targets and leave source values
and output storage unchanged on failure. They do not expand branches or resolve
linker relocations.

`Template::parse_with_features` filters candidates in the selected CPU context.
`$name`, `${name}`, class restrictions such as `${name:register}`, repeated names
and `_` wildcards are supported. Capture names are case sensitive.
Native register spellings such as MIPS `$zero` remain literal operands; use
`${zero}` to capture an ambiguous name explicitly. `holes`,
`hole_position`, `encodings`, `byte_filters` and `could_match` expose compiled
template metadata. Byte filters are necessary opcode filters; a successful filter
does not bypass operand or relational checks. `for_encoding` opens one exact
source form, including optional ignored fields that canonical text can omit.

The Hexagon, Xtensa and Z80 APIs compose descriptions, holes, edits and relocation
over complete packets, bundles and prefix-framed instructions. Their operand
spans identify the instruction within the container. Hexagon updates explicit
extenders while retaining packet size and describes new-value registers using
the packet's actual producers; open template domains retain conservative source
producer bounds. Xtensa retains slot/format placement;
Z80 retains ignored prefixes and computes the PC from the complete stream.
Underlying field APIs remain explicitly named word/field/body APIs. Packet and
bundle `could_match` account for contextual framing; they do not promise the
same constant-time filter as one standalone fixed-field instruction.

With no feature filter the codec admits the union of its imported extensions.
Use `decode_with_features` and `assemble_with_features` to distinguish
conflicting instruction sets; `profile(name)` returns source-defined predicate
sets. For example, classic AVR and reduced-core Tiny encodings require different
profiles even when their byte patterns overlap. AMDGPU generations can also
assign different instruction lengths to the same byte prefix, so stream decoding
must select the actual processor profile. Generated corpus checks select a
declared profile supporting each form before checking its exact framing and text
round trip; catalogs without a matching declared profile retain union checks.

Go generator-side APIs use named `map[string]int64` operand values. A full-width
64-bit unsigned bit pattern is represented by its two's-complement `int64`
value. Generated Rust accepts `i128` values, including full unsigned 64-bit
inputs, and preserves their encoded bits.

Bytecode and module-oriented backends expose format-specific structured APIs.
They share the CLI `--json` / `--codegen rust` workflow while retaining their
own framing, context and validation requirements:

| Backend | Operand analysis and templates | Address behavior |
|---|---|---|
| CIL | Typed operand spans, named captures, token/float/switch kinds, hole metadata, atomic edits | Exact opcode relocation retains branch and switch targets relative to the instruction end |
| JVM | Named scalar spans, whole switch spans, wide operand domains, template holes and opcode filters | Relocation retains branch and switch targets and recomputes switch padding |
| DEX | Scalar/register-list/range/payload spans, source field metadata, template holes and opcode filters | Target fields use code units; payload entries retain referring-switch-relative semantics |
| M68k/ColdFire | Structured value spans, source operand classes, template holes and opcode filters | Relocation handles branches and enabled PC-relative effective addresses, including indexed forms |
| WebAssembly | Structured scalar/list/reference spans, source field kinds, atomic edits and template holes | Structured label and index values are independent of byte addresses |
| SPIR-V | Typed ID/enumerant/composite spans, public operand quantifiers and requirements, atomic edits and template holes | IDs and module context replace native PC-relative addressing |
| PTX | Existing source/operand spans and validated source edits, source class/format metadata, rendered-text template capture and fill | Textual symbols remain symbolic; primary-assembler validation establishes ISA legality |

These APIs validate instruction or grammar behavior. Moving a complete method or
module can also require updating its exception regions, references or container
metadata. See the package READMEs for those container contracts.

`scripts/validate-architectures.py` runs several real inputs through the built
CLI, checks their exported IR, generates standalone Rust libraries, and batches
their unit and integration tests. Pass `--spec TARGET=SOURCE` once per target
and an artifact output directory. It requires Python 3.11 or newer and uses the
normal managed `cargo` command. The optional `scripts/ghidra-codec-oracle.py`
accepts JSONL assembly/disassembly requests against an existing Ghidra
installation for targets without LLVM support.

Each shared-runtime crate tests every emitted form with three legal sample
selections, including nonzero and boundary-oriented candidates. The tests check
spans, domain containment, position inverses, source-exact and text templates,
captured re-encoding, filters and relocation. They run alongside the existing
complete byte/text corpus tests. The validator compares runtime-emitted case IDs
with the complete exported encoding-ID set and rejects missing, duplicate or
unknown IDs. This covers all emitted forms; it does not enumerate every possible
operand tuple. Format-specific suites cover their entire imported opcode or
grammar tables with their actual wide, switch, payload and context models.

IR export and validation stream one instruction record at a time, including
large GPU catalogs. When an equivalent generated crate has already been compiled
and tested in the current validation session, `--reuse-tested-crate TARGET=DIR`
checks every generated source/data file against that actual crate and records
the comparison separately from the newly run Cargo targets. A differing file
rejects reuse. If generation replaces the tested directory itself, the validator
hashes its files before generation and verifies the new output against those
earlier bytes. This avoids a duplicate build while keeping the real CLI output
bound to the tested implementation.

## Validation boundaries

Generated byte/text round trips establish consistency. Independent assembler,
disassembler or executable-consumer checks establish separate evidence about
the instruction specification. The architecture packages retain real upstream
corpora and test both kinds of behavior, including malformed inputs.

An instruction codec does not execute semantics or produce decompiled source.
Bytecode framing, stack-height verification and full type verification are
separate checks. CIL supplies stack-height verification and an explicit ILVerify
integration; those capabilities do not imply verification of every VM or
execution of managed code. Container, linker and loader boundaries are documented
separately for each format. Unsupported source records remain explicit rather
than acquiring fabricated encodings.

The generated M68k and ColdFire runtimes iterate borrowed operand descriptors.
Exact form IDs use a generated binary-search index when their normalized or
aliased spelling cannot also select a mnemonic. Ambiguous names retain the
original catalog-order search. Successful exact encoding avoids temporary name
and error strings.
Once decoding has a valid result, forms with an equal or lower fixed-bit score
are skipped; catalog order still breaks ties. Formatting borrows nested operand
values instead of cloning them into a temporary list.
