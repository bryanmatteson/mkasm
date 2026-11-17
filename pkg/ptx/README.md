# NVIDIA PTX textual virtual ISA

PTX is a textual virtual instruction set. This package reads and writes PTX
modules as text, preserves every byte of the source, and exposes tokens,
instructions, operands, predicates, modifiers, directives, functions, scopes,
declarations, labels, and control-flow references. It does not turn PTX into
invented GPU machine-code encodings.

```go
catalog := ptx.Default()
module, err := ptx.Decode(source)
if err != nil { return err }
for _, instruction := range module.Instructions {
    fmt.Println(instruction.Opcode, instruction.Predicate, instruction.Operands)
}
changed, err := module.ReplaceOperand(0, 1, "%new_register")
if err != nil { return err }
fmt.Print(changed.Encode())
```

`Decode` and `ParseModule(io.Reader)` parse source. `Module.Encode`/`Write`
preserve its exact spelling, comments, whitespace, strings, constants and line
endings. Source byte spans support explicit `Replace` and `ReplaceOperand`
edits followed by a complete reparse. `Functions`, `Declarations`, and
`ControlFlow` provide views over the syntax tree. Function headers retain
parameter and return declarations, linkage attributes and execution directives
as structured tokens. Operand kinds distinguish addresses, vectors, tuples,
registers, literals and general expressions; their token lists preserve nested
operand syntax, predicate pairs, offsets, dimensions, and qualifier expressions.
`Module.WriteJSON` exports this structure.

The source text is authoritative. Mutating a returned view does not silently
rewrite the source. Scoped and operand delimiter nesting is limited to 256.
The codec accepts UTF-8 comments/strings and rejects unquoted non-ASCII tokens,
unclosed comments/strings, malformed delimiter nesting, missing instruction
terminators, and malformed predicates/operand separators.

## Complete imported source registry

`Default()` loads the pinned factual registry in `testdata/registry.json`.
`Parse(reader, "ptx")` imports the same JSON format; `WriteJSON` exports it.
The `nvptx`, `nvptx32`, and `nvptx64` source-registry aliases use canonical PTX.
Module address size is a module/profile property, not a machine-code width.

The registry contains the complete source import rather than a selected group
of example instructions:

* NVIDIA **PTX ISA 9.5**, documentation updated **November 2, 2026**: every
  syntax-bearing reference section, comprising **223 instruction sections**,
  **37 special-register sections**, and **35 directive sections**. Syntax
  blocks, modifier alternatives, examples, PTX/target requirements, section IDs,
  and names are retained. All **286 reference example blocks** are retained.
* Lexical/declaration/operand/ABI grammar code blocks from their complete parent
  specification sections, and target introduction versions from the primary
  `.target` reference.
* LLVM **llvmorg-22.1.8** NVPTX TableGen: **6,629 instruction records**, including
  pseudo records and **308 empty-syntax records**. All **6,321 nonempty syntax
  records** have printable templates. Operand classes, predicate references,
  constraints, namespaces and source locations are retained.
* All **157 LLVM predicate/subtarget-feature definitions**, including their
  original condition expressions, feature values and implications. Compiler
  policy predicates are retained as source data rather than treated as GPU
  feature flags.

The NVIDIA HTML SHA-256 is
`3a4fe2a0dff0320a46e140b52d913839c8cd3dc0227b9809a46e116ab5b0a0a3`.
The LLVM resolved dump SHA-256 is
`ecb3467b6b196856d382a29a75e49b10a1b1181f3cc47abf2692583cf0a11758`.
Source URLs and hashes are embedded in JSON. `import_registry.py` checks both
pinned hashes before import. To reproduce using retained primary sources:

```sh
python3 pkg/ptx/import_registry.py \
  ~/Documents/Developer/go-mkasm/architecture-expansion/ptx/ptx-isa-9.5.html \
  ~/Documents/Developer/go-mkasm/architecture-expansion/nvptx.json \
  /tmp/ptx-registry.json
cmp pkg/ptx/testdata/registry.json /tmp/ptx-registry.json
```

`Lookup(opcode)` returns the matching primary instruction-family references.
`Template(llvmID)` and `CompileTemplate` support LLVM `$name`/`${name:format}`
notation. Caller values are rendered PTX fragments; target-specific LLVM operand
printer formats are exposed and are not guessed. `CompileModuleTemplate` uses
`{{name}}` holes while preserving literal dollar signs in PTX symbol names.
Templates reject missing and unused values.

## Profile and primary semantic validation

`Check(module, Profile{MaxVersion, Target, AddressSize})` checks module headers,
known targets/options, target introduction versions, address-size consistency,
architecture/family-specific compatibility, instruction-family availability,
and the baseline PTX/target requirements exposed by source sections. Omitted
`.address_size` correctly defaults to 32. `Assemble(source, profile)` combines
structural parsing with these checks and returns a textual module.

A local report has `SemanticComplete == false`. The primary specification has
modifier-dependent constraints in prose and tables. The package retains their
source notes, but does not claim to reproduce NVIDIA's register type checker,
all modifier combinations, ABI/linkage checks, resource limits, or target policy
in a second semantic compiler. In particular, local family checks alone do not
prove that an arbitrary modifier/type combination is legal.

`ValidateWith(ctx, module, profile, command, args...)` sends the source on stdin
to an explicitly selected primary validator. It reports semantic completion
only after that command succeeds. For native NVIDIA tooling, arrange stdin and
output arguments, for example `ptxas -arch=sm_80 - -o /dev/null`. A CUDA driver or
GPU is not required for `ptxas` validation. Validation applies to the selected
tool's supported PTX/target scope; it does not execute kernels.

## Standalone Rust

`catalog.GenerateRust(output)` writes an MIT-licensed, dependency-free Rust crate
with the complete static registry and its JSON source, the lossless module codec,
profiles, templates, JSON structure output and public consumer tests.

```rust
let module = mkasm_ptx::decode(&source)?;
let report = mkasm_ptx::check(&module, &mkasm_ptx::Profile::default());
report.result()?;
assert!(!report.semantic_complete);
assert_eq!(module.encode(), source);
for function in module.functions() {
    println!("{} entry={}", function.name, function.entry);
}
```

Rust mirrors the Go APIs as `decode`, `assemble`, `lex`, `lookup`, `template`,
`compile_module_template`, `check`, `validate_with`, module views, explicit source
edits and `to_json`. `REGISTRY_JSON`, `DOCUMENTS`, `LLVM`, `FEATURES`, and
`TARGET_VERSIONS` expose the generated source registry. The Rust reader borrows
text slices and retains source offsets; explicit edits return newly owned text.

## Validation

`go test ./pkg/ptx` runs generated Rust public consumers by default using normal
`cargo test --test public`. It also verifies full registry counts, every LLVM
printed template, and byte-preserving tokenization of every NVIDIA syntax and
example block. Documentation examples include incomplete fragments, ellipses,
multiple alternative module headers, and one missing semicolon; they are tested
as source fragments, not misrepresented as complete assemblable kernels.

Real Clang/LLVM 22.1.8 outputs are pinned for an optimized SM80 module and an SM90
debug module, covering functions, entries, parameter lists, registers, labels,
branches, calls, floating-point/integer operations, and debug sections. Both
round-trip through Go and Rust; their rebuilt text assembles with NVIDIA ptxas.
The original CUDA source is `testdata/kernels.cu`; rebuild with:

```sh
clang++ -x cuda --cuda-device-only -nocudainc -nocudalib \
  --cuda-gpu-arch=sm_80 -Xclang -target-feature -Xclang +ptx88 \
  -S -O2 pkg/ptx/testdata/kernels.cu -o /tmp/clang-sm80.ptx
```

The PTX 9.5 fixture additionally exercises `.metadata_section`, family-specific
SM107 targeting, `.2pi` sine, and conditional/payload `trace.mark`. It is accepted
by NVIDIA **ptxas 13.5.37**, downloaded from NVIDIA's CUDA 13.5 redistributable
manifest and run in an ARM64 Linux container. A generated Rust consumer invokes
the real assembler, accepts the valid module, and rejects the invalid `.2pi`
variant missing `.ftz`. The optimized/debug compiler modules were independently
assembled as well. These tool-based checks and generated crates are retained
under `~/Documents/Developer/go-mkasm/architecture-expansion/ptx`.

`TestIndependentUpstreamNVIDIARuns` additionally runs all **594 native NVIDIA
RUN configurations** in LLVM22's NVPTX corpus: 575 static-IR configurations and
19 primary Python-generated matrix, texture and address-space configurations,
covering 300,833 instructions.
It compiles the original/generated IR with each RUN's actual LLVM options,
round-trips the live PTX through Go and fresh CLI-generated Rust, and invokes
the corresponding NVIDIA assembler from both consumers. CUDA8, 11.8, 12.9 and
the current native assembler retain old targets and 32-bit PTX without changing
the programs. The upstream SM90/32-bit ABI combination must reproduce NVIDIA's
explicit rejection; it is retained as a negative case rather than skipped.
This cohort exercises scoped `tcgen05` family names, multiline semicolon-ended
directives and indexed branch-table references. The original 37-program cohort,
PTX9.5 and negative modules remain in the strict job. See
[reference testing](../../docs/reference-testing.md) for tool and artifact paths.

Source notices are in [UPSTREAM-NOTICE.md](UPSTREAM-NOTICE.md).
