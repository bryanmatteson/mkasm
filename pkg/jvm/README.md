# JVM bytecode backend

`Parse(reader, "jvm")` reads OpenJDK's actual
`src/hotspot/share/interpreter/bytecodes.cpp` definitions. It imports the complete
ordered Java bytecode corpus and checks its regular and wide framing against the
source metadata. HotSpot's VM-private rewritten instructions are excluded from
class files. The retained OpenJDK 21 corpus provides 202 standard opcodes,
including the `wide` modifier, plus three explicitly reserved opcode definitions:
`breakpoint`, `impdep1`, and `impdep2`.

The custom catalog implements `codec.Backend` (`WriteJSON` and `GenerateRust`).
Bytecode framing is independent of the fixed-mask architecture model because JVM
switch padding depends on the instruction's offset within the method.

Go API:

```go
catalog, err := jvm.Parse(openJDKSource, "jvm")
instruction, err := catalog.Decode(code[methodOffset:], methodOffset)
bytes, err := catalog.Encode(instruction, methodOffset)
text := instruction.Format()
bytes, err = catalog.Assemble(text, methodOffset)
method, err := catalog.DecodeMethod(code)
bytes, err = catalog.EncodeMethod(method)
```

`Instruction` exposes its opcode, mnemonic, byte offset, encoded length, `Wide`
flag, typed operands, and optional structured switch. Branch operands and switch
targets hold signed byte displacements from the opcode. Format and text assembly
use absolute method byte offsets. Constant-pool references use `#index`;
primitive array types use their names. Examples:

```text
wide iinc 300 -300
ldc_w #4660
invokeinterface #12 2
newarray int
goto 24
tableswitch {"default":40,"low":-1,"targets":[20,24,28]}
lookupswitch {"default":40,"pairs":[{"match":-100,"target":20},{"match":1000,"target":28}]}
```

`Decode` and `Encode` operate on one instruction at the given method offset.
`DecodeMethod` and `EncodeMethod` additionally enforce the JVM method size limit
and ensure every branch/switch target points to an instruction opcode. They
reject reserved opcodes, invalid wide modifications, malformed switch bounds or
key ordering, truncated data, nonzero reserved bytes/padding, invalid primitive
array tags, zero constant-pool indices, and zero counts/dimensions.

`GenerateRust` emits a standalone dependency-free `mkasm_jvm` crate. Its public
`Instruction`, `Operand`, `Switch`, and `LookupPair` structures carry the same
encoding values. The crate exports `decode`, `encode`, `assemble`,
`decode_method`, `encode_method`, and `Instruction::format`.

Named operand templates support matching and encoding in both languages. For
example, `catalog.Template("iinc", true)` in Go or
`InstructionTemplate::new("iinc", true)` in Rust selects the wide form. `Set` /
`set` fixes a named operand; `Match` / `match_instruction` returns the structured
instruction with any unfixed operands captured. Encoding requires all scalar
operands and, for a switch, a supplied structured payload. Branch values remain
displacements. Generated projects include their complete opcode and alignment
tests and run them with `cargo test --lib --tests`.

This backend accepts Code-attribute instruction bytes, rather than parsing an
entire class file. Constant-pool resolution, exception tables, stack maps, local
variable bounds, stack/type verification, and class-version restrictions require
class-file context. Numeric references are preserved without claiming those
context-dependent checks.

`go test ./pkg/jvm` checks the complete retained corpus, all twelve wide
modifications, all switch alignments, independent JVMS byte vectors, invalid
framing and branches, generated Rust conformance, and actual javac/javap/JVM
consumption when those tools are installed. Set `MKASM_JVM_ARTIFACT_DIR` to retain
the generated crate, compiled Java class, method bytecode files, and javap
listing. The Rust conformance test also consumes those retained javac methods.

`TestIndependentASMAllOpcodes` executes OpenJDK's ASM emitter live: all 201 legal
standalone opcodes and twelve wide forms, at all four switch alignments and two
operand cases (1,704 independent byte comparisons). Set
`MKASM_JVM_REFERENCE_RUST` to export the live vectors and a fresh Rust integration
test. The [reference runner](../../docs/reference-testing.md) requires every
selected external test to execute; an unavailable reference is a failed run.
