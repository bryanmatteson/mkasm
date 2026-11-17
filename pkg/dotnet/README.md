# Managed PE, CIL rewriting and ReadyToRun inspection

`dotnet.Open([]byte)` reads a PE32/PE32+ managed image, an ECMA-335 metadata
root, a Portable PDB, or a native composite ReadyToRun image. `dotnet.Parse(io.Reader)` is the reader equivalent.
No assembly is loaded and no managed or native code is executed.

```go
image, err := dotnet.Open(contents)
if err != nil { return err }
methods, err := image.Metadata.Methods()
if err != nil { return err }
for _, method := range methods {
    body, err := image.MethodBody(method.Token)
    if err != nil { return err }
    fmt.Println(method.Token, method.FullName,
        method.Signature.Format(image.Metadata), body.Kind)
    if body.Kind == "cil" {
        // body.IL is the exact instruction byte slice for the CIL codec.
        // body.Raw includes the tiny/fat header and exception sections.
    }
}
```

The package exposes:

* PE sections, checked RVA mapping, CLI directories, native entry point flags,
  recognition of the ReadyToRun `RTR\0` managed native header, and exported
  composite `RTR_HEADER` discovery.
* All 45 standard ECMA-335 table schemas (IDs 0–44), all 8 Portable PDB table
  schemas (48–55), every standard coded index, variable-width table and heap
  indices, unoptimized pointer tables, and lazy row access through `Metadata.Row`.
* UTF-8 strings, GUIDs, blobs, and UTF-16 user strings. `UserString` returns both
  a display string and exact UTF-16 code units, preserving unpaired surrogates.
* Assembly, type, field, property, event, and method enumeration; nested types,
  generic parameters/constraints, member references, method specifications,
  and generic substitutions through `Metadata.Member`.
* ECMA signatures including custom modifiers, function pointers, varargs,
  multidimensional array shapes with signed lower bounds, generic instances,
  pinned locals, and managed/unmanaged calling conventions. The structured
  representation retains calling convention bits and encoded token identities.
* Tiny/fat CIL method framing, stack/local signature metadata, exact method body
  bytes, and small/fat exception clauses including catch, filter, finally, and
  fault regions. `MethodBody` identifies abstract, P/Invoke, native, runtime,
  OPTIL, and absent bodies without inventing CIL.
* Embedded and external manifest resources, structured serialized attributes
  (including boxed values, arrays and enums), marshal descriptors and binary
  declarative security, with exact raw blobs and per-record decode diagnostics.
* Debug directories, Portable PDB document names and sequence
  points, external type-system row counts, and bounded embedded PDB inflation.
  Other PDB records remain available through the complete table and heap APIs.

Input bytes are borrowed; callers must keep them unchanged while using a reader.
The Go reader validates metadata stream/table boundaries, heap references, coded
index tags, token limits, required indices, list ordering/ownership, type graph
cycles, method framing, and exception region bounds. Signature and member APIs
validate the signatures they consume. Nesting is limited to 64 levels. `Parse`
reads its input completely; callers handling streams should apply their own file
size policy with an `io.LimitReader` or another bounded source.

## CIL verification and rewriting

`pkg/managed` composes the metadata reader with the CIL codec. `VerifyMethod`
checks control-flow joins, stack heights, call effects, arguments, locals,
exception-entry stacks and declared maxstack in the method's actual metadata
context. `RewriteVerifiedMethods` applies the same analysis before publishing
replacement tiny/fat CIL bodies. The CLI exposes these operations directly:

```sh
mkasm --arch cil --inspect --verify --json Example.dll
mkasm --arch cil --rewrite edits.json --output Changed.dll Example.dll
```

The edit manifest is a JSON object mapping explicit MethodDef token strings to
complete hex-encoded method bodies. Select the token from the image's method
list; the replacement must match that method's signature. Duplicate tokens,
including different numeric spellings of the same token, are errors. A failed
rewrite leaves an existing output file untouched.

`Image.RewriteMethods` is the lower-level framing writer. Bodies can grow beyond
the original allocation; metadata tokens and untouched bodies retain identity.
The writer adds an IL section or extends the final section without moving
existing RVAs. It clears stale debug-directory references. Native-code and
signature invalidation require explicit `RewriteOptions`: `DropNative`,
`StripStrongName`, and `StripAuthenticode`. CLI equivalents are `--drop-native`
and `--strip-signatures`. Dropping native code requires an ordinary ReadyToRun
image whose affected methods retain valid IL; composite native publications are
rewritten through their component IL images.

Stack-height analysis is distinct from CLR type verification. Use
`managed.VerifyTypesWith` with an explicitly selected Microsoft ILVerify
executable, a complete reference assembly set and the correct core library name:

```sh
mkasm --arch cil --inspect --verify --json \
  --type-verifier /path/to/ilverify \
  --references '/path/to/runtime/*.dll' \
  --system-module System.Private.CoreLib Example.dll
```

`--system-module mscorlib` supports the corresponding .NET Framework reference
set. Verification consumes exactly the input bytes inspected, including stdin
and URL inputs, and retains tool diagnostics. No dependencies are downloaded or
implicitly loaded by these APIs. Valid unsafe CIL may be unverifiable.

Serialized enums require their defining metadata. `NewReferenceSet(local,
references...)` resolves explicitly supplied assemblies, netmodules and type
forwarders. Assembly-qualified identities include version, culture and public
key token; missing, ambiguous and cyclic bindings are errors. Serialized
identifiers preserve escaped punctuation and distinguish a literal `+` from
nested-type separators. Closed enums nested inside generic declaring types
retain their constructor signature arguments and boxed assembly-qualified names.
The resolver checks generic arity and the supplied argument metadata.

Use `ReferenceSet.DecodeAttribute`, `SerializedAttributes` and `SecurityRecords`
with the originating metadata to preserve `ModuleRef` scope. Module identities
retain their names and MVIDs. Manifest `File` and `ExportedType` records identify
the defining netmodule, including nested exported types. `BindModule` explicitly
associates a manifest file token with supplied metadata when file and module
names differ or multiple modules share a name. This metadata-only API does not
verify manifest file hashes. It never loads files implicitly.

`EnumUnderlying` remains available as a callback for assembly-scoped values;
`EnumUnderlyingIn` accepts an explicit origin. `LocalEnumUnderlying` is useful
for self-contained local attributes. `--inspect --references` installs the
module-aware resolver without requiring a type-verification run. The CLI retains
explicit reference paths and binds a supplied module beside its manifest to that
manifest's `File` record. Assemblies with equally named netmodules keep their
separate MVIDs and definitions. No neighboring file is opened unless it was
explicitly supplied. Repeated identical metadata inputs share one identity.
The reader
constructs serialized values without instantiating attribute classes or
executing their constructors.

## Native ReadyToRun code and composite images

`ReadyToRunHeader` preserves every native section, including unrecognized section
types. `NativeFunctions` returns exact code ranges and unwind references for
x86-32, x86-64, Arm32, Arm64, LoongArch64 and RISC-V64, using each target's unwind
length representation. OS-specific machine identifiers are retained.

MethodDef entry-point arrays map native functions to local metadata tokens.
Generic instance hash tables retain owner types, generic type arguments,
constrained types, token/slot identity, module overrides, raw signatures, fixup
offsets and runtime-function indices. Foreign tokens keep their module context;
they are never silently resolved against the current assembly's metadata.

`Image.Composite` identifies native multi-assembly publications. Such images
can have manifest metadata or no global metadata at all; check `HasMetadata`
before treating `Metadata` as a parsed root. The empty global view has zero
rows. `ReadyToRunComponents` returns each component's CLI/core header, native
sections and embedded metadata where present. `NativeFunction.ComponentMethods`
pairs tokens with component indices, preserving identity across assemblies.
External component metadata still requires the corresponding assembly inputs.

The returned native bytes can be passed to the matching CPU codec. This package
does not execute CLR code or decompile methods, reconstruct metadata stripped
by NativeAOT, apply Edit-and-Continue deltas, or parse legacy Windows PDBs.
Unknown metadata table IDs and unsupported method data sections produce explicit
errors. Legacy XML security declarations and native sections without structured
decoders remain available as exact bytes.

## Standalone Rust

`dotnet.GenerateRust(output)` writes a dependency-free MIT-licensed Rust crate,
notices, pinned fixtures, and executable consumer tests. The generated reader
borrows PE/metadata/method bytes, using owned buffers only for structured results
and bounded embedded PDB decompression.

```rust
let image = mkasm_dotnet::Image::open(&bytes)?;
for method in image.metadata.methods()? {
    let body = image.method_body(method.token)?;
    println!("{} {} {}", method.token, method.full_name, body.kind);
    if body.kind == "cil" {
        // Hand body.il to the generated CIL decoder.
    }
}
if let Some(bytes) = image.embedded_pdb_bytes(16 * 1024 * 1024)? {
    let pdb = mkasm_dotnet::Metadata::parse(&bytes)?;
    assert!(pdb.pdb.is_some());
}
```

`WriteRustModule(path)` writes the same self-contained module for integration as
`pub mod dotnet;` in a generated CIL crate. `WriteRustTests(output, modulePath)`
installs its consumer tests using a Rust import path such as
`mkasm_cil::dotnet`. `Image.GenerateRust` and `Image.WriteJSON` also satisfy the
shared backend contract.

## Validation and fixtures

Run `go test ./pkg/dotnet`. This includes real generated Rust consumer tests by
default and requires the normal `cargo` command. The generated crate runs its
pinned consumer tests with `cargo test --lib --tests`. The CLI-generated CIL
crate additionally tests combined inspection, verification and verified rewriting.

The fixtures are original C# code built with pinned .NET SDK 10.0.401, targeting
AnyCPU PE32 DLL, x86 PE32 managed EXE, and x64 PE32+ DLL, with portable and embedded
PDB variants. They include generics, nested types, interface implementations,
async/iterator state machines, function pointers, array/pointer types, layout and
marshal metadata, attributes, constants, resources, P/Invoke, and exception
filters/catches/finally. Independent JSON expectations come from Microsoft's
System.Reflection.Metadata/PEReader and its signature decoder. Go and Rust
compare table counts, type/member tokens, signature bytes and formatted types,
exact CIL/header/exception bytes, sequence points, resources, and non-CIL kinds.
Malformed/truncated inputs, hostile sizes, signed compressed values, index-width
boundaries, cyclic nested types, reserved coded tags, and large trailing image
data are exercised.

To rebuild fixtures without writing build products into the source directory:

```sh
cd pkg/dotnet/testdata/source
python3 regenerate.py \
  ~/Documents/Developer/go-mkasm/architecture-expansion/dotnet \
  /usr/local/share/dotnet/dotnet
```

Additional local validation used .NET 10.0.12's actual ReadyToRun
`System.Private.CoreLib.dll`: all 41,420 method records, 39,317 CIL bodies, 2,103
other method kinds, 45 table counts, signatures, full method bytes and exception
clauses matched PEReader in Go. The standalone Rust consumer matched the same
independent complete corpus. Framework binaries are not copied into this package;
its reproducible default tests use only the original pinned fixtures.

ReadyToRun runtime and composite checks are enabled with
`MKASM_DOTNET_CORPUS` and `MKASM_DOTNET_COMPOSITE`. They enumerate every native
runtime function and method entry, check all code extents, and validate
component/token ownership. A real self-contained composite publication was
executed and inspected through Go, the CLI and generated Rust: 174 components,
213,260 native functions, 79,303 component method mappings and 119,490 generic
instances. The CLI-generated CIL consumer also verifies and byte-round-trips all
39,317 CoreLib CIL bodies. `MKASM_DOTNET_REFERENCE_ARTIFACTS` enables the compiled
reference, forwarder, escaped-name, closed generic enum and multi-module cases;
the manifest and both compiled netmodules are compared with PEReader and
inspected through the CLI. `MKASM_ILVERIFY`,
`MKASM_DOTNET_REFERENCES` and `MKASM_DOTNET_TYPE_IMAGE` enable real external type
verification, including rejection of a height-correct invalid return type.
Retained independent PE-layout fixtures also exercise
export ordinals, component headers, generic signatures, malformed hash tables
and LoongArch64/RISC-V unwind extents. `testdata/source/composite-fixture.py`
rebuilds the small composite layout fixture; it is separate from real crossgen2
publication validation. When `dotnet` is available, the rewrite test builds and
executes an independent CLR consumer against the changed assembly.

Specification sources and their notices are retained in
[UPSTREAM-NOTICE.md](UPSTREAM-NOTICE.md).
