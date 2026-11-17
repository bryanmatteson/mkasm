# .NET CIL

`Parse(io.Reader, "cil")` imports the actual `OPDEF` and `OPALIAS` records in
.NET's `src/coreclr/inc/opcode.def`. `Default()` loads the included complete
source. The pinned source is dotnet/runtime **v10.0.0**, commit
`60629d14374c56f1cb51819049ad1fa529307f8d`; its MIT license is included.

The catalog contains **218 public real opcodes**, including all five public
prefix instructions, and the source's assembly aliases. Reserved/unused rows,
internal reference/prefix markers and non-bytecode implementation macros are
excluded. `FE 19` (`no.` in older descriptions) is reserved in this source;
it is rejected rather than invented as a public opcode.

Definitions retain the source ID, operand class, instruction kind, stack pop/push
categories and counts, flow category, and prefix flag. A stack count of `-1`
means a signature-dependent effect; resolving the call signature belongs to a
metadata consumer.

## APIs and representation

* `Decode` / `Encode`: one instruction with an explicit stream offset.
* `Format` / `Assemble`: canonical text, aliases and typed numeric operands.
* `DecodeMethod` / `EncodeMethod`: complete instruction streams, branch and
  switch boundaries, and prefix group checks.
* `FormatMethod` / `AssembleMethod`: labeled streams; switch targets and branches
  resolve labels in two passes. Opcode widths remain explicit (`br` / `br.s`).
* `Template`, `ParseTemplate`, `Bind`, `Encode`, `Match`: reusable typed operand
  capture or fixed binding. `_` / `$name` capture the whole operand, including a
  complete switch list. Binding copies the operand and switch entries.
* `DecodeMethodBody` / `EncodeMethodBody`: tiny/fat headers and chained small/fat
  exception tables (catch, filter, finally, fault), preserving header form,
  section form and alignment padding. `Length` reports bytes consumed so a PE
  reader can pass a containing section. `Instructions` is authoritative when
  non-nil during Go body encoding; otherwise `Code` is used.
* `WriteJSON` and `GenerateRust` satisfy the shared backend interface. Rust output
  is a complete dependency-free library with default corpus tests, a separate
  public API consumer test, licenses and notices. Rust bodies carry `code`; use
  `decode_method` / `encode_method` to edit structured instructions.

Float operands carry IEEE **bits**, preserving NaN payloads, infinities and
negative zero. Text uses `bits(0x...)`. Tokens preserve all 32 bits and validate
allowed token categories and nonzero row/heap indices. Symbol names and token
resolution require the surrounding module metadata.

Branch operands are signed byte displacements from the end of the instruction;
switch entries are signed displacements from the end of the **entire table**.
Text uses absolute `IL_` targets. Editing a typed instruction stream preserves
these displacements; use labels when changing instruction layout.

Malformed/truncated operands, reserved opcodes, invalid token categories,
misaligned branch destinations, duplicate/dangling/misapplied prefixes and
invalid method/EH structure return errors. EH validation includes region bounds,
instruction-group boundaries, disjointness/nesting/mutual protection, table
ordering and terminating `endfilter`. Modern .NET constrained prefixes may
modify `call`, `callvirt` or `ldftn`, matching the pinned JIT importer.

This is a binary/text codec with structural checks. It does not execute CIL,
resolve metadata, compute maxstack, verify stack/type safety, enforce all
protected-region control flow rules, rewrite signatures, or read a containing
PE image. Unknown method section kinds and future extended fat headers are
rejected explicitly. PE/CLI metadata is handled by the surrounding module
backend.

## Independent validation

`testdata/oracle/Program.cs` builds and executes real C# methods using SDK
**10.0.401**, runtime **10.0.12**. It independently enumerates
`System.Reflection.Emit.OpCodes`, uses `ILGenerator` to emit all 218 public
opcodes, and uses `System.Reflection.Metadata.PEReader.GetMethodBody` to extract
compiled method bodies and EH metadata. The retained `oracle.json` records those
results. Per-opcode methods exercise encoding, not the executability of isolated
instructions; separate valid methods execute branches, switch, generics,
volatile/unaligned/readonly/tail prefixes, catch, filter and finally behavior.

The fixtures include eight compiled methods (tiny/fat headers, small/fat EH) and
three executed dynamic prefix methods. Go and generated Rust compare exact bytes,
text assembly, templates and complete bodies, including truncation at every byte
of each reference encoding/body. Additional tests exercise scalar boundaries,
malformed inputs, chained EH sections, fault flags, labels and lossless decoding.

Regenerate the oracle in an artifact directory rather than creating build files
inside this source tree:

```sh
cp -R pkg/cil/testdata/oracle "$ARTIFACTS/oracle"
cd "$ARTIFACTS/oracle"
/usr/local/share/dotnet/dotnet build -c Release -o out
/usr/local/share/dotnet/dotnet out/Oracle.dll > ../oracle.json
```

Primary sources:

* [Pinned opcode table](https://github.com/dotnet/runtime/blob/60629d14374c56f1cb51819049ad1fa529307f8d/src/coreclr/inc/opcode.def)
* [Pinned JIT prefix rules](https://github.com/dotnet/runtime/blob/60629d14374c56f1cb51819049ad1fa529307f8d/src/coreclr/jit/importer.cpp)
* [ECMA-335, sixth edition](https://ecma-international.org/publications-and-standards/standards/ecma-335/), I.12.4.2.7, II.25.4, Partition III
* [Runtime method-body parser](https://github.com/dotnet/runtime/blob/60629d14374c56f1cb51819049ad1fa529307f8d/src/libraries/System.Reflection.Metadata/src/System/Reflection/Metadata/IL/MethodBodyBlock.cs)
