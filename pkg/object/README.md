# Complete-program assembly and object inspection

`object.Assemble` runs an explicitly selected assembler on a complete source
program and retains the resulting object bytes. The external assembler handles
sections, symbols, ABI relocation expressions, pseudo instructions, literal
pools, instruction packets and relaxation. This API complements the instruction
catalogs when a source program needs those facilities.

```go
result, err := object.Assemble(ctx, ".text\ncall external\n", object.Options{
    Executable: "/opt/homebrew/opt/llvm/bin/llvm-mc",
    Kind:       "llvm",
    Triple:     "x86_64-unknown-linux-gnu",
})
```

LLVM mode requires a target triple and accepts an optional CPU, feature list and
additional arguments. GNU mode uses the selected assembler's own target options
in `Arguments`. Command mode supports vendor tools with explicit `{input}` and
`{output}` argument placeholders. Arguments go directly to the process without a
shell. The Go call supports cancellation through its context; temporary assembly
files are removed after the process completes. Successful tool diagnostics remain
in the result, and failed assembler invocations return their diagnostics.

`Parse` preserves the complete input in `Object.Data`. ELF inputs additionally
expose their machine, class (`1` for ELF32, `2` for ELF64), byte order (`little` or
`big`), ELF file type and processor-specific `e_flags`, sections, symbols and
relocations. Non-ELF vendor output retains its exact bytes with format `vendor`.

The section and relocation model follows the stored ELF representation:

- `Sections` retains ELF section order, including the null section. A relocation's
  `SectionIndex` identifies its target; `Section` is the display name. Section
  names may repeat, so the numeric index determines identity.
- Section `Data` contains the exact stored payload. Compressed sections retain
  their compression header and compressed bytes, with `Size` equal to the stored
  size and compression flags preserved. `SHT_NOBITS` sections have empty data and
  retain their logical extent in `Size` without allocating that extent.
- `Symbols` includes each symbol table's null entry. `Table` and `Index` preserve
  the original symbol-table section and entry indices. `Other` retains the full
  `st_other` byte, including visibility and target-specific flags. Extended ELF
  symbol-section indices are resolved.
- A relocation's `Symbol` indexes the flattened `Symbols` list. `SymbolTable` and
  `OriginalSymbol` also retain its original table reference. RELA addends are
  signed; REL records set `HasAddend` to false and retain their implicit addends
  in section bytes. MIPS64 little-endian compound relocation records retain their
  special `r_info` layout.

The API preserves unresolved relocations for the target linker. It does not link
objects, apply relocations, interpret BTF type graphs, or extract a universally
usable flat binary. BPF `.BTF` and `.BTF.ext` sections and their relocations remain
available as exact object data. ELF byte order is explicit for consumers that
interpret these metadata payloads.

`InstallRust` installs the equivalent standard-library-only `object` module in a
generated Rust crate. Its `Options`, `assemble` and `parse` APIs expose the same
object information; the native assembler remains an explicit external tool.
Generated tests include the original multi-symbol-table identity fixture and
native LLVM programs. `object-fixture.elf`, `object-bpf.s` and `object-hexagon.s`
are installed alongside the module for these tests.

Run the native Go checks with:

```sh
MKASM_LLVM_MC=/opt/homebrew/opt/llvm/bin/llvm-mc go test ./pkg/object -count=1
```

The generated Rust object's tests use the same `MKASM_LLVM_MC` environment
variable. Native cases cover AArch64, x86-64, PowerPC64, SPARC, RISC-V, BPF in both
byte orders, and Hexagon. Hexagon checks repeated `CONST32` pool deduplication,
`CONST64`, and a packet relaxed into two call extenders with seven ABI
relocations. BPF checks a real LLVM-generated program's external call, hidden
function symbol, BTF types, function/line information and instruction-offset
relocations. Compressed debug sections and duplicate section names have separate
regressions.

`testdata/bpf-program.s` was generated from the adjacent maintained LLVM IR with
LLVM 22.1.8:

```sh
llc -mtriple=bpfel -filetype=asm pkg/object/testdata/bpf-program.ll \
    -o pkg/object/testdata/bpf-program.s
```

The assembly is valid for both BPF byte orders; `llvm-mc` emits the corresponding
ELF and metadata encoding. The checked-in source keeps native integration tests
independent of an installed `llc`.
