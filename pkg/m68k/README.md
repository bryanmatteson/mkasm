# Motorola 68000 and ColdFire instruction codec

`Parse(reader, "m68k")` and `Parse(reader, "coldfire")` import the complete,
pristine GNU binutils 2.44 `opcodes/m68k-opc.c` source. The source fixture is
included with its original notice and `testdata/COPYING-binutils`. Its SHA-256
is `d9861be507da2ac77b28207227e0c444bdfe660378d54db1491dbc160f760e0d`.
An unrecognized C revision is rejected explicitly. Resolved `mkasm.m68k.v1`
JSON is also accepted. No C compiler or target toolchain is needed at runtime.

All **1,887** upstream templates are retained, including the 24 CPU32 forms
expanded from the source's `TBL` macros and all 237 upstream mnemonic aliases.
The classic profiles select 1,489 forms collectively; ColdFire selects 641.
These sets overlap. LLVM 22.1.8 has only 978 concrete M68k records and no
ColdFire corpus, so its TableGen dump is not the source for this backend.

## CPU profiles and APIs

The default is `68000` for `m68k`, and `isa-a` for `coldfire`.
`catalog.WithCPU(name)` selects another profile without copying the table.
Classic profiles include `68010`, `68020`, `68030`, `68040`, `68060`,
`68020+68881`, `68020+68851`, `68020+68851+68881`, `68030+68881`,
`68881`, `68851`, `cpu32`, and `fido`. ColdFire profiles include `isa-a-nodiv`,
`isa-a`, `isa-a+`, `isa-b`, `isa-c`, `isa-a+mac`, `isa-a+emac`, `cfv4`, and
`cfv4e`. ColdFire ISA B and C do not implicitly enable ISA A+ instructions.
`m68k-all` and `coldfire-all` are analysis/testing unions rather than concrete
processors. Instruction availability uses the upstream architecture flags;
address extensions are checked against the selected processor family.

The Go API provides `Encode(idOrMnemonic, []Value)`, `Decode(bytes)`,
`Assemble(text)`, `Disassemble(bytes)`, `Template(id)`, `WriteJSON`, and
`GenerateRust`. `U`, `S`, `T`, and `L` construct unsigned/signed integers,
register strings, and structured lists. Templates expose stable names
`op0`, `op1`, etc.; `Set(name, value)` validates the operand and `Encode()`
checks the complete instruction, including interactions between operands.
`Match(bytes)` captures unbound operands and compares bound operands by their
encoded meaning, including structured effective addresses. Binding copies nested
values, so later changes to the caller's lists do not modify the template.

`GenerateRust(directory)` writes a standalone, dependency-free Cargo crate.
Its default `encode`, `decode`, `assemble`, and `disassemble` functions use
the generated profile. `Catalog::new(cpu)` selects a runtime profile and
exposes those same methods plus `template(id)`. Rust values are
`Value::{U,I,Text,List}`. `InstructionTemplate::new(id)` constructs a template
for the generated default profile; `set`, `encode`, and `match_instruction` match
the Go API.
The generated interpreter has the project's MIT license; the separate
`UPSTREAM-LICENSE` retains the opcode metadata's GPL-3.0-or-later notice.

## Lossless text and operands

The canonical text format is `instruction_id [JSON operands]`. An exact
source-template ID preserves the size and encoding when multiple source
forms share a mnemonic. Mnemonics and upstream aliases are accepted for
input, including names such as `move.l` and `moveq`. This is an instruction
codec's structured assembly syntax, not a parser for GNU source files,
labels, directives, expressions, or linker relaxation.

Examples:

```text
moveq [-7,"d3"]
movel [[26],[35]]
movew [[60,4660],[41,6]]
movel [[50,3,0,1,0,127],[0]]
movel [[50,3,1,2,1,20,16,0,0,2,40],[1]]
```

Register operands accept encoded numbers or class-appropriate spellings:
`d0`–`d7`, `a0`–`a7`/`sp`, `fp0`–`fp7`, control registers such as `vbr`,
cache selectors, accumulator registers/halves, and MMU registers. `%` prefixes
are accepted. Decoding emits numeric fields and the fixed register names.
A PMMU BAD/BAC register is `[selector, bank]`, where selector 28 means BAD,
29 means BAC, and bank is 0–7; spellings such as `bad3` are accepted for input.

Effective addresses are arrays whose first item is the six-bit EA code:

| Code | Meaning | Remaining items |
|---|---|---|
| 0–7 | Dn | none |
| 8–15 | An | none |
| 16–23 | (An) | none |
| 24–31 | (An)+ | none |
| 32–39 | -(An) | none |
| 40–47 | d16(An) | signed displacement |
| 48–55 | indexed An | indexed fields below |
| 56 | absolute word | word address/bit pattern |
| 57 | absolute long | 32-bit address |
| 58 | d16(PC) | signed displacement |
| 59 | indexed PC | indexed fields below |
| 60 | immediate | integer or exact floating bytes |

Brief indexed addresses are
`[code,index_register,index_is_long,scale,0,signed_disp8]`.
The index register is 0–7 for Dn and 8–15 for An, `index_is_long` is 0 or 1,
and scale is 1, 2, 4, or 8. Baseline 68000/68010 permit scale 1; ColdFire
requires a long index. Full 68020 extensions are
`[code,index_register,index_is_long,scale,1,base_disp,base_disp_bits,base_suppressed,index_suppressed,indirect_bits,outer_disp]`.
Base displacement size is 0, 16, or 32. Indirect bits are the actual 3-bit
I/IS field (0, 1, 2, 3, 5, 6, 7); they select pre/post indexing and the outer
displacement size. Reserved formats, invalid EA classes, and out-of-range
signed displacements are rejected. ColdFire does not accept full extensions.
MAC/EMAC masked addresses use `[effective_address, mask_bit]`.

Integer byte immediates occupy a word. Negative scalars sign-extend, matching
GNU as; nonnegative scalars zero-extend. Both valid padding conventions are
retained when decoding. `[upper_byte, lower_byte]` preserves any other unused
upper-byte value. IEEE single/double, extended 96-bit, and packed decimal
immediates use exact big-endian byte arrays, preserving all payload bits.

Branches use signed displacements relative to the architecture's PC base.
`BranchTarget(pc)`/`branch_target(pc)` returns a wrapping 32-bit target.
`PCRelativeTarget(operand, pc)`/`pc_relative_target(operand, pc)` resolves a
`d16(PC)` operand using that operand's actual extension-word location.
Indexed PC addresses require index-register state from the caller.

## Strict framing and upstream defects

The interpreter validates big-endian opcode and extension words, duplicate
register fields, CPU features, operand counts, address classes, index
extensions, signed branch and displacement limits, and FPU control-register
transfer restrictions. A decoded candidate must re-encode to its consumed
bytes, so unused fields cannot silently disappear from disassembly.
This is instruction decoding rather than privilege, execution-state,
address-map, or complete-program validation.

Import records retain `original_mask`, `original_args`, and `correction`
when repairing these upstream contradictions:

* One `fmovem` mask fixes a coprocessor-ID bit that is an operand.
* Three `pflushs` masks fix a variable effective-address mode.
* Three MAC/MSAC masks fix an explicit shift operand's bits.
* Two unsized `fmovem` source addresses require long immediates; one of these
  records also has the coprocessor mask correction above.

Other upstream disassembler behavior is handled in framing without copying
its bugs: immediate coprocessor traps include the immediate after the
condition word; `stldsr`/`strldsr` include their third word; GNU's relaxable
`jra`/`jbsr` records use branch displacement encoding. The `swbeg`/`swbegl`
records are retained as GNU data markers. `swbeg` shares its first word with
`illegal`, so instruction decoding canonically returns `illegal` for that
word; treating following bytes as a jump table requires external context.

## Validation

`go test ./pkg/m68k` checks every template on classic and ColdFire profiles,
more than 100,000 address expansions, deterministic malformed/random input,
JSON and template workflows, CPU restrictions, branch targets, register
aliases, and retained GNU assembler vectors. Source corpus tests do not
require an installed cross toolchain.

An independent target-only GNU binutils build can be exercised with
`MKASM_M68K_BINUTILS=/path/to/build go test ./pkg/m68k -run TestGNU -v`.
The corpus disassembler comparison checks all 1,887 source templates:
1,801 have matching complete instruction lengths; 86 are explicitly counted
upstream disassembler/data-marker exceptions (trap cursor/offset bugs,
incorrect masks and matching priority, and RTM lookahead). The retained
assembler vectors independently exercise these affected families, ordinary
instructions, processor extensions, MMU banks, ColdFire MAC/EMAC/FPU,
branch sizes, and all major effective addresses.

Set `MKASM_M68K_RUST_OUTPUT=/artifact/directory` when running
`go test ./pkg/m68k -run TestRustGeneration -v` to generate both crates and
the full Go/Rust corpus, address, and GNU-vector comparison tests. Then run
`cargo test --test corpus` in each generated crate.
