# Z80, Z180 and derivative instruction streams

`Parse(reader, architecture)` imports actual primary opcode descriptions and returns
a `codec.Backend` with an instruction catalog and a dedicated framing runtime.
The prefix-framed targets are `z80` and `z180`. The source-defined CPU profiles
`z8401x` and `z182` use their parent Z80 and Z180 instruction grammars respectively,
as specified by Ghidra's bundled `z80.ldefs`. A nil reader uses the bundled source;
a non-nil reader accepts MAME's complete `z80.lst` or JSON written by `WriteJSON`.
All six 256-entry source opcode spaces are required and duplicate/missing entries
are errors. JSON preserves the framing model, source digest, operand fields,
features and instruction metadata.

The Z80 catalog contains 1,446 finite physical forms covering base, CB, ED, DD,
FD, DDCB and FDCB, including the source's index halves, SLL, indexed-CB register
results, ignored BIT selectors, duplicate ED encodings and undefined ED no-ops.
An undefined ED instruction consumes both bytes. DD/FD prefix trains have no
artificial length limit: the last effective index prefix selects IX or IY; earlier
prefixes and prefixes ignored by the instruction remain part of that instruction.
An ED prefix ignores preceding DD/FD prefixes. A stream containing only DD/FD is
truncated. The stream API consumes the first instruction and leaves trailing bytes.

The Z180 catalog contains 732 forms from the Z80 documented grammar plus its
IN0, OUT0, TST, TSTIO, MLT, OTIM/OTDM/OTIMR/OTDMR and SLP extensions and Ghidra's
flag-only IN0 form. Reserved opcode combinations return `ErrUnknown`, including
ignored/repeated index prefixes, index halves, SLL and indexed-CB register-result
extensions. Z180's invalid-opcode trap behavior is described by Zilog's manual;
these byte sequences are not silently decoded as ordinary Z80 instructions.
Separate targets `ez80`, `ez80-adl`, `z80n`, `r800` and `gbz80` use the
complete retained GNU variant descriptions through
`ParseVariant(reader, architecture) (*codec.Catalog, error)`. A nil reader loads
`data/variants.json.gz`; a non-nil reader accepts that target's resolved
`WriteJSON` catalog. eZ80's non-ADL and ADL modes are distinct targets because
immediate widths and PC wrapping depend on the selected mode.

| Target | Retained physical source forms |
|---|---:|
| `ez80` | 6,705 |
| `ez80-adl` | 6,705 |
| `z80n` | 1,279 |
| `r800` | 1,255 |
| `gbz80` | 500 |

These 16,444 forms use the shared Go/generated Rust encoder, decoder, formatter,
assembler, operand analysis, template, edit and relocation APIs. They have their
own variant grammar; the arbitrary ignored-prefix framing wrapper described
below belongs to `z80`, not every derivative target. Selecting `gbz80` does not
admit ordinary Z80-only instructions. GBZ80 STOP retains its required trailing
zero (`10 00`). GNU 2.44 emits only `10` for its `stop` mnemonic, so the oracle
adds `.byte 0` explicitly and records that assembler discrepancy.

```go
variant, err := z80.ParseVariant(nil, "ez80-adl")
if err != nil { panic(err) }
// Shared codec.Catalog APIs, using the selected mode's operand widths.
choices, err := variant.Assemble("ld a,(ix-5)", 0x1000)
_, _ = choices, err
```

The CLI dispatches each canonical target to the appropriate loader. `Parse`
continues to accept only the Z80/Z180 framing model; use `ParseVariant` for the
five derivative targets.

## Go consumer

```go
c, err := z80.Parse(nil, "z80")
if err != nil { panic(err) }
d, err := c.Decode([]byte{0xdd, 0xfd, 0xdd, 0x21, 0x34, 0x12})
if err != nil { panic(err) }
// d.Length == 6; d.Prefixes == []byte{0xdd, 0xfd}; d.Body includes effective DD.
plain := d.CanonicalFormat(0x1000) // "ld ix,4660"
exact := d.Format(0x1000)          // "prefix[ddfd] ld ix,4660"
raw, err := d.Reencode()          // exact original bytes
alternatives, err := c.Assemble(exact, 0x1000) // first result equals raw
_, _, _ = plain, raw, alternatives
```

`Encoding`, `Values`, signed index displacements, immediate fields, encoded
register/pair/condition selectors, flow metadata and `BranchTarget(address)` are
available structurally. Branch arithmetic wraps at 16 bits and includes every
ignored prefix in the PC base. Repeating block instructions expose their repeat
target. Indirect branches expose flow metadata without inventing a known target.
Exact encoding accepts an ID, semantic operand map and optional ignored DD/FD
bytes; prefixes that would change the selected instruction are rejected.

Ordinary assembly returns all physical alternatives in deterministic order,
preferring shortest encodings and the documented indexed BIT selector. `Format`
adds `enc[id]` when ordinary text would prefer another physical encoding; it adds
`prefix[hex]` for ignored prefixes. These explicit qualifiers make every formatted
instruction assemble back to its exact original bytes. `CanonicalFormat` provides
ordinary assembler syntax when that lossless annotation is not wanted.

`ParseTemplate(text,address)` supports `$name`, `${name}` and `_` in operand
positions. Bindings use semantic numeric operands (register encoded indices and
signed displacements). Repeated names require equal values. `Matches` returns
instruction length and bindings; `Encode` accepts bindings. Prefix qualifiers
match exact prefix bytes. An unqualified template matches an instruction without
ignored prefixes. Wildcards match but cannot be encoded without a value.

## Generated Rust

For `z80`/`z180`, `GenerateRust` emits a standalone crate with the same framing, exact-byte text,
structured decode/encode, targets and templates. Public entry points include
`decode`, `encode`, `encode_with_prefixes`, `assemble_at`, `Decoded::reencode_into`
and `Template::parse_at`. The generated fixed catalog is internal to the wrapper;
the public decoder handles arbitrary prefix trains. Caller-owned output buffers
are supported. `UPSTREAM-LICENSE` retains the source notices and license texts. The public
`UNSUPPORTED` metadata mirrors the underlying instruction catalog. Generated
library and external consumer tests compile with `-D warnings`; the fixed-field
module remains private so public decoding always retains prefix framing.

## Primary sources and corrections

- [MAME `z80.lst`](https://github.com/mamedev/mame/blob/47d7645d814fdf93b5ffda7df1593070554438c7/src/devices/cpu/z80/z80.lst),
  commit `47d7645d814fdf93b5ffda7df1593070554438c7`, BSD-3-Clause, copyright
  Juergen Buchmueller and Andrei I. Holub. This actual executable instruction
  corpus defines all 1,536 source opcode records and the prefix dispatch rules.
- [MAME `z180ed.hxx`](https://github.com/mamedev/mame/blob/47d7645d814fdf93b5ffda7df1593070554438c7/src/devices/cpu/z180/z180ed.hxx),
  same revision, BSD-3-Clause, copyright Juergen Buchmueller. It distinguishes
  reserved ED82/8A/92/9A from the valid OTIM family. GNU's broad Z180/eZ80 table
  mask otherwise admits these eZ80 INIM forms incorrectly on Z180.
- GNU binutils **2.44**, `opcodes/z80-dis.c`, GPL-3.0-or-later. The actual ED
  opcode table and its operand handlers supply the Z180 extension description.
- [Ghidra `z80.slaspec`](https://github.com/NationalSecurityAgency/ghidra/blob/42db038f3c88c6bd7e9bedbb919138111f8b77fd/Ghidra/Processors/Z80/data/languages/z80.slaspec),
  revision `42db038f3c88c6bd7e9bedbb919138111f8b77fd`, Apache-2.0. Its Z180
  flag-only IN0 is included even though GNU's assembler/disassembler omits it.
- Zilog [Z80 CPU User Manual UM0080](https://www.zilog.com/docs/z80/um0080.pdf)
  and [Z8018x User Manual UM0050](https://www.zilog.com/docs/z180/um0050.pdf),
  instruction tables and opcode maps. GNU's [documented opcode options](https://sourceware.org/binutils/docs-2.44/as/Z80-Opcodes.html)
  distinguish its complete Z80 undocumented assembly mode from the Z180 grammar.

Assembly spelling normalizes MAME's `EX HL,(SP)` to the documented `EX (SP),HL`.
Ghidra has concrete source errors for FD29 (`ADD IY,IX` instead of `ADD IY,IY`),
ED6E (`IM 1` instead of `IM 0`), index-half self loads, and Z180 `MLT SP`
(its pair table incorrectly selects AF). The backend follows the primary opcode
execution source and GNU/Zilog in those cases. Ghidra also omits undocumented
indexed-CB results/SLL and many ED aliases/no-ops, as well as ignored/repeated DD/FD prefixes. Oracle tests record each exact
gap and reject discrepancies outside the explicit opcode-specific list.

## Validation

The ordinary suite checks every finite form through structured encoding,
dedicated decoding, exact reencoding and text round trips. Boundary tests include
65,537 ignored prefixes, signed index limits, 16-bit branch wrap, malformed source
and text, truncated byte streams, templates and JSON. `FuzzDecode` checks consumed
length and exact byte retention for arbitrary input.

Opt-in production consumers and independent oracles:

```sh
go test ./pkg/z80
go test ./pkg/z80 -run '^$' -fuzz FuzzDecode -fuzztime=10s -parallel=2
MKASM_Z80_RUST=1 MKASM_Z80_ARTIFACT=/absolute/artifacts/generated go test ./pkg/z80 -run TestGeneratedRust -v
MKASM_Z80_GHIDRA=1 MKASM_Z80_ARTIFACT=/absolute/artifacts go test ./pkg/z80 -run TestIndependentGhidra -v
MKASM_Z80_AS=/absolute/z80-binutils/gas/as-new MKASM_Z80_ARTIFACT=/absolute/artifacts go test ./pkg/z80 -run TestIndependentGNU -v
MKASM_Z80_AS=/absolute/z80-binutils/gas/as-new go test ./pkg/z80 -run TestVariantGNUOracle -v
```

GNU 2.44 is configured for `--target=z80-elf --with-system-zlib`, then built with
`make all-gas all-binutils`. The GNU corpus checks assembler output for all 1,446
Z80 forms and 731 Z180 forms; Z180 ED30 is checked independently by Ghidra instead.
Duplicate source forms can assemble to a preferred equivalent opcode; the test
requires GNU's bytes to be among the backend's alternatives, while the source
round-trip checks retain each original physical encoding. A real indexed copy
loop with symbolic labels additionally checks instruction walking, text and
structured round trips, lengths and its backward DJNZ target.

The retained Ghidra 12.1.2 run verifies 794 Z80 finite-form decodes and
1,101 finite-form assemblies (plus seven prefix-case canonical assemblies),
and 730 Z180 decodes and assemblies each. Its 1,008 exact operation gaps
include seven prefix-framing rejections and the source errors listed above;
these are recorded as gaps rather than reported as successful oracle coverage.
GNU and the primary source round trips independently cover the omitted valid
Z80 forms. Both generated public Rust consumers run the complete finite catalogs
and exercise lossless qualifiers, prefixes, targets, templates and malformed
input; the Z80 consumer also tests unbounded prefix retention and 16-bit wrapping
at the largest public address value.

The variant corpus suite checks every retained form at zero, nonzero and
signed/boundary operand samples through encode/decode/reencode and text assembly.
The native GNU variant oracle covers all 16,444 source forms, comparing exact
section bytes with the complete legal assembly candidate set. Mode-specific
`.assume adl` context is supplied where GNU's eZ80 syntax requires it; the GBZ80
STOP correction above remains explicit. These are source-form checks, not an
exhaustive enumeration of all operand values or execution semantics.
