# Intel MCS-51 / 8051

`Parse(io.Reader, architecture)` imports the actual Ghidra
`8051_main.sinc` constructor and token definitions. Pass this source file, not an
include-only `.slaspec`. `Default()` loads the bundled pinned source. The result
embeds `*codec.Catalog`, implements the shared backend interface, and adds Intel
literal spelling, Go templates, and address-space helpers.

The source is **Ghidra 12.1.2**, revision
`c0f584bf229fffba61b36431f3ce30c0c3e4e682`, under Apache-2.0. Its unmodified
source, processor symbols and license are retained in `data/`. The bundled source
SHA-256 is `a514b25d08b85893c9fd96ead444eff856b201d98e0fd62ecf57e4387fd1a009`.

Supported targets:

| Target | Aliases | Instruction set and addressing |
| --- | --- | --- |
| `mcs51` | `8051`, `mcs-51` | Complete classic 8051 instruction set, 16-bit code addresses |
| `mcs80390` | `80390`, `ds390` | Complete source-backed DS80C390 flat mode; 24-bit DPTR, LJMP/LCALL and 19-bit AJMP/ACALL |

Each selected target contains **111 core constructor forms**, expanded across
**255 defined opcode bytes**, plus **nine `C` aliases** for source spelling `CY`.
Opcode `A5` remains reserved. Source constructors that specialize SFR bit p-code
are folded into their unrestricted constructor with identical instruction bytes
and displayed bit operands. These are semantic alternatives rather than additional
opcodes. The importer does not execute p-code.

The two targets are separate catalogs because their framing differs. A generic
union would decode long/short operands ambiguously. Source-defined feature metadata
and a named profile identify the selected target.

## Instruction, text and template APIs

The shared catalog provides `Encode(id, values)`, `Decode(bytes)`, decoded
`Format(address)` and `BranchTarget(address)`, JSON and Rust generation.
`Catalog.Assemble(text, address)` accepts ordinary Intel syntax, source SFR/bit
symbols, `C` / `CY`, complemented bit operands, and hexadecimal/binary suffix
literals such as `#0ffh` and `#101b`. Canonical text uses hexadecimal addresses and
decimal immediates. Byte/word immediates also accept their signed two's-complement
spelling. `MOV direct,direct` keeps its architectural **source byte first** layout.

`ParseTemplate(text, address)` compiles reusable Go patterns. `$name` captures a
whole encoded operand; `_` matches without capturing. `Encode(bindings)` supplies
captures and returns all compatible byte encodings. `Match(bytes)` returns the
decoded instruction and captured values. Fixed branch text is an absolute address
resolved at template creation; captures hold the underlying signed displacement
or page-offset field. Rust output exposes the equivalent shared `Template` API.

PC-relative branches use the address after the complete instruction. They wrap
within the selected 16/24-bit code space. AJMP/ACALL take their page from the
**post-instruction PC**: 2 KiB pages for 8051 and 512 KiB pages in DS80C390 flat
mode. Encoding from text rejects targets outside that page. LJMP/LCALL addresses
and immediate DPTR data are big endian. An instruction may cross the code-space
end when its bytes are supplied in stream order; a memory reader is responsible
for fetching those bytes with the processor's wrapping behavior.

The register operand `R0`..`R7` represents the logical banked register. It does not
silently become a fixed internal-RAM address. Explicit helpers model state:

* `RegisterAddress(reg, psw)` resolves PSW.RS1:RS0 into physical internal RAM.
* `ResolveDirect` distinguishes low internal RAM from SFR space.
* `ResolveBit` maps bits 00..7f to bytes 20..2f and bits 80..ff to bit-addressable SFR bytes.
* `ExternalIndirectAddress(riValue, p2)` models the classic MOVX @Ri external bus.
* `ComputedCodeAddress` models @A+DPTR / @A+PC additions and target-width wrapping.

Rust output includes corresponding functions, an independent corpus test and an
external public API consumer test by default. It has no dependencies.

## Validation and exact boundaries

The retained independent corpus includes:

* **4,590 Ghidra cases**, covering every defined opcode in both targets, three
  operand patterns and three PC positions, including page and code-space edges.
  Ghidra decoding matches all **3,900** cases that its address buffer accepts;
  its buffer rejects the **690** instructions crossing the code-space end.
* Ghidra assembles **3,564** cases exactly, with zero byte differences. Its solver
  declines **192** in-range page-expression cases and **144** in-range bit-expression
  cases; another **690** cases exceed its linear address buffer. These oracle
  limitations are recorded, not counted as successful assemblies.
* **1,530 SDCC 4.6.0** cases from the independent `sdas8051` / `sdas390` assemblers
  and `sdld` linker, covering every defined opcode with three operand patterns in
  each target: **all exact, zero mismatches**. Linking resolves real branch and
  page relocations rather than comparing unpatched listing placeholders.
* All **65,536** first-two-byte combinations for the classic target, with exact
  decode/encode round trips; every invalid A5 slot is rejected.
* Real compiled and linked C program segments: 55 classic bytes and 65 flat-mode
  bytes. Go and generated Rust round-trip both code segments exactly. The classic
  program also executes in uCsim and stores the expected result **27** at internal
  RAM address 08 before reaching its final loop. Four additional uCsim instruction
  executions confirm classic AJMP/ACALL/SJMP wraparound and the post-PC page transition.
* Text assembly, reusable templates, source aliases, truncation, malformed operands,
  16/24-bit PC wrap, page transitions, register banks and bit mappings.

`go test ./pkg/mcs51` runs the retained source/oracle corpus without external tools.
Generated crates run the corpus with `cargo test --lib --test public`. The oracle
artifacts and reproduction scripts are under
`~/Documents/Developer/go-mkasm/architecture-expansion/mcs51/`.

This codec does not execute instructions, model device peripherals, infer live PSW,
P2 or DPTR state, link object files, or treat data tables as instruction streams.
The `.pspec` includes symbols from several 8051 derivatives; accepting such a symbol
as a direct/bit address does not assert that a particular chip implements that SFR.
MCS-251 binary/source mode, MX51 extension opcodes and CIP-51 flash/SFR banking are
separate device specifications and are not admitted by these targets.

Primary sources:

* [Pinned Ghidra instruction source](https://github.com/NationalSecurityAgency/ghidra/blob/c0f584bf229fffba61b36431f3ce30c0c3e4e682/Ghidra/Processors/8051/data/languages/8051_main.sinc)
* [Pinned processor symbols](https://github.com/NationalSecurityAgency/ghidra/blob/c0f584bf229fffba61b36431f3ce30c0c3e4e682/Ghidra/Processors/8051/data/languages/8051.pspec)
* [SDCC project and source distribution](https://sdcc.sourceforge.net/)
