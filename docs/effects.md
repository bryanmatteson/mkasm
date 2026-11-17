# Architectural effect summaries

Generated x86, A64, A32/Thumb and fixed-field codec crates expose a public
`effects` module. `Decoded::effects()` returns an owned `EffectSummary` without
external dependencies. A64 and A32 also expose `effects::effects(&decoded)`.
The existing x86 `semantic_access()` boolean API remains a coarse compatibility
summary; completeness-sensitive consumers use `effects()`.
Hexagon packet and Xtensa bundle `effects()` return individual source summaries
in word/subinstruction or slot order. They do not infer cross-instruction value
dependencies. Z80/Z180 facade `effects()` delegates to its exact decoded body;
redundant index prefixes do not invent architectural data effects.
The Go fixed-field codec exposes `Decoded.Effects()` and retains the complete
source `EffectSpec` on each encoding and in exported JSON.

`knowledge`, `registers_knowledge`, `flags_knowledge`, and `memory_knowledge`
state completeness independently. `Complete` applies to the represented
architectural category. `Partial` retains useful facts while leaving other
accesses unspecified. `Unknown` supplies no exhaustive classification.
An omitted flag or an `Unknown` flag action does **not** preserve that flag.
An empty list with incomplete coverage does **not** prove absence of effects.
`other_side_effects` remains unknown unless the source explicitly excludes
unmodeled effects. These APIs describe normal architectural accesses, not
instruction value evaluation, exceptions, debug events, MMU walks, or timing.

Register effects identify a bank, number or source name, bit offset and optional
width. Width is the accessed slice, not the encoded register-number field size.
AH is GPR 0 at bit offset 8. Address-only register inputs have `address=true`;
implicit stack/IP/source operands have `implicit=true`. Reads and writes may
be conditional. `ZeroUpper` clears the enclosing register above the written
width; `PreserveUpper` preserves bits outside the written slice; `Replace`
replaces the described register value. `Unknown` asserts no partial-write rule.
Value-dependent vector lane selection remains partial; EVEX merge masking
includes a conditional old-destination read, while zero masking does not add
that dependency. A mask value is not evaluated by these APIs.
Legacy register-to-register MOVSS/MOVSD writes cover only the low 32/64 bits
with `PreserveUpper`; scalar register sources use the same accessed width.
Their memory-load forms write all 128 XMM bits, including the cleared upper
portion, and preserve the enclosing vector register above bit 127.

Flag actions distinguish reads, writes, preservation, clear/set, undefined
results, and unknown behavior. Conditional effects are explicit. x86 opcodesDB
`iflags` and nested implicit memory address registers survive import.
Audited bounded ISA rules refine arithmetic/logical flags, flag controls,
ordinary moves, condition branches, and shifts/rotates at decoded immediate
counts. Rotate CF/OF actions outside the qualified zero/one count cases remain
unknown. Variable shift counts leave affected flag actions unknown and
conditional. Near stack accesses use the architectural stack width in long
mode; non-long-mode stack pointer width is unknown without SS context. LEA
reads address inputs without reading memory. Unsupported flag families retain
source facts and unknown coverage.
Near JMP forms preserve flags. Far JMP/CALL forms retain unknown flag coverage
without descriptor context: protected-mode task switches can replace flags.

Memory effects distinguish direction, width in bits, conditional execution,
ordering, atomicity and pre/post writeback. An absent memory operand reference
means an implicit access or an address the source does not resolve. Unknown
ordering or atomicity must not be inferred from the absence of a LOCK prefix.
LOCKed read-modify-write and memory XCHG report atomic sequential accesses.
A64 LDAR/STLR report acquire/release atomic accesses. Ordinary memory accesses
retain unknown atomicity where alignment and architectural context matter.

A64 rules are selected by allocated binary encoding classes, rather than
mnemonic prefixes. Covered classes include integer ADD/SUB immediate/shifted,
logical immediate/shifted, move-wide (including exact MOVK input slices),
conditional select, scalar integer immediate loads/stores and pairs, and
LDAR/STLR. A32 immediate single-data-transfer rules preserve predication and
writeback. Unmodeled A64 SIMD/SVE/system and Thumb effects remain unknown.
Pair base/writeback overlap and duplicate load destinations are checked
independently. Their constrained unpredictable behavior can include a NOP,
so both register and memory categories become partial and their accesses
conditional. Load/base overlap also leaves writeback unknown because a load
can execute with writeback suppressed. NZCV preservation remains complete
independently. SP bases and ZR data operands do not alias despite sharing the
encoded register number 31.
The Arm XML parser's operand usage defaults are not trusted as effects: they
do not distinguish destinations. Its current pseudocode projection does not
retain enough execution semantics to prove all architectural accesses.

LLVM TableGen imports retain OutOperandList/InOperandList, implicit Defs/Uses,
mayLoad, mayStore, and hasSideEffects. Architecture adapters establish which DAG
operands are registers before effect generation. Source register-class names
remain bank identities; missing physical widths, flag interpretation, ordering,
and subregister policies remain unknown. Positive mayLoad/mayStore properties
are conditional possibilities, not unconditional accesses. Explicit false/false
proves no source-modeled memory accesses. Non-TableGen catalogs may provide an
explicit `effects` object using the same source model. Missing metadata stays
unknown; no generic instruction-name classifier invents semantics.
