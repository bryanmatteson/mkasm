# Generated Arm structured analysis

The A64 crate exports `analysis::analyze(word, address)` and
`Decoded::analyze(address)`. The A32/Thumb crate exports
`Decoded::analyze(address)` and
`Decoded::analyze_with_thumb_condition(address, effective_condition)`.
These paths do not format or parse assembly, initialize the text assembler's
caches, or allocate. They use the same operand definitions, constraints and
numeric transformations as the formatter. A64 selects preferred aliases through
static high-byte candidate buckets, rather than scanning the whole corpus.

A32 `details(address)` shares operand/access extraction with `presentation()`
without rendering operands. `mnemonic_text()` renders only the mnemonic and its
condition, flag and size suffixes. `try_mnemonic_text()` exposes errors for
unprintable mnemonic metadata; the convenience method retains the static
mnemonic on those encodings.

An analysis separates the canonical encoding identity from the preferred display
identity. Components retain Arm operand symbols and typed values. A64 register
values distinguish W/X widths, SP from ZR, fixed-width SIMD registers, scalable
vectors, predicates, predicate counters and tiles. Arrangements and lanes attach
to their register component; predicate operands expose merging/zeroing mode.
`attached_to` links a modifier component to its register. Register-list members
carry a common `Location::RegisterList` identifier; `register_lists()` exposes
first/count/stride descriptors, including source range notation. A32 uses its existing typed
`Register` enum and represents lists as a mask or a first/count/stride sequence.

Memory addresses separate the base, index, signed displacement, shift/extend and
amount, indexing mode and writeback. A64 `memory_addresses()` enumerates every
bracketed address in source order; `Memory.id` and `Component.memory_id` link each
address to its components. `memory_address(id)` looks up that identity without
allocation. The existing `memory` convenience field is present only for exactly
one address; use the slice for instructions with multiple addresses. MOPS copy
instructions retain both addresses with `IndexMode::Updating`, since their
pointer updates follow the variable-length copy operation rather than a fixed
pre/post offset. Their count register remains an ordinary operand; the source
writeback marker is exposed by `Component.writeback`. Post-index values are separate from the
address used for the access. A64 offsets state whether their unit is bytes,
vector lengths or predicate lengths. A32 literal loads expose an absolute target
and the aligned architectural PC base; its `subtract` flag describes register
index polarity, while numeric displacement and post-index immediates are already
signed. Shift selector/amount and alignment operands never contribute to the
numeric displacement. A32 `alignment_bits` preserves an explicit memory alignment
requirement, and `shift` applies to either `index` or `post_register`.

Control flow states the transfer kind, predicate, target and fallthrough.
A64 compare-and-branch instructions expose `Predicate::RegisterCompare` with
their 8/16/32/64-bit operand width, signedness, exact relation and register or
unsigned immediate operand. The predicate uses the canonical physical relation
even when the display spelling is an alias. Consistent conditional branches
retain their condition-code predicate. Neither compare-and-branch operands nor
their predicates imply a read or write of NZCV.
Direct A64 address arithmetic is checked: a target or fallthrough outside the
64-bit address space is `None`. A32 architectural addresses wrap in 32 bits and
branch targets account for the ARM/Thumb PC bias and BLX alignment. A32 identifies
instruction-set exchange. RFE addressing variants expose their block address,
return target, and `exception_return` marker; exception returns can restore the
instruction set. Thumb TBB/TBH expose `BranchTarget::Table` with its table address,
entry width, architectural PC base, and loaded-entry target scale. TBH's table
index shift is independent of that target scale. A Thumb instruction without an explicit condition or
caller-supplied IT context reports `ThumbItStateRequired`; pass condition 14 when
outside an IT block. The API does not infer IT state from a single instruction.

`Coverage::Partial` and `Value::Unknown` are part of the contract. An encoding
without a usable operand definition still has canonical/display identities and
partial analysis. Unresolved symbolic expressions, unsupported operand relations,
and transfer classes without a modeled predicate do not become fabricated
registers, offsets or linear control flow. `Complete` describes the represented
operand/control-flow facts; register effects, memory access widths, flags and
instruction semantics have separate generated APIs. A32 data-processing writes
to PC that need instruction semantics report unknown control flow.

The Go integration test `TestRustAnalysisRealCorpus` invokes the production parser/generator
and compiles/runs real generated Rust against both full corpora. Set
`MKASM_CORPUS` and `MKASM_ARM32_CORPUS` to local corpus archive paths. It covers
aliases, SP/ZR, memory indexing, branch targets and predicates, vector lanes,
arrangements and lists, SVE predicates, address overflow, multiple MOPS addresses,
shift/alignment operand roles, shifted register post-index, every RFE addressing
variant, TBB/TBH table and target scaling, and allocation-free A64/A32 analysis. Ordinary Go tests cover canonical alias chains and candidate buckets.
