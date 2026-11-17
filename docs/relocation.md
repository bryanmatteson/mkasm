# Encoded references and block relocation

Generated codecs expose addresses independently of printed operand spans. A
reference identifies its operand, control-flow versus data/literal purpose,
physical encoded fields, signed range and scale, PC bias/alignment, wrapping and
resolved target. Register-based effective addresses are not static references.
The importer's complete encoding constraints remain authoritative: a range is a
necessary field bound, and rewriting checks the complete instruction.

All APIs that write caller-owned storage validate into temporary storage first.
An error leaves every output byte unchanged. Allocating block APIs return no
partial block. Address/length arithmetic is checked before block construction.
The source instruction/block is never modified.

## x86

`Decoded::address_references(ip)` returns `Vec<AddressReference>`. The reference
contains `operand_index`, `kind`, `bit_offset`/`bit_width`, `signed`, `scale`,
`pc_relative`, `pc_bias`, `pc_align_bits`, `wrap_bits`, `min`/`max` and `target`.
Bit offsets count from the first physical instruction byte; fields are little
endian. Bounds are encoded integer bounds before scale. RIP-relative and
address-size-overridden EIP-relative memory references are data references;
EIP-relative target arithmetic wraps at 32 bits. Absolute displacement-only and
moffs addresses are classified separately. Segmented far pointers require
segment state and are not presented as flat addresses.

`rewrite_reference(decoded, original, ip, reference_index, target, output)`
retains the exact form and validates that the original bytes agree with the
decoded instruction. `relocate` retains form and size, preserving every encoded
PC-relative target. Both return a typed error on range/constraint failure.

`relocate_block(original, old_ip, new_ip, mode)` returns `RelocatedBlock` with
`bytes`, `(original_offset, relocated_offset)` pairs in `offsets`, and
`original_len`. `relocated_address(old_offset, new_ip)` resolves an instruction
boundary (or the new block end) as a linear byte address. In wrapping modes,
mask this result to the architectural IP width when comparing it with a branch
target. `relocate_block_into` copies the successful
result into a caller buffer.

Block relocation remaps direct branches/calls to instructions inside the source
block, and preserves external destinations and every RIP/EIP-relative data
target. A destination exactly at the original block end is an external
continuation, so it keeps that address. A target inside an instruction returns
`MidInstructionTarget`. Membership and boundary offsets use modular arithmetic
in Mode16/Mode32, including blocks crossing the address-space boundary. Blocks
whose source or relaxed output exceeds the applicable IP address space return
`Unsupported` because architectural addresses would identify multiple physical
occurrences. Plain two-byte JMP and Jcc grow to the mode's near form
when needed; relaxation repeats until all instruction offsets stabilize. It
never shrinks an encoding. The selected near form must be present in the
generated catalog. LOOP/JCXZ-family expansion, prefixed short-branch expansion
and scratch-register/absolute veneers are unsupported and return explicit
errors when needed. Calls to their immediately following instruction return
`PositionDiscovery` because moving the pushed return address would change
position-discovery semantics.

The decoded memory view and formatter treat `67` with long-mode ModRM rm=5 as
EIP-relative. Text uses `[eip+...]`, the text assembler preserves its address
size, and displacement-hole metadata uses
`Position::WrappingInstructionRelative { bits: 32 }`.

## A64

The crate root and `formatters::references` export `address_references`,
`rewrite_reference`, `relocate`, `relocate_into`, `relocate_block` and
`relocate_block_into`. References reuse the formatter's generated label operand
bit placements, including split immediates and literal bits. `operand_index`
selects the formatter part rather than a rendered text span. `EncodedBits`
positions refer to the architectural 32-bit instruction word; serialization is
little endian. `Position` distinguishes instruction-relative and page-relative
ADRP calculations. Signed ranges bound the encoded integer before scale/bias.

B.cond and BC.cond references are both classified as control flow, so their
internal destinations remap to relocated instruction boundaries. BC.cond retains
its native encoding and returns a range error when its target cannot fit; it
does not use the B.cond expansion.

Conditional B, CBZ/CBNZ and TBZ/TBNZ relax to an inverted branch over an
unconditional B. Internal targets are remapped after every growth pass.
Unconditional B/BL destinations beyond their native range, veneers requiring
scratch registers, and paired ADRP+ADD transformations return range errors.
ADR, ADRP and literal addresses preserve their original targets, including data
inside the input block. This operation relocates instructions, so a caller must
supply a block of instructions rather than mix inline literal data into it.
BL to its next instruction is rejected. Blocks and addresses must be aligned to
four bytes, and truncated tails fail before writing.

## A32 and Thumb

The crate root exports the `references` APIs. `Decoded::address_references`
returns branch, ADR and literal references with PC+8 (A32), PC+4 (Thumb), aligned
PC bases and architectural 32-bit wrapping. `ReferenceTransform` makes rotated
Arm immediates and the Thumb J1/J2/sign relationship explicit. Reference `bits`
use architectural word positions. `AddressReference::encoded_bits(length,
mode, endian)` gives physical byte-order bit positions, including T32's high
halfword first and endian conversion within each halfword.

`relocate` and `relocate_block` accept the execution mode and endian. T16 B and
B.cond relax to their corresponding T32 forms. The block result carries the same
byte-offset mapping as x86/A64. Internal targets must be instruction boundaries.
Mode-changing internal BLX targets, IT blocks, unmodeled PC reads, branches
outside the available wide range and transformations that need additional
instructions return explicit errors. Calls to the next instruction are rejected.
Data references retain their original destinations; the implementation does not
coalesce ADR/literal references with branch destinations.

## Imported fixed-field catalogs

The common Go `codec.Decoded` model supplies `AddressReferences` and
`RewriteReference`. Generated Rust supplies equivalent
`Decoded::address_references`/`rewrite_reference` with imported physical
`BitSlice`s, signedness, scale/bias, semantic `Domain` and complete `Position`
metadata (including pre-alignment bias, region/page rules and wrapping).
Generated `relocate_block` remaps internal direct references without selecting a
different catalog form. Delay-slot architectures and relocated opcode-only
internal targets are explicitly unsupported by this common adapter. Choosing
alternate encodings requires an architecture-owned equivalence rule; the common
adapter reports exact-form range errors instead of guessing one.

Conditional calls (`conditional_call` and `conditional-call`) have the same
control-reference identity and internal remapping as direct calls. Both spellings
reject call-next position discovery, including when the following IP wraps.
`TargetMask` / `target_mask` is applied to inspected control destinations, in
agreement with `BranchTarget` / `branch_target`. A rewrite must represent the
requested architectural destination exactly: ignored alignment bits, truncated
high bits, and a relocated target that violates the mask cause transactional
rejection. Data references keep their own address semantics.

Internal membership uses explicit relative-PC wrapping or the architectural
width declared by a destination mask. The highest set destination-mask bit
defines wrapping width; low alignment bits do not remove byte offsets from the
source block. Absolute field width alone does not establish processor address
width. Catalogs without either source declaration retain 64-bit membership.
Source blocks larger than a reference's declared address space are unsupported.
The Z80/Z180 importer supplies the 16-bit destination mask for direct control
flow, so the canonical-body API also remaps wrapped absolute jumps and calls.

## Z80 and Z180 prefix framing

The Z80/Z180 wrapper exposes `relocate_block`, `relocate_block_into` and their
`_with_features` variants for complete physical streams. The wrapper decodes
ignored DD/FD prefix trains as part of their instruction, retains every prefix,
and calculates relative fields from the canonical body's actual address.
Internal branches and calls remap to complete instruction starts; targets into
a prefix train or another instruction's body return `MidInstructionTarget`.
External targets retain their original architectural address. The selected
Z180 profile continues to reject undefined redundant-prefix combinations.

Address arithmetic wraps at 16 bits. A full-stream block may span the address
space boundary, but its physical size must not exceed 65,536 bytes: a larger
block gives some architectural addresses more than one physical occurrence and
is explicitly unsupported. The existing single-instruction framing APIs still
accept arbitrary prefix trains. This adapter retains exact forms; JR/DJNZ range
failures are reported instead of introducing a new instruction sequence.

`relocate_body_block` and `relocate_body_block_into` are separately named public
APIs for canonical bodies. Their addresses and boundaries exclude ignored
prefix bytes. They expose the common catalog adapter without implying that it
understands complete Z80 prefix-framed streams. Both body and full-stream APIs
use public `BlockRelocateError` and `RelocatedBlock` types; caller buffers remain
unchanged after errors.

## Validation

`go test ./pkg/x86 -run TestGeneratedBlockRelocation` compiles a generated Rust
consumer covering internal forward/backward branches, internal calls, external
targets, growth cascades, RIP/EIP loads, EIP text round trips, truncation,
mid-instruction targets, overflow, unsupported widening, call-next rejection and
transactional failures. `go test ./pkg/codec -run
'TestEncodedAddressReferences|TestGeneratedEncodedReferences|TestArchitecturalReferenceTargets|TestGeneratedArchitecturalReferences'` checks both Go
and generated Rust consumers.

`go test ./pkg/arm -run TestGeneratedBCRelocation` compiles a portable reduced
BC.cond XML fixture through the real parser, assembler and disassembler generators
and tests forward/backward internal remapping and transactional range rejection.

Full Arm corpus consumers live in `pkg/arm/testdata/relocation_{a64,arm32}.rs`.
Run `go test ./pkg/arm -run TestGeneratedArmRelocation` with
`MKASM_RELOCATION_A64_CORPUS` and/or `MKASM_RELOCATION_ARM32_CORPUS` pointing to
the corresponding complete XML archives. These checks generate real codecs and
compile and execute their Rust integration tests. The A64 consumer includes a
conditional/test-branch growth cascade across 8,192 source instructions; the
A32/Thumb consumer checks both endian modes and architectural halfword order.

`go test ./pkg/z80 -run TestGeneratedPrefixBlockRelocation` generates both Z80
and Z180 codecs and compiles their library and public consumer with
`RUSTFLAGS=-D warnings`. Tests cover the explicit body API, framed internal and
external branches, architectural wrapping, prefix retention, feature filters,
mid-instruction/prefix-interior destinations, call-next, address overflow,
truncation, bounded block ambiguity and transactional output failures.
