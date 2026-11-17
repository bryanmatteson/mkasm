# Generated semantic recipes

Generated Rust A64, A32, x86 and common imported codecs expose `semantics` and
`recipes` modules and `Decoded::semantic_recipe(address) -> semantics::Recipe`.
The instruction address is the address of its first byte. Recipes are optional
semantic authority, independent of decoding, formatting and effect summaries.
Only a `Support::Full` result authorizes the transition described by a recipe.
`Partial(reason)` reserves a useful but incomplete description; consumers must
explicitly handle it. `Unsupported(reason)` supplies no guessed effects. The
current generators return Full or Unsupported, and the evaluator rejects both
Partial and Unsupported.

These are hand-audited, bounded encoding families. The generator does **not**
execute or automatically translate Arm documentation pseudocode. An imported
mnemonic does not establish instruction semantics. Other architectures' common
codec currently emits the same public schema and an explicit Unsupported result
for every decoded form; there is no architecture-independent mnemonic fallback.

## Coverage

| Target | Implemented families | Remaining boundaries |
| --- | --- | --- |
| A64 | Scalar integer arithmetic, bitfields, shifts, multiply/divide, conditional operations, address generation, branches/calls/returns; fixed-width integer SIMD saturation, shifts, permutations, widening/narrowing, multiply and reductions; scalar/vector FP arithmetic, fused operations, comparisons, conversions, rounding, reciprocal estimates/steps and BF16 conversion/dot products; scalar/vector/pair memory; native exclusive, acquire/release, LSE and pair CAS operations; selected status/system operations and barriers | All-class coverage is still in progress. Implemented extensions now also include SVE integer/predicate and many floating families, structured SIMD memory, CRC/FlagM/CSSC, AES/SHA/SM crypto and SME matrix/state operations. Remaining boundaries include additional scalable/matrix families, newer floating formats, ordinary data tag checking, authenticated exception returns, alternative FP environments and broader privileged/system transitions. Constrained pair/writeback overlaps remain qualified. |
| A32/Thumb | Scalar arithmetic, register shifters, multiply/divide, DSP saturation/parallel arithmetic, single/pair/multiple memory, stack and interworking, dynamic IT predication; VFP arithmetic, fused operations, comparisons, conversions including legacy half conversion, rounding and transport; integer NEON saturation, shifts, widening/narrowing, permutations and multiply; native exclusives and acquire/release; selected status operations and barriers | Structured SIMD memory, crypto and half-format extensions have dedicated helpers and tests. The explicit legacy VFP vector API covers LEN/STRIDE with untrapped or synchronous V3 exception contexts. Remaining floating formats and privileged/environment transitions still need further implementation. |
| x86 | Scalar moves/arithmetic/bit operations/shifts, near control and stack; packed integer SIMD, AES/PCLMUL/GFNI/SHA, mask operations and permutations; scalar/vector FP arithmetic, FMA, comparisons, integer/format conversion, min/max and rounding with explicit MXCSR; native locked atomics | Coverage is qualified by physical opcode, mode, prefixes, operand constraints and implemented native contracts. Masked/broadcast memory, BF16, the primary x87 catalog, all 590 imported AVX512-FP16 forms and 144 additional XED IFMA/VNNI forms now have dedicated recipes. RNDSCALE and REDUCE support all immediate scale fields. Remaining boundaries include additional newer floating families, broader privileged/environment transitions and other instruction families. Native x87 approximation capability remains explicit even when recipe extraction is Full. |

Ordinary SVE gathers and scatters implement all 70 June 2026 scalar-base/vector-offset and vector-base/immediate classes for LD1B/H/W/D, LD1SB/SH/SW and ST1B/H/W/D. Active accesses retain their original memory widths and lane order; inactive lanes suppress address and value reads. Active SP-based accesses require 16-byte SP alignment before memory is read; an empty predicate suppresses the SP read. Streaming execution requires effective FA64. Fault-first, nonfaulting and nontemporal forms have separate encoding contracts and do not inherit these recipes.

SVE LDFF1 and LDNF1 have separate recipes for all 76 June physical classes.
LDFF1's first selected access faults normally; later accesses and all LDNF1
accesses use explicitly recoverable reads. Faults update the architectural FFR
suffix, including the required element-group bits, while untouched backing
storage is preserved. False predicates suppress address and memory inputs.
Active checked-pointer-arithmetic contexts are currently rejected explicitly;
the implemented address path requires effective CPTA to be disabled. Native
execution uses the Normal-memory page model described below; Device memory,
full MTE policy and asynchronous SError require further native contracts.

SVE integer products include bottom/top narrowing shifts, widening and doubling multiply/accumulate, indexed and complex forms, signed and mixed dot products, integer matrix multiply, PMULL128, carry/borrow and bit deposit/extract/group. The product increment is qualified against 93 June primary pages and 130 physical classes across all five lengths. Streaming PMULL128 and bit permutation may use their dedicated SSVE capabilities without consuming unavailable effective FA64 controls. The consumer must still supply the corresponding architectural feature flags.

Ordinary SVE integer/address recipes additionally cover ADDVL/ADDPL/RDVL, all three ADR layouts, predicated ASRD, high signed/unsigned multiplication, full-width shift counts, reversed predicated shifts, bottom/top widening shifts, shift accumulation and shift insertion. They also cover signed/unsigned absolute-difference accumulation, bottom/top long absolute differences and accumulation, cross-lane signed long addition/subtraction, signed/unsigned clamps and both CADD rotations. These 42 classes cover all legal widths and shift amounts at every supported VL. ADR retains its streaming/FA64 qualification; distinct inactive operands are not read. The new arithmetic families use modular integer results and do not update saturation state; saturating complex addition has a separate encoding contract.

Fixed AdvSIMD integer comparisons include scalar/vector register comparisons and comparisons against zero. Integer MOVI/MVNI and ORR/BIC modified-immediate forms implement their complete immediate domains. URECPE and URSQRTE use the integer architectural estimate algorithms without floating-point state or host approximations. Scalar and Q=0 forms clear the upper half; these families preserve NZCV and QC.

Single-vector SVE non-temporal loads and stores implement all 35 June physical classes on 27 primary pages: vector-base plus X offset and contiguous scalar-base plus register or signed VL-scaled immediate offset. Vector-base forms require non-streaming mode or effective FA64; contiguous forms permit streaming execution. Active SP alignment is qualified before access. The schema models the architectural data accesses and preserves inactive/backing lanes; the non-temporal cache hint supplies no cache or timing effect.

SVE crypto covers AESE/AESD/AESMC/AESIMC, SM4E/SM4EKEY, RAX1 and byte polynomial multiply in addition to EOR3/BCAX/XAR and bit permutation. Fixed-width transformations repeat independently per 128-bit segment. Streaming AES can use SSVE_AES, RAX1 can use SME2p1, and the SM4 forms require effective FA64. Native feature admission distinguishes SVE AES, PMULL128, SHA3, SM4 and BitPerm capabilities.

Grouped SVE AES2 covers two- and four-register AESE/AESD and the combined
AESEMC/AESDIMC rounds, plus paired PMULL. Each AES key selector chooses a
128-bit segment within its 512-bit group, reducing the selector at smaller VLs.
Polynomial multiplication writes separate low-half and high-half 64×64 products
to adjacent destination vectors. All nine classes capture incoming aliased
inputs and preserve backing above CurrentVL. SSVE_AES can authorize streaming
execution without consuming SM or FA64. Splice exposes `sve-aes2`, reports the
AES2 identification level and retains each 128-bit AES operation through its
existing exact native contract, keeping grouped native graphs bounded.

A32/Thumb scalar IEEE arithmetic and comparisons support half, single and
double precision, including the fused and separately rounded multiply/add
families and signed/unsigned 32-bit integer conversions. FP16 scalar execution
requires `vfp` and `fp16`; the native CPU checks both before operands. Half
arithmetic ignores FPSCR.AHP, uses FZ16 independently of FZ and raises no
input-denormal status for half inputs. Rounding, DN, sticky exceptions and
exception enables use explicit FPSCR inputs. Status updates precede enabled
FP traps; trapping results and comparison NZCV remain uncommitted. H-register
writes zero-extend into the corresponding S register while preserving its
neighbor. This also applies to half VLDR and bitwise ABS/NEG; legacy
VCVTB/VCVTT retains its selected-half write and separate AHP qualification.

Scalar VFP rounding additionally covers VRINTA/N/P/M/R/Z/X, all signed and
unsigned VCVTA/N/P/M integer conversions, VMINNM/VMAXNM and all VSEL flag
conditions. Unconditional forms reject Thumb IT contexts before consuming
inputs. VSEL moves the selected raw bits without evaluating the other input or
FPSCR. Fixed-point conversions cover both integer sizes, every legal scale and
all three FP formats; integer results extend into their S/D container, and
fixed-to-FP uses ties-to-even independently of FPSCR.RMode. Rounding and numeric
extrema use the existing typed Arm FP primitives with explicit A32 controls.

A32 and Thumb VFP register lists cover VLDM/VSTM increment-after and
writeback decrement-before forms, VPUSH/VPOP aliases and the legacy
FLDMX/FSTMX odd-count encodings. S lists preserve the other half of each D
parent; D lists use two original 32-bit word-aligned accesses in architectural
endian order. Legacy spare words affect the start/writeback extent without
being read or written. Predication precedes address and vector dependencies.
Native list faults publish earlier completed register transfers or stores,
retain the faulting PC and suppress final base writeback. Empty, overflowing,
reserved addressing and prohibited PC-base forms remain Unsupported.

SSE/AVX shuffle and unpack recipes cover SHUFPS/PD, UNPCKH/LPS/PD,
PSHUFD/HW/LW/B, all integer PUNPCK element widths and the four EVEX
128-bit block shuffle families. Bit patterns move without FP classification,
MXCSR changes or FP exceptions. Legacy SSE preserves upper vector storage
and checks 16-byte memory alignment. VEX/EVEX clear upper storage; EVEX
applies element-sized merging or zeroing masks. Cross-lane NF memory operands
retain a complete read even under an empty mask; supported broadcasts read
one scalar. Empty masks on register forms avoid inactive source dependencies.

Packed variable shifts cover VPSLLVW/VD/VQ, VPSRLVW/VD/VQ and
VPSRAVW/VD/VQ across their VEX and EVEX forms. Counts consume the entire
unsigned element: out-of-range logical shifts produce zero and arithmetic
shifts sign-fill. EVEX VPROLD/Q, VPRORD/Q, VPROLVD/Q and VPRORVD/Q reduce
immediate or per-element counts modulo the element width. All vector widths,
source/destination aliases, merge/zero masks and upper-vector clearing retain
the architectural behavior without reading MXCSR or changing integer flags.
Their E4 memory contracts suppress inactive element accesses; broadcast reads
one scalar only when an element is active. Empty masks avoid unavailable
source values and address computation, while merge masks retain old elements.

EVEX integer mask comparisons cover the signed and unsigned VPCMPB/W/D/Q
predicates, VPCMPEQB/W/D/Q, VPCMPGTB/W/D/Q and VPTESTM/NMB/W/D/Q.
They produce complete 64-bit mask results, clear inactive and high bits, and
capture an aliased input writemask before updating its destination. All eight
comparison predicates retain signedness at each element width. Active memory
is read even for the constant TRUE and FALSE predicates; E4 masks suppress
inactive elements and broadcasts. Reserved predicate bits and zeroing or
register-broadcast decorators remain unsupported rather than receiving an
invented execution rule. Integer flags, MXCSR and vector registers are preserved.

A32 and Thumb scalar DSP recipes cover signed/unsigned parallel add, subtract
and exchanged halfword operations with canonical per-bit GE flags, byte selection,
halfword packing and rotated signed/unsigned dual-byte extension. MLS, UMAAL,
USAD8 and USADA8 capture aliased inputs before outputs; UMAAL adds the incoming
low and high words as separate unsigned accumulators. CRC32 and CRC32C cover
byte, halfword and word inputs with their respective architectural polynomials.
CRC requires the native `crc32` feature, A32 AL encoding and execution outside
Thumb IT blocks. These operations preserve NZCV and Q. Splice uses closed GE/Q flag identities,
keeps them synchronized with CPSR slices, and retains them through native lowering,
LLVM, dataflow recovery and Program Database storage. CPU version 18 adds these
canonical status identities to saved A32 states. PC operands and overlapping
UMAAL outputs remain constrained and do not produce complete recipes.

Single-vector MATCH/NMATCH, HISTCNT/HISTSEG and ADDPT/SUBPT cover eight primary encoding classes. Match searches are segment-local, while HISTCNT prefixes span the whole vector and count only active lanes. Pointer arithmetic consumes effective CPTA only for selected lanes. These families require non-streaming mode or effective FA64.

SME integer recipes include grouped SQDMULH and variable rounding shifts, grouped saturating conversions and narrowing shifts, and ZA integer dot/widening multiply accumulation. The increment covers 156 primary encoding classes with incoming-value snapshots, architectural row wrapping and preserved QC/NZCV. Streaming instructions require SM; ZA accumulation additionally requires ZA enablement.

Fixed-width BFDOT and BFMMLA select standard or enhanced BF16 arithmetic from effective FPCR.EBF. Enhanced arithmetic rounds the exact product sum to binary32 before separately rounding the accumulator addition, with FPCR rounding and defined flushing/NaN behavior. Both environments suppress FP exceptions and preserve FPSR. The existing SVE BFDOT/BFMMLA and SME BFMOPA/BFMOPS binary32-accumulator paths use the same effective environment, including lazy inactive-input/control handling. The native EBF16 extension enables FPCR bit 13 and reports the enhanced BF16 identification field. General alternative floating-point behavior and the remaining newer floating formats still require additional implementation.

Scalar FNMUL rounds a multiplication before applying FPNeg, including its AFP.AH NaN-sign rule and source-register merging. FPRCVT covers all 48 June scalar FP-register conversion encodings: signed/unsigned conversion in each direction, all five float-to-integer rounding modes, and all four allocated differing-width pairs. Integer results remain in SIMD&FP storage, merging uses the incoming destination, and FPSR/trap behavior comes from the explicit floating-point contract. Splice admits these forms with `fprcvt` and reports ID_AA64ISAR3_EL1.FPRCVT.

Classic AdvSIMD FMLAL/FMLSL and their upper-half forms cover vector and indexed
half-to-single fused accumulation. FCADD and vector/indexed FCMLA cover every
allocated size, rotation and index, including FPNeg's AH NaN-sign behavior before
the arithmetic operation. These eleven physical classes share ordered FPSR and
first-enabled-exception handling with SVE arithmetic. The three vector FMOV
immediate encoding entries (two physical classes) cover every encoded constant without reading FP control or
status. Fixed-width outputs clear the remaining active Z state and preserve
backing above CurrentVL.

Fixed-width FP sign transforms cover vector and scalar FABS/FNEG at every
allocated half/single/double size. They preserve AH NaN signs without raising
exceptions or touching FPSR. FABD performs the rounded FP subtraction before
applying FPAbs, with ordered FPSR and first-enabled-exception handling. Scalar
FABS/FNEG merge from the incoming destination, while scalar FABD merges from
its first source. All ten physical classes clear active upper Z state and
preserve backing above CurrentVL.

CMPBR implements all 36 register and immediate physical classes, including byte/halfword GPR slices, signed and unsigned relations, six-bit unsigned literals, ZR operands, and signed PC-relative offsets without changing NZCV. Reserved comparison selectors remain unsupported. BC.cond retains ordinary conditional-branch semantics with the consistency prediction hint. Splice admits these extensions with `cmpbr` (which requires `cssc`) and `hbc`, and reports their configured ID_AA64ISAR2_EL1 fields.

SVE predicate/copy additions cover RDFFR, RDFFRS, WRFFR, SETFFR, merging/zeroing
CNOT, integer immediate/register/scalar-vector CPY and floating immediate
FCPY/FDUP. These preserve backing above effective CurrentVL. FFR operations
require non-streaming mode or effective FA64. Nonmonotonic WRFFR uses explicit
replay choices for the architectural arbitrary result; it requires a consumer
that implements those choices. RDFFRS preserves its exact predicate-test flags,
and inactive copies avoid unavailable source or destination dependencies.

SVE2p1/SME2p1 quadword integer reductions cover ADDQV, SMAXQV, SMINQV,
UMAXQV, UMINQV, ANDQV, EORQV and ORQV at all four element sizes and five
vector lengths. Each output element reduces the corresponding position across
128-bit segments, with the architectural empty identity and modular sum.
Inactive source lanes are lazy, and aliased destinations observe incoming
values. The V128 write clears bits 128 through CurrentVL while preserving
backing above CurrentVL, selecting the permitted shared-accessor behavior.

Predicate rearrangements cover both PMOV directions at every legal immediate,
PSEL and FIRSTP/LASTP. PMOV packs individual predicate bits into the selected
contiguous vector bit range or expands vector bits into predicate groups.
Immediate-zero vector copies clear the other active bits; other immediates
preserve unaffected state and availability. PSEL uses the indexed W12–W15
selector modulo the active element count. FIRSTP/LASTP return the first/last
intersection index, or all ones when empty, and discard XZR writes. These
eleven physical classes preserve inactive backing and flags. Splice exposes
`sve2p2` admission and its identification field for the predicate-index forms.

Segment-local quadword permutations cover TBLQ/TBXQ, DUPQ, EXTQ, merging and
zeroing REVD, ZIPQ1/ZIPQ2 and UZPQ1/UZPQ2. All ten physical classes cover every
legal size and immediate at all five vector lengths. Table indices are unsigned
and confined to their 128-bit segment; out-of-range table reads and unused TBXQ
fallback inputs remain lazy. Destructive aliases capture incoming state, and
writes preserve backing above CurrentVL.

SVE pair arithmetic covers segment-local ADDQP, interleaved ADDSUBP, signed and
unsigned paired absolute-difference accumulation SABAL/UABAL, predicated SUBP,
and both SQCADD rotations. SABAL/UABAL sum the absolute differences of both
half-width source elements before accumulating modulo the destination width.
SQCADD clamps signed sums and differences without updating FPSR.QC, as specified
by its SignedSat operation. Splice admits the five newer pair families with
`sve2p3` or `sme2p3` and reports the corresponding configured ID fields.

EXPAND fills active destination elements from the sequential source prefix
across the whole vector and zeros inactive elements. All four element sizes
and five vector lengths retain source/destination aliases, preserved backing
above CurrentVL and lazy unused source chunks. In streaming mode the recipe
requires effective FA64 or SME2p2; non-streaming execution consumes neither
effective capability. Source selection is bounded by the number of preceding
destination elements, keeping the largest native graph within its existing
expression limit.

WHILE predicate-pair comparisons cover all eight signed/unsigned ascending and
descending relations. Comparisons retain their sticky termination behavior and
64-bit wrap rules across both output predicates; NZCV describes the complete
pair. WHILERW and WHILEWR separately implement absolute and directed address
distance, including full predicates when the element-scaled quotient is zero.
These ten classes use X64 operands with XZR semantics, clear predicate padding,
preserve backing above CurrentPL and require only standard SVE access context.

Predicate-as-counter PTRUE PN, all eight WHILE PN relations, one/two-predicate PEXT and counter CNTP use the existing predicate storage. PN aliases P's low 16 bits. The twelve primary classes retain count-tag precision, inversion, sticky comparison/wrap behavior, predicate aliases and MAX_PL zero-extension. Non-streaming execution requires the effective SVE2p1 capability; otherwise streaming mode is required.

Indexed SVE MUL/MLA/MLS cover all nine halfword, word and doubleword classes.
The selected multiplier repeats within each 128-bit segment; products and
accumulation wrap at the element width without changing QC or NZCV. Plain MUL
and both MOVPRFX policies cover every allocated element size, suppress inactive
inputs and preserve backing above CurrentVL. CTERMEQ/CTERMNE use W/X views and
ZR semantics, update N/V and preserve Z/C. FTSSEL implements all half/single/double
selectors, including the AH NaN-sign rule, without reading FPCR or the first
source on paths that do not need them.

Unsigned integer URECPE/URSQRTE implement merging and zeroing SVE word forms
with the architectural integer estimate algorithms. FRINT32X/Z and FRINT64X/Z
cover both predicate policies and both floating formats. Bounded rounding uses
explicit FPCR/FPSR state, returns the architectural indefinite value for invalid
inputs and suppresses later lanes after the first enabled exception. Empty
predicates consume no floating input or FPCR.

SVE replicate loads cover all 32 scalar, quadword and octaword physical classes.
Scalar LD1R and sign-extending LD1RS forms perform one original-width memory
access when any destination predicate element is active. LD1RQ/LD1RO read only
the masked low 128/256-bit block in element order, then repeat that block across
CurrentVL; predicate bits outside the source block do not enable accesses or
change repeated results. Signed immediate and scaled-register addresses wrap at
64 bits, both byte orders are preserved, empty masks suppress address inputs,
and faults produce no partially published transition. Octaword replication
requires VL at least 256 and non-streaming mode or effective FA64. Active
misaligned SP retains the explicit alignment-policy limitation.

Fixed AdvSIMD LUTI2/LUTI4 cover all four encoding forms, every part of the
packed byte/halfword indices, and the wrapped pair of 128-bit halfword tables.
They read incoming operands before publication, including all aliases, clear the
active vector state above 128 bits, and preserve the backing state above CurrentVL.
Their lookup does not depend on scalable streaming controls or floating-point state.

SME LUTI2/LUTI4/LUTI6 cover all seventeen physical table-lookup classes,
including consecutive and strided destinations, modulo segment selection,
LUTv2 pairs of index vectors, three-vector byte indices, and LUTI6's two
512-bit halfword tables with wrapped source registers. Index extraction crosses
CurrentSVL register boundaries and 64-bit chunk boundaries. ZT0 LUTI2/LUTI4 use
32-bit table entries for every output size; LUTI6 uses byte entries. Table forms
require streaming mode and enabled ZA; vector-table LUTI6 requires streaming
mode and SVL at least 512. Writes preserve backing chunks above CurrentSVL.
Splice exposes SME_LUTv2 admission and its SMFR0 identification bit alongside
SME2p3's LUT6 identification bit.

Packed LUTI2/LUTI4/LUTI6 cover all seven physical classes and every part selector.
Indices span the whole vector, and tables start at the bottom of one or two
source registers, with register-number wrapping. The one-register halfword
LUTI4 and byte LUTI6 require VL at least 256; halfword LUTI6 requires at least
512. LUTI2/4 streaming access uses effective SME2 or FA64 context, while LUTI6
retains each encoding's access rule. The native `lut` feature and identification
field distinguish the implemented table extension. MADPT/MLAPT retain separate
effective CPTA/CPTM controls, signed product overflow and pointer error marking;
controls and source chunks are read only when the selected result needs them.
Splice adapter version 7 adds the effective SME2 context bank and migrates older
states from their saved feature configuration, preserving existing storage and
availability.

Grouped LD1/ST1/LDNT1/STNT1 implement all 128 physical classes across 64
primary pages: two/four-register contiguous and strided lists, B/H/W/D widths,
and scalar register or signed VL-scaled immediate offsets. Contiguous lists
permit non-streaming SVE2.1 or streaming SME2; strided lists require streaming
SME2. Both use effective CurrentVL independently of saved SVL. Counter predicates
retain all size tags, count truncation and inversion. Empty masks suppress SP,
address and store-value dependencies; active SP accesses retain alignment
qualification. Loads select the permitted SVEZEROUPPER behavior. Original-width
memory events remain ordered by register then element; cache hints do not add
atomicity or timing effects.

Ordinary structured SVE LD2/LD3/LD4 and ST2/ST3/ST4 implement all sixty B/H/W/D/Q classes, including register and signed-immediate offsets. Vector groups wrap modulo 32, and memory events remain in element-then-member order. Q elements retain one 128-bit event per member. Inactive accesses are suppressed, inactive load elements are zero, and supplied VL is effective CurrentVL in either execution mode.

PAuth recipes retain typed operation/key/modifier inputs, including PACGA's distinct generic key, PAC2 second modifiers, authenticated control flow and endian-aware authenticated loads. Consumers supply the compatible PAC algorithm, address configuration and effective context. Native Splice currently implements QARMA5 with explicit keys; unsupported FPAC/PAuth2/system domains remain explicit.

x86 stack and branch dispatch also checks physical opcode/map/group identity:
far CALL/JMP/RET cannot inherit a near recipe from a shared mnemonic. Genuine
source stack SP/memory/IP metadata is recognized only on the audited near
families, while extra or unknown hidden state is rejected. NOP recipes are
bounded to opcode 90 and 0F 1F /0; other hint/extension forms spelled NOP by the
source catalog remain Unsupported.

PAUSE and PREFETCHNTA/T0/T1/T2/PREFETCHW have separate physically bounded hint
recipes. They select the permitted zero-delay/ignored-cache-hint behavior and
consume no register, flag, segment-base or memory input. LOCK forms are rejected.
These choices model architectural execution; they do not model cache residency,
power consumption or elapsed cycles. PREFETCHWT1 and the separate vector
prefetch families remain outside this increment.

A Full recipe makes its modeled arithmetic, memory, control and native effects
explicit. Ordinary memory accesses use the consumer's page, segment, alignment
and fault policy. Interrupts, timing and MMIO behavior are not inferred from
ordinary reads and writes. Both Arm generators expose an explicit data-endian
API independent of instruction-byte decoding; existing entry points default to
little endian. A64 also accepts `RecipeContext { endian, vector_length,
streaming_vector_length }` through `semantic_recipe_with_context`.
`vector_length` is effective CurrentVL for SVE. The optional streaming length is
SVL for SME, including instructions that access streaming state outside streaming
mode; `None` uses `vector_length`. Both lengths must be 128, 256, 512, 1024 or
2048 bits. The default is 128. Ordinary V-register writes clear their
active upper Z-register chunks at larger lengths.
A32 predication reads NZCV; Thumb additionally reads and advances `a32.itstate`.
A32/T32 PLD, PLDW and PLI use the target's ignored prefetch-hint behavior.
Their recipes retire without computing an address or reading base, offset,
shift-carry or memory inputs. Physical encodings, literal redirects and
constrained register exclusions are retained; Thumb still conditions execution
on ITSTATE and advances the IT pipeline even when its condition is false.
x86 GPR parents are represented as
64 bits in every execution mode; 16/32-bit-mode operations preserve bits above
their architectural slice, and long-mode 32-bit destination writes zero bits
63:32. Consumers whose register file ends at EAX can truncate that parent.

## Schema and consumer contract

`Expr { ty: Type { width, signedness }, kind }` is a typed bitvector expression
for widths 1 through 64. `ExprKind` includes constants, register slices,
backward-referencing temporaries, explicitly undefined values, unary/binary
operations, sign/zero extension or truncation, extraction, selection, scalar
loads, carry/borrow and signed overflow. Arithmetic wraps at the result width.
Shift counts are explicit expressions: architecture masking is present in the
recipe rather than hidden in a host language shift. Comparison outputs have
width one. `Memory` carries address expression, width in **bits**, and endian.

`Register { bank, index }` identifies architectural storage.
`RegisterSlice { register, offset, width, parent_width }` identifies a view.

`IndexedRegister { bank, base, stride, count, index, offset, width, parent_width }`
selects one scalar chunk from a finite architectural register bank. The selected
register number is `base + UInt(index) * stride`; selection never wraps, and an
unknown or out-of-range index fails. Reads use incoming state, and write
selectors must be captured before applying architectural effects. The current
SME2 BFDOT helpers use this for selected ZA rows, so accesses and graph size grow
with the selected group rather than every possible row. A native consumer must
retain `count`, the bank identity and the scalar chunk boundary; replacing the
selection with a guest-memory address changes the contract. Splice maps this
bank to bounded `RegisterFamily::AArch64Za` slices.
`Effect::WriteRegister { destination, policy, value }` distinguishes preserving
untouched bits from zeroing the parent above a destination slice.
`Effect::WriteRegisterConditional` tests its one-bit incoming-state condition
before evaluating the value or reading untouched destination bits. A false
condition emits no write and requires neither input; inactive graphs still
receive complete structural validation. Values and conditions are captured
before architectural publication, while preserving writes merge earlier pending
writes to the same parent. This permits legacy VFP to update only the selected
lanes without requiring unrelated destination registers to be available.
`Effect::Store { memory, value }` describes an ordinary scalar write.
`Effect::StoreConditional` first tests its one-bit condition and suppresses both
address and value evaluation when false. It emits no access or ordered event on
that path; every inactive expression still participates in graph validation.
`Effect::StoreWideConditional` applies the same lazy condition to one original-width wide store.
`Effect::Trap` terminates later outputs when its condition holds. Status writes
which architecturally precede an FP trap appear before that trap. Standalone
barriers and exclusive-monitor clears retain typed ordered effects.
`Effect::Wait` retains a closed environment boundary with fallthrough and an
optional Protection-trap outcome. `Effect::SendEvent` retains local or all-PE
event delivery. Their callbacks plan and acknowledge the boundary; the ordered
transition records it for commit. Consumers without these capabilities reject
them, and a wait callback cannot choose a trap outside its declared domain.
`ControlFlow { kind, condition, target, fallthrough }` makes control transfers
explicit, including a fallthrough edge. `Recipe::guard` supplies predication.

| Register bank | Index meaning |
| --- | --- |
| `a64.gpr` | X0–X30, with W views expressed as width 32 and zero-upper writes |
| `a64.sp` | index 0 is SP; ZR reads are constants and its writes are discarded |
| `a64.nzcv`, `a32.nzcv` | N=0, Z=1, C=2, V=3, each a separate one-bit parent |
| `a32.gpr` | R0–R14; PC reads are address+8 constants, and unsupported PC writes never become guessed GPR15 writes |
| `a32.itstate`, `a32.thumb_state` | index 0: eight-bit ITSTATE and one-bit instruction-set state |
| `a32.vector64` | D0–D31, each a 64-bit parent; S registers are half slices and Q registers use adjacent D pairs |
| `a64.vector64` | register number × 32 + 64-bit chunk; V registers occupy the first two chunks of their Z register |
| `a64.predicate64` | predicate number × 4 + 64-bit chunk; predicate16 is FFR, with one active predicate bit per vector byte |
| `a64.za64` | physical ZA row × 32 + 64-bit chunk; 256 distinct rows, each with 2048-bit maximum backing |
| `a64.svcr`, `a64.fpmr` | index 0; SM/ZA mode bits and floating mode state |
| `a64.zt064` | eight 64-bit chunks of ZT0 |
| `a64.sme_fa64`, `a64.ssve_fexpa`, `a64.ssve_bitperm`, `a64.ssve_aes`, `a64.sme2`, `a64.sme2p1`, `a64.sme2p2`, `a64.sve2p1` | index 0, one-bit effective streaming capabilities supplied by architectural context |
| `a64.pauth_present`, `a64.pauth_lr_present` | index 0, one-bit implemented PAuth and PAuth_LR capabilities; HINT encodings are lazy NOPs when absent |
| `a64.pac_key_enabled` | IA=0, IB=1, DA=2, DB=3; one-bit effective EL0 key enables |
| `a64.pacm`, `a64.pacm_enabled` | index 0, one-bit PSTATE.PACM and its separate effective privileged enable; feature presence does not establish enablement |
| `a64.dit`, `a64.tco`, `a64.tpidr_el0`, `a64.tpidrro_el0` | index 0; one-bit DIT/TCO and 64-bit thread pointers |
| `a64.dczid_el0`, `a64.dc_zva_permitted` | index 0; 64-bit target DCZID image and one-bit effective Normal-memory/tag/trap qualification for DC ZVA |
| `a64.cpta`, `a64.cptm` | index 0, separate one-bit effective pointer-add and signed-multiply-overflow checking controls |
| `a64.mte_enabled`, `a64.tag_exclude` | index 0, one-bit effective allocation-tag access and 16-bit excluded-tag mask for pointer arithmetic |
| `x86.vector64` | vector register number × 8 + 64-bit chunk |
| `a64.fpcr`, `a64.fpsr`, `a32.fpscr`, `x86.mxcsr` | index 0, explicit 32-bit architectural FP control/status |
| `a64.fpcr_write_mask`, `a32.fpscr_write_mask` | index 0, 32-bit target writable masks for architectural FP control writes |
| `x86.gpr` | RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7, R8–R15=8–15; AH is GPR0 offset8, not GPR4 |
| `x86.flags` | CF=0, PF=1, AF=2, ZF=3, SF=4, OF=5, DF=6, separate one-bit parents |
| `x86.mask` | K0–K7, 64-bit parents |
| `x86.segment_base` | segment number, 64-bit linear base; includes implicit DS/SS in legacy modes |
| `x86.x87` | logical ST register × 2 + chunk; low64 followed by high16 |
| `x86.x87_control`, `x86.x87_status`, `x86.x87_tags` | index 0, coupled x87 control/status/full tag words |
| `x86.mxcsr_mask` | index 0, 32-bit target writable mask for FXRSTOR validation |

FP control reads use the architectural read image, including zero in RES0
positions. MSR FPCR and VMSR FPSCR read their target's explicit writable-mask
bank, replace writable bits and preserve the remaining incoming read image.
This includes implementation-dependent exception-enable writability and
feature-dependent fields. The qualified system helper entry points also accept
a constant mask. A consumer must supply the selected implementation's mask;
an absent mask is an unavailable input, rather than permission to guess one.

All register and memory reads refer to the immutable incoming state. Bind
`Recipe::temporaries` in vector order, checking that references point backwards,
then capture every write value, memory address and control target **before**
applying effects. This handles source/destination aliasing, memory RMW,
writeback, XCHG, PUSH RSP and BLR X30/CALL target capture. Writes may share a
parent; apply their write policies in effect order, using the previously pending
parent value for untouched bits. Never re-read an already-updated register to
lower another expression. A false guard suppresses ordinary outputs and memory
accesses, while `write_always` pipeline updates still execute. Such updates may
read incoming state but cannot reference predicated temporaries. Selection is
lazy: loads and undefined-value choices in an unselected arm do not execute.

A translator to another IR needs recursive expression lowering, architectural
register mapping, ordered bindings and native effects, and control flow. Call
`Recipe::validate` before reading state or lowering; it checks inactive branches,
forward references, widths, slices and effect contracts as well as active paths.
No Splice or other
consumer dependency is present in generated crates. `AddCarry` and `SubBorrow`
are unsigned carry-out and borrow-out; A64/A32 subtraction C is the inverse
borrow. `Overflow` uses original input signs and the final width-truncated
result, including carry-in/borrow-in. Undefined flags are first-class expressions
and must lower to the target IR's unknown/undefined value, not a defined zero.
For example, x86 logical AF and multi-bit shift OF remain explicitly undefined.
XOR of an identical register slice defines zero without reading its incoming
value, including when that input is unknown. Different slices such as AL and AH
retain their input dependencies; narrow writes still preserve unaffected bits.
The rotate recipe distinguishes the masked count from its modulo-width count:
a byte rotate by eight retains its value but updates CF and leaves OF undefined,
as specified by the [Intel instruction reference](https://cdrdv2-public.intel.com/835757/325383-sdm-vol-2abcd.pdf).

## Evaluator and validation

`Machine` supplies immutable register reads and scalar memory reads. Typed FP
expressions carry operation, format, architecture, explicit control/status and
value/status/trap projection. `Machine::evaluate_float` must use an architectural
FP engine; the default rejects the capability, and host ambient FP is never an
implicit fallback. Splice lowers these expressions to its software FP contracts. Mixed-width widening
fused operations preserve the binary32 addend and two binary16 operands until
one final rounding. Typed x87 expressions retain full 80-bit payloads and
coupled control/status/tag projections; `Machine::evaluate_x87` must provide
the selected operation or return an explicit capability/result error.

For Splice's synchronous Arm FP contract, the status projection accumulates
exceptions in operation order and stops before the first enabled class. Earlier
operations and SIMD lanes retain their cumulative flags. An enabled class does
not set its own cumulative bit; later exceptions do not execute. Flush-to-zero
can set UFC directly even with UFE enabled, and this status survives a later
lane's trap. The typed FP engine and generated Scale/LogB expression algebra
follow the same publication contract.

Original-width ordinary accesses use `WideMemory` for byte-multiple widths from
72 through 2048 bits. Ordered scalar reads use `load_ordered` or
`load_ordered_conditional`, retaining their original 8–64-bit access in the same
read stream; this supports the precise x87/FX restore read and validation order. `load_wide` returns low-to-high numeric scalar chunks from
one `Machine::read_wide_memory` callback; `store_wide` emits one pending wide
write and one ordered event. A consumer must preserve the original access width
and fault span instead of replacing it with independent chunk accesses. This
contract does not imply atomicity. Unsupported backends reject the capability.
`load_wide_conditional` additionally suppresses the address and complete read
when its incoming-state condition is false, leaving its result chunks
unavailable. `bind_before_reads` captures reusable pure incoming-state values in
the `pre_read_bindings` prefix of the ordinary temporary array. These bindings
may reference earlier prefix entries and explicit choices, and cannot perform
memory reads or consume ordered read/atomic outputs. Ordered reads follow that
prefix and may reference it and earlier read results. Remaining scalar bindings
follow the read stream. Arm pair register order is selected before lowering according to
the original element width and data endianness.

`try_load_ordered` appends one scalar 8/16/32/64-bit attempt to that same read
stream and returns correlated value/success expressions. Only explicitly listed
`MemoryFaultKind` classes recover: a classified architectural fault produces
zero data and success zero. Success produces the original data and success one.
A false predicate consumes neither address nor memory and leaves both outputs
unavailable. Generic `EvalError::Memory`, unsupported capabilities and backend
errors propagate. The recovery list is nonempty, unique and in enum order.
`Machine::try_read_memory` is a separate explicit capability with an unsupported
default; an ordinary read is never substituted. Device-memory suppression must
occur before any external transaction. Splice's native `Statement::TryLoad`
preserves the attempt and its two result projections, checks the recovery list
against the exact access fault contract, and executes against its Normal-memory
page model. Unsupported LLVM/SSA/replay consumers reject this behavior explicitly.

LSE128 SWPP, LDCLRP and LDSETP cover all twelve acquire/release encodings.
Each recipe issues one indivisible 128-bit read-modify-write and returns both
old 64-bit chunks. Rt and Rt2 are independent registers; endian conversion
selects their architectural order before lowering. LDCLRP complements both
incoming chunks, and LDSETP ORs them. XZR operands are reserved. For equal
operand registers, the implementation selects the architecture's permitted
NOP outcome, without a memory access or SP alignment check. Other forms check
SP alignment before issuing the transaction. Splice admits these forms with
`lse128` (requiring `lse`) and reports Atomic=3 in ID_AA64ISAR0_EL1.

The pair RMW contract has closed Exchange, And and Or operations. Evaluation
requires a native pair callback, validates both observed chunks and forwards
pending transactions to subsequent observations. It never splits a transaction
into scalar atomics or ordinary memory accesses. Lowering retains one native
128-bit atomic statement; the execution engine applies it to the full value,
and LLVM emits one i128 atomicrmw when the target's byte order matches.
Backends without this capability reject it explicitly.

Native atomic operations carry ordering, scope, endian and typed result
projections. Their immutable planning callback returns an observation and commit
witness; pending atomic writes and exclusive-monitor outcomes remain separate
from ordinary memory writes. A backend must validate or reserve that observation
when committing the architectural transition. It must reject unsupported
capabilities rather than emulate atomic access with an ordinary load/store pair.

`evaluate(&recipe, &machine)` returns a pending `Transition` containing full
parent-register writes, memory and atomic writes, ordered native events,
trap outcome and `next_pc`; it mutates no state. A trap outcome takes precedence
over the ordinary next PC and suppresses later outputs and pipeline updates.
The caller can validate and apply the pending transition. Memory lookup failure,
unknown address/control conditions, invalid widths/slices/temporary references,
and unsupported recipes return an error. `Value { bits, defined, width }` tracks
defined bits independently. Arithmetic with unknown inputs conservatively
returns unknown output; casts and preserving writes retain individual known
bits. This evaluator is a reference/testing aid, not a full CPU emulator.

Run the owning tests with:

```sh
go test ./pkg/semantics ./pkg/arm ./pkg/x86 -run 'TestRustScalarEvaluator|TestRustA64ScalarRecipes|TestRustA32ScalarRecipes|TestRustX86ScalarRecipes' -count=1
```

The tests compile generated Rust and execute real decoded instruction words or
bytes against independently specified machine-state outcomes. They cover
carry/borrow/overflow (exhaustive eight-bit inputs and both carry states), zero
and masked shifts, undefined flags, source/destination aliases, high-byte and
zero-upper writes, SP/ZR, conditional control flow, target capture, scalar memory
addresses, pre/post-index writeback and explicit unsupported system/vector/atomic
operations. These checks qualify the listed bounded families; they do not claim
complete ISA semantics or automatic proof of every catalog encoding.

The SME base integer category includes ADDHA/ADDVA for 32- and 64-bit
elements and ADDSPL/ADDSVL/RDSVL. Tile additions use independent row/column
predicates and preserve other tiles and storage outside active SVL; they
require both streaming mode and ZA enabled. Scalar length arithmetic uses
saved streaming length even while non-streaming, supports every signed
immediate, treats SP according to the instruction, and discards RDSVL to XZR.
The 64-bit tile additions require FEAT_SME_I16I64 at native admission.

Splice's basic FP arithmetic consumer accepts AH/FIZ for FADD, FSUB, FMUL and
FDIV (and FABD's subtract/absolute sequence), with independent half precision
FZ16. AH selects the first of two NaNs, preserves its sign through absolute
value, uses a negative default NaN, reports unflushed denormal inputs only after
non-NaN arithmetic, and tests underflow after rounding with an unconstrained
exponent at the destination precision. FIZ suppresses input denormal exceptions;
AH output flushing raises UFC/IXC without trapping underflow. Other native FP
contracts continue to reject alternative controls until their particular rules
are implemented; this does not claim complete AFP instruction coverage.
The native `afp` profile enables writable AH/FIZ/NEP and reports AFP in
ID_AA64MMFR1_EL1. These are configuration-dependent controls on existing
instructions; the profile does not supply a semantic fallback for other FP
contracts. Profiles without `afp` retain read-as-zero/write-ignored AFP bits.

A64 exclusive loads and conditional stores cover all 24 physical classes in
LDXR/LDAXR, STXR/STLXR and LDXP/LDAXP, STXP/STLXP, including byte and
halfword scalar forms. W-pair loads remain one 64-bit observation. Default
X-pair loads use `LoadLinkedPairSplit`: two independently atomic 64-bit reads
and one 128-bit reservation. `Machine::evaluate_exclusive_pair` supplies the
numeric chunks, both address-ordered read witnesses and a reservation token
which detects interference anywhere in that reservation, including between
reads. Conditional stores retain one indivisible write and may fail
spuriously. A provider with an applicable pair single-copy guarantee can still
select `AtomicContext::exclusive_pair_atomic` explicitly.

The native `MemoryAccess::atomic_element_width` preserves split observation
granularity independently of the reservation width. Validation confines it to
128-bit load-linked accesses with 64-bit elements; canonical identity,
persistence, SSA and rendered qualifiers retain it. The software executor
performs two reads and sets one complete reservation, invalidates that
reservation on overlapping writes to either half, and checkpoints it intact.
LLVM rejects this access without a target reservation runtime instead of
substituting an indivisible helper. Duplicate load destinations and overlapping
store-status operands select the architecture's permitted decode NOP before
SP checks, source reads, memory access or monitor changes. Effective SP
alignment enforcement is an explicit input shared with ordered memory.

A64 LRCPC, LRCPC2, LRCPC3 and LSCP ordered-memory recipes cover all 42 physical
encoding entries in the 21 June 2026 primary pages: LDAPR/LDAPRB/LDAPRH,
LDAPUR and signed variants, STLUR, the SIMD unscaled forms, LDAP1/STL1 D lanes,
LDIAPP/STILP pairs, and LDAP/LDAPP/STLP pairs. Acquire-RCpc remains a distinct, load-only ordering in
the recipe, native statements, canonical encoding, verification projections,
rendered operations and stored records. LLVM currently returns an explicit
unsupported result for this ordering; substituting ordinary acquire changes
its architectural contract.

Scalar and SIMD addresses retain byte offsets, SP checks and source snapshots.
Loads to ZR still perform the ordered access. Signed loads extend to the encoded
32- or 64-bit destination. SIMD whole-register loads clear upper bits; lane
loads preserve the other D lane and clear Zn above bit 127. Post-index loads
choose the architecture's permitted writeback-suppression behavior on base
aliasing, and duplicate pair load destinations choose the permitted NOP before
checking SP or accessing memory. Pre-index STILP stores the higher-addressed
element first and captures sources before updating the base.

The default ordered-pair recipe profile does not advertise FEAT_LSE2. It retains
two element accesses with independent atomic observations. A caller that has an
applicable single-copy guarantee can explicitly request
`arm64_ordered::a64_with_pair_atomicity`; that profile emits one 64- or 128-bit
transaction. This guarantee is not inferred from LRCPC3 or host atomic support.
The 128-bit SIMD forms always retain the primary's two 64-bit accesses.
Misaligned ordered accesses need alignment-control context and reject before
access in its absence. Translation, permissions, device-memory and tag checks
remain with the consumer's memory environment. SP alignment checks use the
explicit effective `a64.sp_alignment_enforced` control. LSCP admission is
independent of LRCPC. LDAP uses acquire, LDAPP uses acquire-RCpc, and STLP uses
release. Either ZR load destination suppresses LSCP acquire ordering without
suppressing the access; LDIAPP retains its acquire-RCpc ordering. LSCP has no
offset or writeback, and follows the same explicit pair-atomicity contract.

The fixed AdvSIMD FP8 conversions cover F1CVTL/F2CVTL, BF1CVTL/BF2CVTL
and both FCVTN half/single-source classes, including both Q forms. Recipes
carry the operand, FPMR, FPCR and FPSR explicitly. Widening selects F8S1/LSCALE
or F8S2/LSCALE2; narrowing selects F8D/NSCALE/OSC. The native integer
significand evaluator implements E5M2 and E4M3, gradual underflow, ties to
even, finite saturation, unsupported-format Invalid, default NaNs, AHP input
and AFP AH behavior. FPCR rounding and flushing controls ignored by these
instructions stay ignored. Source operands are captured before destination
writes, FCVTN2 preserves the low D lane, and fixed V writes clear active upper
Z state. Ordered exception projections stop at the first enabled exception
and preserve destination state on a trap. The `fp8` execution profile reports
both formats and conversion support in ID_AA64FPFR0_EL1; separate FP8
arithmetic capability fields remain clear. The scalable conversion category covers all 22 encoding classes in the fourteen
SVE/SME primary pages: low/top byte widening, BF16 widening, interleaved or
contiguous pairs, half/single narrowing, four-register groups and top-byte
narrowing that preserves every even destination byte. SVE forms use CurrentVL;
SME-only groups use SVL. Registers outside the active length remain untouched.
Streaming admission follows SME2, and FP exception enables are suppressed when
streaming full A64 is disabled, while cumulative status still accrues. FPMR
survives executor checkpoints. FP8 arithmetic families remain separate work.


BF16 widening multiply/accumulate covers all 26 June 2026 physical encoding
entries across fixed SIMD BFMLAL (vector/indexed, both source parts), SVE
BFMLALB/BFMLALT/BFMLSLB/BFMLSLT (vector/indexed), and SME2 ZA BFMLAL/BFMLSL
(single, VGx2 and VGx4 vector, indexed and group forms). BF16 operands expand
exactly into binary32 and the product and accumulator round once. This uses a
separate native contract from BF16 dot arithmetic: FPCR.EBF does not select
BFMLAL arithmetic, and FZ16/AHP do not reinterpret its BF16 inputs.

Ordinary forms carry ordered FPSR/trap projections. AFP.AH forces RNE and
input/output flushing for non-ZA BFMLAL/BFMLSL and suppresses exceptions; its
NaN source priority and BFNeg behavior remain explicit. ZA forms instead use
FPMulAdd_ZA: exceptions suppressed, no FPSR dependency or write, default NaN forced, and the supplied
rounding/flush controls retained. SVE forms suppress exception enables in
streaming mode without SME_FA64. SME forms require SM and ZA, use saved SVL,
and select stride-separated pairs of physical ZA rows using the low W8..W11
value, offset, modulo and pair alignment in the primary operation order.
Sources and accumulators are captured before publication; fixed writes clear
active upper Z, while scalable/ZA writes preserve backing beyond the active
length. Persistence, LLVM runtime contracts, execution and decompiler recovery
all retain the dedicated BF16 widening operation and its ZA distinction.


FP8 widening fused multiply/accumulate covers all 28 physical entries in the
18 SVE and SME primary pages: FMLALB/FMLALT and FMLALLBB/BT/TB/TT, with vector
and indexed operands, plus half/single ZA accumulators with single, VGx2 and
VGx4 sources. Independent F8S1/F8S2 formats and LSCALE come from saved FPMR.
Products and accumulators round once to IEEE binary16/binary32, using RNE,
gradual underflow, forced default NaNs and suppressed exceptions. OSM clamps
finite overflow; input infinities remain infinite. AH selects the default NaN
sign. FPCR rounding/flushing/AHP and FPMR narrowing controls stay ignored.
The native evaluator uses software arithmetic; half results retain the exact
sum in binary128 before their sole half rounding. No FPSR reads or writes are
introduced by the recipes.

SVE admission selects the saved non-streaming FP8FMA or streaming SSVE_FP8FMA
capability before operand reads. SME half/single forms require SME_F8F16 or
SME_F8F32, SM and ZA, and use SVL independently of CurrentVL. Indexed source
bytes repeat within 128-bit segments; ZA destinations retain pair/quad row
alignment and stride-separated register groups. All operands are captured
before writes, including overlapping indexed sources. Checkpoint version 8
adds missing FMA capability bits while preserving saved values and availability.
ID registers, stored exact intrinsics, LLVM runtime calls and decompiler recovery
retain the same arithmetic contract. FP8 dot and matrix operations are separate
families and are not implemented by this widening-FMA category.


FP8 dot recipes cover all 19 physical entries across SVE FDOT 2/4-way
(vector/indexed) and SME FDOT/FVDOT (half/single ZA, VGx2/VGx4, vector,
indexed and group layouts). FVDOT interleaves two source registers and retains
its bottom/top indexed half selection. ZA row bases use the unaligned scalar
offset modulo group stride; these dot layouts do not apply FMLAL pair/quad
alignment. SVE CurrentVL and SME SVL remain independent.

A dedicated exact dot operation carries packed byte sources, the accumulator
and FPMR. Its native evaluator sums signed integer significands on the binary32
2^-149 lattice before one ties-even rounding. This preserves cancellation,
midpoint sticky bits and widely separated source/accumulator exponents without
intermediate host or binary128 rounding. Formats, scale, saturation, default
NaNs and suppressed exceptions match FP8DotAddFP. Saved mode-specific DOT2
and DOT4 capability bits govern SVE admission and their ID register fields;
checkpoint version 9 adds missing fields without overwriting saved state.
Matrix multiply and outer-product FP8 instructions remain separate families.


FP8 matrix recipes cover all 16 physical entries in the ten FMMLA, FMOPA,
FMOP4A and FTMOPA primary pages. Fixed and SVE matrix multiplication retain
2x2 accumulator ordering with exact four/eight-way dot products. SVE FMMLA
requires non-streaming mode; fixed FMMLA admits streaming only with SME_FA64
and clears active upper Z state. SME outer products use SVL and physical tile
rows, preserve other tiles and inactive backing, and require SM and ZA.

Predicated FMOPA zeros each independently inactive source byte and skips an
accumulator only when no corresponding pair is active. This preserves the
specified zero-times-infinity behavior when another pair is active. MOP4
selects its two source groups by opposite half-vector coordinates. FTMOPA
selects the first two control-selected bytes across the two sources for half
results, or independently per source for single results; control indices span
all four SVL/4 segments. All source and accumulator reads precede publication.
The matrix profiles expose F8F16MM/F8F32MM and SME_MOP4/SME_TMOP independently;
storage, LLVM, native execution and recovery use the same exact FP8 dot
contract, explicit FPMR controls and suppressed exception projections.


Non-widening ZA addition/subtraction covers every BFADD/BFSUB/FADD/FSUB
entry in the June 2026 primary pages: two/four-register groups, BF16 and
IEEE FP16/32/64, all saved streaming lengths, W8-W11 selectors and row
wraps. Recipes preserve unselected rows and backing, require SM+ZA before
operand reads, capture incoming operands and use an explicit ZA binary
contract. The consumer forces default NaNs, retains AFP/rounding/flush
controls and suppresses all exception accrual/traps without an FPSR read.
FP16 admission accepts either SME_F16F16 or SME_F8F16; BF16 and FP64 retain
their independent extension requirements and identification bits.


Non-widening ZA FMLA/FMLS/BFMLA/BFMLS includes all 40 encoding entries
(48 width/group variants), indexed sources in every 128-bit segment,
single-source register wrapping and aligned two/four-register groups.
Exact BF16 and IEEE FP16/32/64 fused arithmetic rounds once, forces default
NaNs and suppresses exceptions. Saved SVL, selector row wrapping, source
capture and untouched ZA backing follow the same explicit contracts as
ZA binary arithmetic. Fused FP16 requires SME_F16F16 independently of
SME_F8F16. AFP input flushing, output flushing and unconstrained-exponent
tininess are retained separately in the BF16 numerical engine.


Classic predicated ZA outer products cover all ten FMOPA/FMOPS/BFMOPA/BFMOPS
entries. IEEE FP16/32/64 and BF16 non-widening products use the explicit ZA
fused contract; BF16-to-FP32 outer products retain architectural two-product
dot behavior (including effective FPCR.EBF). Independent row/column predicate
elements zero individual dot sources and suppress the entire operation only
when no corresponding pair is active. Tile interleaving, saved SVL, inactive
accumulators, other tiles and backing are preserved.

The same outer-product category includes the two widening FP16-to-FP32
FMOPA/FMOPS entries. Their exact half products feed one rounded FP32 dot,
then a separately rounded accumulator add. FZ16 controls source flushing;
AHP is ignored, AFP controls the FP32 stages, DN is forced and exceptions
are suppressed. The replaced generic floating outer-product paths are
removed from the SME runtime; direct runtime callers use the same contracts.


SME2 FP16 widening ZA FMLAL/FMLSL covers all 16 physical entries: indexed,
single-vector and grouped two/four-vector sources. Exact half expansion
honors FZ16 separately from FP32 accumulator FZ/FIZ and ignores AHP for
arithmetic. The resulting FP32 fused operation rounds once, forces default
NaNs and suppresses exceptions. Indexed lanes repeat per 128-bit segment;
selectors align to double rows after wrapping and grouped single-vector
sources wrap at Z31. Tests preserve all unselected ZA rows and backing
outside saved SVL, with CurrentVL chosen independently.


The ZA half-dot category covers all six FDOT entries and both FP16/BF16
vertical dot entries. Ordinary dot groups consume adjacent half pairs;
vertical dot consumes the same parity lane from two adjacent source Z
registers for the two stride-separated destination rows. Indexed pairs
repeat per 128-bit segment. FP16 retains separate dot and accumulator
rounding; BF16 retains standard/enhanced FPCR.EBF behavior. All use saved
SVL, preserve FPSR and leave unselected rows/backing untouched. These eight
entries complement the six existing ordinary BF16 ZA dot entries.


Non-FP8 MOP4 and selective TMOP outer products cover all 139 June encoding
entries on 30 primary pages. The category includes signed, unsigned and
mixed-sign integer dot products to 32/64-bit ZA, IEEE FP16/32/64 fused
outer products, FP16-to-FP32 two-product dots, and BF16 fused/dot products.
MOP4 source groups are selected across opposite output quadrants, with
independent one/two-register lists and addition/subtraction. TMOP selects
the first one/two source lanes from the two-vector group; byte products
select two independently from each register. Packed control segments and
indices use each encoding's exact mask size. Incoming aliases, every
supported SVL, physical tile interleaving and untouched ZA backing are
preserved. Native admission retains MOP4/TMOP independently of F16F16,
B16B16, F64F64 and I16I64. FP results use the same exact ZA fused and
separately rounded dot contracts; integer products are modular and do not
consume FP context or modify QC/NZCV.

Grouped IEEE SME arithmetic covers all 38 physical entries on 19 primary
pages (98 format/group variants): FMUL, FMAX/FMIN, FMAXNM/FMINNM, FSCALE,
FAMAX/FAMIN, FCLAMP and FRINTA/M/N/P. Multiplication uses its independent
source group; destructive operations capture incoming destination aliases.
The two/four-register forms use saved SVL independently of CurrentVL, require
streaming mode and preserve all storage above SVL and other registers.
FRINT encodings operate on FP32 only. Admission retains SME2p2 for FMUL,
FP8 for FSCALE and FAMINMAX for absolute min/max independently of SME2.
Effective FPCR masks exception enables without FA64 and ignores AHP for
IEEE arithmetic. Ordered status/trap evaluation precedes destination writes,
including both numeric min/max stages of clamp. AFP retains operand-two
NaN/signed-zero selection for nonnumeric min/max, distinct numeric output
flushing, and directed rounding of unflushed subnormal inputs. Absolute
min/max retains its architecturally separate AH/FIZ/FZ/FZ16 behavior.

Grouped BF16 arithmetic covers all 26 physical entries for BFMUL,
BFMAX/BFMIN/BFMAXNM/BFMINNM, BFCLAMP and BFSCALE. BF16 values expand exactly
for min/max selection, while multiplication rounds directly to BF16 precision
and scaling uses BF16 integer expression algebra; neither introduces an
intermediate FP32 rounding. FP32 AH/FIZ/FZ controls apply independently of
FZ16/AHP. The category preserves saved SVL, two/four-register groups,
incoming aliases, status/trap ordering and backing. Native admission exposes
SVE_B16B16 and SVE_BFSCALE independently from SME_B16B16, including their
ID_AA64ZFR0_EL1.B16B16 identification levels.

Ordinary SVE BF16 arithmetic covers all 17 physical entries: predicated and
unpredicated BFADD/BFSUB/BFMUL, indexed BFMUL, predicated numeric/nonnumeric
min/max and scale, clamp, and predicated/indexed BFMLA/BFMLS. Indexed lanes
repeat per 128-bit segment. Empty predicates consume only predicates and
incoming destination storage, with no FPCR/FPSR/source reads or FPSR write.
CurrentVL stays independent of saved SVL; streaming execution requires SME2
or effective FA64. FPCR exception-enable masking follows streaming/FA64,
and fused operations use exact BF16 products plus the addend before one
rounding. AH NaN priority, negative default NaNs, FIZ versus FZ and direct
result-flush exception behavior reach native execution and recovery.

Grouped floating-point conversion covers all sixteen physical entries on twelve
June primary pages: FCVT/FCVTL half widening; FCVT/FCVTN and BFCVT/BFCVTN
single narrowing with concatenated/interleaved layouts; two/four-register
SCVTF/UCVTF and FCVTZS/FCVTZU; and SVE2p3 FCVTZSN/FCVTZUN narrowing to
8/16/32-bit integers. SME-only forms consume saved SVL; the SVE narrowing forms
consume CurrentVL independently. All source groups and aliased destinations
observe incoming state, while execution and first-enabled-exception order follow
the primary operation order before destination packing. Backing above the active
length is preserved. AFP conversion handling includes FIZ, signed default NaNs,
post-rounding denormal exceptions, and BF16's exception-free nearest-even mode.

Floating quadword reduction implements FADDQV/FMAXQV/FMINQV/FMAXNMQV/FMINNMQV
at half/single/double precision, all predicate masks and all five CurrentVLs.
Each output position reduces the corresponding lane across 128-bit segments,
using the recursive high-first evaluation and low/high combine order in
FPReduce. Single-segment cases transport raw bits without FP arithmetic or FPSR
access; numeric min/max inactive identities use the AFP-signed default NaN.
The V128 result clears bits 128 through CurrentVL and preserves higher backing.
Native checks include a rounding-sensitive cancellation that distinguishes the
pair tree from serial summation, as well as complete register-state comparisons.

SVE floating helpers include FAMAX/FAMIN, FCLAMP, FTSMUL and FTSSEL at all
three floating widths and five CurrentVLs. Absolute min/max locally disables
AH/FIZ/FZ/FZ16, retains original NaN payload/sign priority and preserves inactive
lanes without FP context access. Clamp orders numeric maximum before numeric
minimum. FTSMUL squares with one rounded multiplication before applying the
selector sign to non-NaNs; FTSSEL transports raw bits or signed one and uses
AFP-aware FPNeg only for its negated-source branch. Trigonometric preprocessing
requires non-streaming execution or effective FA64. All forms preserve backing
above CurrentVL and observe incoming aliased operands.

Fixed-width AdvSIMD FP8 arithmetic covers all 16 June encodings: FMLALB/T,
FMLALLBB/BT/TB/TT, and two/four-way FDOT, including indexed and vector forms.
Each source has its own FPMR format; LSCALE applies before a single destination
rounding. Arithmetic suppresses FP exceptions and preserves FPSR. Indexed
widening uses the full H:L:M:Rm[3] byte selector, independently of the three-bit
source register. FDOT supports both 64-bit and 128-bit results. Fixed-width
writes clear the rest of CurrentVL while preserving backing above it, observe
incoming aliases, and require FA64 in streaming mode. Native arithmetic feature
admission is independent of SVE/SVE2.

Fixed FP16 arithmetic additionally implements FDOT (vector and indexed),
FMMLA with half results and FMMLA widening to single results. A distinct exact
half-dot contract retains FZ16 input handling, four-source signaling-NaN
priority, payload widening, directed rounding, FPSR accumulation and enabled
exception traps. Dot products round before adding their accumulator; widening
matrix multiply rounds its two pair dots before their sum and the accumulator
addition. Half-result matrices round each multiply, their sum and the final
addition separately. Every form preserves incoming aliases, suppresses later
operations and all destination writes on a trap, and clears active upper Z.
The F16F32DOT/F16F32MM feature levels are reflected in ISAR0.FHM; F16MM is
reported by FPFR0.F16MM2 and, with SVE, ZFR0.F16MM.


The non-FP8 SVE matrix category consolidates all six encodings: same-precision
BF16/FP16/FP32/FP64 matrices and BF16/FP16 widening to FP32. Each independent
2-by-2 segment retains source snapshots even when destination aliases either
input. BF16 widening performs two ordered BFDotAdd operations with suppressed
exceptions and leaves FPSR untouched; FP16 widening rounds its pair dots before
their sum and final accumulator add. Same-precision multiplication and both
additions each round separately, with ordered enabled-exception handling.
FP64 requires CurrentVL at least 256. All forms require non-streaming SVE or
effective FA64, preserve backing beyond CurrentVL, and use explicit per-class
feature admission. F32MM and the newer BF16 matrix capability are represented
in ZFR0; the half-to-single SVE capability is separately selectable.


Additional lane arithmetic implements SVE merging FABD, vector/indexed FP16
FDOT with FP32 accumulation, and every signed/unsigned lower/upper widening
integer conversion in SCVTF/SCVTFLT/UCVTF/UCVTFLT. Predicate-inactive FABD
lanes retain their bit patterns without reading FP state or inactive operands;
AH controls the sign of NaN absolute results. Half dots round before the
accumulator addition. Widening conversions sign/zero extend integer bits before
a single FP rounding. Fixed AdvSIMD FSCALE uses the exact integer Scale algebra
for FP16/32/64, signed full-width exponents, cumulative flags and precise traps;
64-bit vector encodings clear the destination upper half through CurrentVL.


SME2 grouped integer arithmetic includes every two/four-register ADD,
signed/unsigned min/max and clamp form, counter-predicated SEL, signed/unsigned
unpack, and two/four-register ZIP/UZP (36 physical encodings). Integer wraparound
and signed comparisons use the architectural element width, clamp retains the
specified Max-then-Min order even for reversed bounds, and SEL interprets PN as
the existing counter encoding. Permutations include 128-bit elements and their
minimum SVL constraints. All source groups are captured before any write,
streaming mode is required, ZA enable is independent, and storage above SVL is
preserved.


ZA integer ADD/SUB covers all twelve two/four-vector encodings, including
accumulation from ZA, vector/broadcast assignment, and paired vector assignment.
It applies 32/64-bit lane wraparound, reads W8-W11 for the row selector, wraps
the offset within each group's row stride, and wraps unaligned vector source
groups at Z31. These operations require SM and ZA, preserve every unselected
ZA bit and Z register, and consume no FP state. The 64-bit forms additionally
require SME_I16I64.


ZA integer multiplication includes all 21 mixed-sign long multiply and vertical
dot encodings (SUMLALL, USMLALL, SVDOT, UVDOT, SUVDOT, USVDOT). The recipes
preserve independent source signedness, indexed 128-bit segment selection,
transposed vertical dot source groups, wrapping unaligned vector groups,
quad-row alignment after row-selector modulo, and lane-local modular sums.
The common ZA integer matrix implementation addresses only selected rows using
indexed registers, preserving all inactive rows and storage beyond SVL without
expanding every possible row into conditional writes. SM and ZA are required;
64-bit vertical dots additionally require SME_I16I64. No FP state is consumed.


SME state recipes cover all 27 MOVAZ, selected ZERO ZA, ZERO ZT0 and MOVT
encodings. MOVAZ atomically transfers and clears horizontal/vertical tile slices
or strided ZA vectors, including 128-bit elements and maximum SVL. Z outputs
choose SVEZEROUPPER, while ZA preserves inactive backing. Scalar ZT0 MOVT reads
explicit one-bit `a64.debug_halted[0]` context (Splice Special42); it is admitted
only when halted, and XZR remains zero/discard. Z-to-ZT0 insertion uses the
SVL-capped 128/256/512-bit transfer, wraps its segment index and zeroes the
remainder only for immediate zero. Table-only ZERO/scalar MOVT needs ZA but
permits non-streaming mode. Four 64-bit tile slices require SVL at least 256.

Ordinary SVE transfers use one ordered access at the specified width for each
active lane, including 128-bit gather/scatter and zero-extending 32/64-bit loads
into 128-bit elements. Whole Z/P spills use byte accesses and signed scaled
nine-bit offsets. The complete contiguous family shares this path, including
signed register offsets. Inactive lanes suppress source, base and offset reads;
loads zero inactive elements and select SVEZEROUPPER for unused backing. Generic
Protection traps represent alignment failures in the recipe trap vocabulary.
Misaligned uses consult explicit effective `a64.alignment_enforced[0]` (Special43)
and SP uses `a64.sp_alignment_enforced[0]` (Special44); aligned accesses require
neither input. Empty predicates choose the permitted CHECKSPNONEACTIVE=false.
128-bit SVE transfers permit non-streaming mode or streaming with effective FA64.

The 28 SVE prefetch encodings select the NOP behavior explicitly permitted by
Hint_Prefetch, retaining streaming/FA64 admission without touching guest memory
or demanding hint operands. They cannot create translation/alignment aborts or
Device accesses. PMLAL computes both full 64x64 carryless products and XORs them
into the incoming pair, preserving aliases. PSEL uses 32-bit W12-W15 selectors,
adds the decoded immediate in unbounded-index arithmetic, wraps at CurrentVL,
and copies the complete active predicate or zeros it; unused backing is zero.


LSFE load-update and no-return store recipes cover all 120 June 2026 encodings:
IEEE binary16/32/64 and bfloat16 add, maximum, minimum, maximum-number and
minimum-number, including acquire/release combinations. Each instruction is one
floating atomic read/modify/write event, with the original-width old memory
value returned to Vt for load forms (V31 is a real vector destination). Store
forms have a separate no-return encoding bit. Writes clear the full retained
2048-bit vector backing above the returned scalar. Both data endians are
explicit. An incoming SP alignment policy check runs before any atomic request.

The floating atomic contract takes the source bits and raw FPCR separately in
recipes. Native `AtomicRmwOp::AArch64{B}Float*` packs them in a W+32-bit operand:
source in bits W-1:0, raw FPCR in bits W+31:W; memory and result remain W bits.
Integer atomic tags 0 through 9 retain their storage identity; floating tags 10
through 19 append to the same typed statement. Executors implement Arm
MemAtomicFP: AH=0, DN=1, FZ=FZ OR FIZ, dynamic rounding/FZ16, no enabled floating
exception trap and no FPSR update. Native LLVM lowering uses a strong cmpxchg
retry loop and an explicit pure `__bt_aarch64_atomic_{f,bf}{op}_fW` helper ABI;
it never substitutes a host-environment floating atomic instruction. These
helpers, like other exact floating runtime helpers, must be supplied by the
LLVM consumer. The bit-vector-only reconstruction proof backend reports this
floating operation unsupported instead of treating its packed operand as integer
arithmetic. Decompiler AST and storage retain the typed atomic operation,
ordering, memory attributes and explicit FPCR-bearing operand.

Scalable FP8 conversions include both BFConvertFP8 layouts: streaming grouped
`BFCVT` and interleaved `BFCVTN`. A bfloat16 source widens exactly to binary32
bits before narrowing, so it uses all eight signed NSCALE bits and ignores AHP.
The entire scalable conversion family clears retained Z backing above VL/SVL.
Ordinary forms permit streaming with SME2 or effective FA64, while streaming-only
forms require SM; exception controls remain conditional on FA64.

### Non-branch A64 system hints and barriers

CSDB, CLRBHB, DGH, STCPH, both STSHH forms, both SHUH forms,
PSB CSYNC, TSB CSYNC, CHKFEAT, SSBB/PSSBB and all four DSB nXS
options retain their separate architectural contracts. Implementation-defined
performance hints carry distinct typed events; they do not fabricate data
fences or memory transactions. Profiling and trace synchronization carry
separate ordered events. Their runtime backend supplies the profiling/trace
machinery, as the barrier ABI already requires for data synchronization.

`a64.system_hint_features` is an eight-bit incoming mask in the order CLRBHB,
DGH, CMH, PCDPHINT, SPE, TRF, CHK, XS. Absent optional hint features execute
as NOPs without consulting policy or operand inputs. DSB nXS without XS is
UNDEFINED. `a64.psb_trap` and `a64.tsb_trap` contain the effective fine-grained
trap decisions; admitted traps occur before synchronization. The current trap
vocabulary reports Protection and does not model EL2 exception entry or syndrome
register writes. `a64.gcs_enabled` resolves the effective feature-enable bit
queried by CHKFEAT; only selected bit zero is cleared and all other selectors
are preserved. `a64.dsb_nxs` resolves FEAT_XS and the ordinary DSB's effective
EL/HCRX_EL2.FnXS override. Unknown required inputs remain unavailable.

Native Special registers 45 (mask, eight bits) and 46 through 49 (one bit each,
PSB trap, TSB trap, GCS enable, ordinary DSB nXS) preserve these inputs in
checkpoints. New software EL0 processes initialize the feature mask from the
execution profile and the four effective controls clear. Migration preserves
saved controls and leaves missing policy inputs unavailable. New barrier
kinds append durable storage and LLVM runtime ABI tags 4 through 16; tags
zero through three retain their meanings. LLVM runtime implementations must
interpret each tag according to the named event contract.

### A64 unprivileged load/store families (LSUI)

The 64 canonical LSUI encodings and their 12 store aliases carry an explicit
`AArch64Unprivileged` memory policy through generated evaluation, native IR,
execution, canonical identity and durable storage. This policy selects
`AArch64_IsUnprivAccessPriv` using the environment's EL, nested-virtualization
and UAO controls; it does not mean an unconditional address-space number.
The software A64 CPU executes at EL0, where the policy uses unprivileged guest
mappings. Other generated backends must implement the typed access callback;
ordinary read callbacks are never an implicit substitute.

CAST/CASPT preserve compare-exchange success/failure ordering and indivisibility;
LDTXR/LDATXR and STTXR/STLTXR preserve reservation/status behavior. LDTADD,
LDTCLR, LDTSET and SWPT preserve return values and acquire suppression when the
result is discarded. Scalar and SIMD pair transfers retain one original-width
128/256-bit access, byte order, signed scaled offsets and pre/post writeback.
SIMD loads clear all upper scalable backing. Non-temporal pair hints do not add
an ordering guarantee. Permitted constrained-unpredictable register overlaps
select the documented NOP or undefined-instruction outcome before any access.
SP alignment checks precede memory and all architectural writes.

Ordinary persisted accesses retain their previous row and column bytes and
canonical identities. Unprivileged accesses use a tagged policy extension.
Decompiler presentation retains the qualifier and excludes these accesses from
ordinary-memory folding. Direct LLVM pointer lowering explicitly rejects the
policy until a target permission runtime is supplied; it cannot silently turn
an unprivileged transfer into an ordinary host pointer access.


### A64 limited-order loads and stores (LOR)

All eight LDLAR/LDLARB/LDLARH and STLLR/STLLRB/STLLRH forms retain
`AcquireLimited` or `ReleaseLimited` through recipes, native transitions,
canonical identity, durable storage, decompiler output and reconstruction
verification effects. These contracts retain the architectural LORegion-dependent
ordering; consumers must not substitute ordinary acquire/release or RCpc.
Limited ordering is valid only for scalar ordinary loads/stores of 8, 16, 32 or
64 bits, with its matching direction. Exclusive, pair, RMW and compare-exchange
operations reject it. Existing ordering storage tags 0 through 5 stay stable;
limited acquire and release append tags 6 and 7.

Generated requests preserve the address, transfer width, endian and ordering for
the target memory backend. Register 31 is SP as base and zero/discard as data.
SP alignment policy runs before memory; loads zero-extend their architectural
W/X destination. The native EL0 CPU selects SCTLR.nAA=0: with alignment checking
off, unaligned accesses within one aligned 16-byte quantity are allowed, while
boundary-crossing accesses fault. Enabling alignment checking requires natural
alignment. CPU fault selection precedes guest memory publication, and permission
faults publish no register or memory effects. Stores need write permission only.
The `lor` execution feature reports FEAT_LOR and the corresponding MMFR1 LO field.
Direct LLVM lowering rejects these target-specific orderings explicitly; its
ordinary atomic vocabulary cannot represent the architectural contract.


### A64 restricted compare/write atomics (RCW)

The 64 physical encodings across RCWCAS/RCWSCAS, RCWCLR/RCWSCLR,
RCWSET/RCWSSET and RCWSWP/RCWSSWP, including all pair variants and A/R
orderings, produce typed conditional atomic updates. Scalar accesses are 64 bits;
pair accesses are one indivisible 128-bit transaction. Hard and soft checks,
failed comparisons, old-value returns and all four NZCV outputs follow explicit
mask and protection inputs. A rejected check selects the architectural no-write
outcome. Pair register overlap selects the permitted decode-NOP outcome.

The recipe register banks `a64.rcwmask64[0..1]` and
`a64.rcwsmask64[0..1]` provide raw architectural masks; recipes expand their
replicated bits and clear reserved bits before passing effective numeric masks
to the atomic backend. `a64.protection_enabled` and `a64.d128_enabled` are
explicit effective controls. Scalar operations require D128 disabled and pair
operations require it enabled. Mode and SP checks precede memory observation;
unknown selected controls and unavailable atomic capabilities fail explicitly.
Numeric mask bits retain their meaning in either transfer endian.

Native transitions pack expected value, update operand, effective hard mask,
effective soft mask and protection into a `4W+1` bit operand, retaining one
atomic operation at width W. Guest execution checks permissions and natural
alignment before observing memory, then publishes the conditional write, old
register values and flags together. The EL0 software CPU defaults both masks
to zero and protection disabled, and selects D128 from the configured `d128`
feature. These controls are retained in ordinary CPU checkpoint state; older
checkpoints that lack controls do not fabricate available values. The `the`
feature reports ID_AA64PFR1_EL1.THE and `d128` reports ID_AA64MMFR3_EL1.D128.
Both features are required for pair instructions.

LLVM emits integer checks and a compare/exchange retry loop directly. Failed
checks perform no write, and interference retries the checks against the newly
observed value. Durable atomic operation tags append 20 through 27, preserving
all existing tags. Decompiler presentations preserve the restricted operation
name and packed policy. Reconstruction proof translation currently rejects
these operations explicitly because its expression domain cannot represent
the packed policy operand; this is distinct from executable recipe support.

MOPS uses a documented permitted Option B implementation: prologue and epilogue
work sizes are zero, ordinary copy/set main iterations transfer one byte, and
SETG main iterations transfer one aligned 16-byte allocation granule. The main
recipe branches to its own PC while work remains. A consumer executes these as
restartable iterations, preserving completed iterations across a fault and
retiring the instruction only when it leaves that PC. Copy direction follows
low-56-bit overlap; nonoverlapping copies select forward execution. Counts are
clamped to the architectural family limit. Effective MOPS enablement is an
explicit input; register overlap, format mismatch and malformed parameters keep
their architectural traps. Non-temporal options are cache hints and introduce
no additional architectural state.

Allocation metadata has its own four-bit load/store operations and ordered
transition entries. A tag names an aligned 16-byte granule, never four data bits
or one ordinary byte. MTE scalar/pair tag operations and MTE2 bulk operations
retain address updates, data/tag ordering, endian rules and privileged traps.
Bulk block sizes and the current exception level are explicit inputs. The memory
provider owns tag enablement, allocation-tag translation, memory type and tag
availability; a provider without tag support rejects tag reads explicitly.

Splice lowers tags to a distinct memory-access kind and stores them separately
from guest data. Snapshots, forks, restore and unmap retain this distinction.
Mapped granules start with tag zero in this software environment. FEAT_MTE's
default EL0 policy disables allocation-tag access; translation and permissions
still apply, reads return zero and stores preserve metadata. Explicit effective
controls can enable allocation metadata. The `mte2` feature requires `mte`,
admits the bulk tag instructions, and reports level 2 in ID_AA64PFR1.MTE;
base `mte` reports level 1 and rejects those instructions. Ordinary data
tag-check execution remains outside this allocation-metadata provider. LLVM rejects metadata accesses until a target
tag runtime is supplied; decompiler folding and byte-data dependency tracking
must not replace them with ordinary memory operations.

IRG uses the same effective MTE-enable and exclusion state as ADDG/SUBG.
Its deterministic paths retain the architectural 16-bit RGSR LFSR and four-bit
TAG/EIRG state, including the four-step ordinary generator, the single-step
EIRG generator and the all-excluded cases. RRND uses one explicit 64-bit replayable
entropy draw to select an included bin with multiply-high scaling; it leaves
RGSR unchanged, a permitted implementation-defined choice. Disabled access and
an empty RRND set consume no entropy. Native checkpoints retain the effective
RRND/EIRG controls and generator state; older unavailable controls remain unavailable.

LS64 covers LD64B, ST64B, ST64BV and ST64BV0. A typed `AtomicStep::Block64`
passes one address-ordered eight-word transfer to `Machine::evaluate_block64`.
The provider must preserve the 64-byte event, resolve translation, memory type,
alignment and tag policy, and stage effects until the whole transition commits.
There is no scalar fallback. Per-word guest byte order, incoming register aliases,
the status destination and ACCDATA_EL1 substitution are architectural recipe
operations. Effective `a64.ls64_enabled[0..2]` controls respectively select the
LD/ST64B, ST64BV and ST64BV0 trap decisions; `a64.accdata_el1` is 32 bits.
A declined status-returning store retains the provider's 64-bit status without
inventing a completed data write. Plain ST64B must commit or fault. Unknown or
malformed block observations are rejected before a transition is published.

Splice's conventional shareable software-memory target implements LS64 as one
aligned 512-bit native atomic load or store, returns zero on successful stores
with status, and clears its local reservation. It has no accelerator response
channel or Device-memory model. The `ls64`, `ls64-v`, `ls64-accdata` and `ls64-wb` feature
levels gate the corresponding instructions and report ID_AA64ISAR1_EL1.LS64.
Conventional write-back memory requires `ls64-wb`; older levels fault on this
software-memory target instead of gaining that capability implicitly.
LLVM currently rejects this atomic width explicitly; it must not decompose the
operation into smaller host accesses.

WFET/WFIT use explicit incoming `a64.event_register` (one bit),
`a64.interrupt_pending` (one bit) and `a64.virtual_counter` (64 bits).
WFET clears an already-set event register before retiring; WFIT retires for a
pending interrupt. Both retire when the unsigned virtual-counter value reaches
the deadline. Readiness suppresses unused timer/deadline inputs and the wait
provider. Otherwise a typed timed-wait request preserves the event/interrupt
kind, source-register number and 64-bit deadline. The provider resolves wakeup,
delayed trapping and EL3 undefined priority without mutating guest state.
Outcomes are fallthrough, WFET event clearing, Protection, or InvalidInstruction;
WFIT cannot clear the event register. No instruction memory access is invented.

Splice retains selected timed waits as closed environment operations, including
explicit source and deadline inputs. A provider is required for an unexpired
wait; the default environment reports the evaluated external boundary. Readiness
and permitted provider outputs execute transactionally and survive checkpoints.
The `wfxt` feature gates both forms and reports WFxT identification level 2.
HINTE covers every allocated extended immediate as an architectural NOP and
excludes the complete legacy HINT subspace; Splice gates it with `hinte`.

### A64 branch-target pipeline

`Decoded::semantic_recipe_with_branch_target_context` adds the architecture's
instruction-entry branch-target check and successful-completion BTYPE update to
the ordinary context recipe. This applies to every instruction, not only BTI.
It preserves Unsupported results. The ordinary context API retains the
feature-absent execution contract; the explicit pipeline API requires
`a64.bti_enabled` (one bit). When disabled it reads no other BTI state.

When enabled, `a64.btype` is the incoming two-bit PSTATE value,
`a64.bti_guarded_page` identifies the current fetched instruction's guarded page,
and `a64.debug_halted` bypasses the check during debug halt. All four BTI hints,
BRK/HLT compatibility, and PACIASP/PACIBSP and PACIASPPC/PACIBSPPC implicit landing
pads follow the primary compatibility rules. PAC compatibility uses the existing
feature-presence banks and effective one-bit `a64.bti_pac_strict` (SCTLR BT0/BT1)
and `a64.bti_pac_disabled` (PAuth_EnhCtl SCTLR2 BTD0/BTD1) controls. SPPC forms
ignore BTD. Feature-absent PAC hints are not implicit landing pads.

BR/BRAA/BRAB and zero-modifier forms produce BTYPE 1 from X16/X17 or an unguarded
source page, otherwise 3. BLR and authenticated calls produce 2; returns, direct
branches and ordinary instructions produce 0. A Branch Target exception occurs
before predication, operand reads, entropy, memory or instruction effects. A
successful completion updates BTYPE even if ordinary effects are predicated off;
exceptions and faults retain incoming state. `Recipe.entry_traps` and
`completion_writes` express these two pipeline boundaries independently of the
instruction guard and are validated as incoming-state-only expressions.

Splice adds these generated rules during CPU execution preparation when the
`bti` feature is configured, covering every native A64 lifting path, including
compact AES, streaming reset and FP-control transfers. Static lifting retains
the ordinary feature-absent contract; the explicit generated API supports
consumers that model branch-target state. CPU version 15
stores enable/type/fetch/PAC controls in Special 71 through 75 with widths
1/2/1/1/1. New software-target mappings begin unguarded; a caller that models GP
translation attributes must supply the resolved current-fetch value. This is not
a page-table walker or privileged exception-entry implementation: a failed check
raises the explicit `TrapKind::AArch64BranchTarget` trap with incoming BTYPE still available.
The `bti` CPU feature supplies ID_AA64PFR1_EL1.BT=1 without turning feature-absent
BTI hint encodings into decode failures. Checkpoints retain all controls and
pending branch types, and migration preserves explicit saved values.

### A64 guarded control stacks

GCSSTR/GCSSTTR retain a distinct 64-bit guarded-control-stack store contract,
with incoming source/base aliasing, XZR/SP, byte order, GCS-specific natural
alignment and explicit unprivileged selection. GCSB emits the distinct
`GuardedControlStackSynchronization` event when FEAT_GCS is present and is a
feature-absent NOP. The store builders check `a64.gcs_present`, the effective
`a64.gcs_store_permitted` STREn/trap resolution, and SP alignment before any
memory effect. GCSSTTR uses `a64.current_el` and resolved
`a64.unprivileged_is_privileged` to determine whether the current STREn is
consulted. Privileged exception routing remains an explicit caller obligation;
the typed `TrapKind::AArch64GcsStore` trap preserves the current instruction and state.

Portable `MemoryKind::GuardedControlStack`, `MemoryWrite.guarded_control_stack` and native
`MemoryAccessKind::GuardedControlStack` prevent these writes from silently
becoming ordinary byte stores. Splice's flat Normal-memory target requires a
writable mapping with `MappingDetail.guarded_control_stack=true` for a GCS store,
and rejects ordinary guest stores to that protected mapping. Ordinary reads
retain their separate read permission. This is the software target's resolved
permission policy, not a hardware page-table walker; callers importing hardware
translation attributes must normalize them to that policy or reject the target.
Analyst/setup byte supply remains separate from guest access. Mapping splits,
forks and saved memory roots retain this metadata; trace events preserve the GCS
access kind. LLVM rejects GCS memory without a target permission runtime.
Persistence and C/Rust/Go presentation retain the access contract, and ordinary
memory folding predicates exclude it. CPU version 16 adds presence, store
permission and resolved unprivileged controls in one-bit Special 76 through 78;
ID_AA64PFR1_EL1.GCS reports the configured feature.

GCSPUSHM/GCSPOPM, GCSSS1/GCSSS2, GCSPUSHX/GCSPOPCX/GCSPOPX and
GCSPR_EL0 reads retain the same protected access identity. SS1 is one 64-bit
monotonic compare-exchange, including its incoming witness and capability test;
SS2 checks the switch token, restores the old capability and emits GCS
synchronization. Exception records retain their format, ELR, SPSR and LR fields,
ordered read checks and precise typed failures. POPX still performs every record
read even though it discards the values. Explicit system aliases consume
`a64.gcs_stack_permitted`, the caller-resolved SYS permission policy; privileged
record operations reject EL0 before reading operands. The current pointer is
masked to eight-byte alignment, and GCSPR_EL0 remains readable independently of
implicit record enablement.

`semantic_recipe_with_gcs_context` adds implicit call records and return checks
to the generated public API. Incoming target authentication and register captures
precede the protected record access; successful returns consume a record, and
returns with checking disabled use the recorded target. Feature-absent or
PCRSEL-disabled paths perform no pointer or protected memory access. Splice's CPU
preparation applies this contract when `gcs` is configured, before its BTI wrapper,
so instruction-entry BTI faults retain priority over body effects. Static lifting
keeps its explicit context API. CPU version 17 adds the current pointer (Special
79), return check (80), system permission (81), selected SPSR/ELR (82/83), EXLOCK
(84) and effective EXLOCK enable (85). The pointer and privileged record inputs
remain unavailable until supplied. Checkpoints migrate older states while
preserving explicitly supplied controls. GCS return, pop, authenticated-return,
switch and exception-record failures have distinct closed trap identities across
canonical semantics, storage and projections. Hardware exception-vector routing
and translation-control resolution remain target responsibilities.

A32 and Thumb NEON FP16/FP32 lane arithmetic covers VADD/VSUB/VMUL,
VFMA/VFMS and separately rounded VMLA/VMLS, VABD, ordered/equality and
absolute comparisons (including all five comparison-with-zero relations),
VMAX/VMIN and numeric extrema, and D-register VPADD/VPMAX/VPMIN. Sources
share the architectural D/Q bank and are captured before aliased outputs.
StandardFPCR fixes nearest-even, default NaNs and single-precision flushing,
disables exception traps, and retains FPSCR.FZ16 for half arithmetic. Sticky
status is accumulated without changing integer NZCV or floating controls.
FP16 physical feature requirements are checked before input reads, including
sign-only VABS/VNEG, and FP16 Thumb forms reject an IT context.

The generated feature expression evaluator also accepts partial feature
knowledge through `Expr::evaluate_with`: unknown capabilities remain unknown,
while a proved unsatisfied requirement remains rejectable. A32 `Undefined()`
guards and A64 `EndOfDecode(Decode_UNDEF)` guards produce the same explicit
conditional feature rules. Native load-list lowering publishes a leading
completed register transfer before later accesses only after proving that no
later input reads its architectural register or a dynamic register family;
otherwise it retains incoming-state capture order.

NEON integral rounding implements VRINTA/N/P/M/Z/X for FP16 and FP32,
including VRINTX's exact-inexact status behavior. VCVTA/N/P/M, truncating
VCVT and integer-to-float VCVT use signed or unsigned lanes of the same width.
Fixed-point VCVT covers both directions and all 1..16 or 1..32 fractional
scales. D/Q aliases, upper D-bank registers and StandardFPCR control are
preserved across the entire category; FP16 forms require the physical FP16
capability and reject Thumb IT contexts.


## Moving handwritten lifters into generated ownership

Instruction behavior belongs in these architecture recipe templates; consumers
retain register mapping, memory contracts and lowering into their own IR. The
Splice BMI1/BMI2 lifter has moved entirely to generated recipes: ANDN, BEXTR,
BLSI, BLSMSK, BLSR, BZHI, MULX, PDEP, PEXT, RORX, SARX, SHLX and SHRX.
BEXTR includes AMD TBM's XOP immediate-control form. MULX captures implicit
EDX/RDX and its explicit source before writing low then high destinations, so
coincident destinations retain the high half. Both operand sizes, register and
memory forms, incoming aliases and defined/undefined flags are preserved.
Splice retains independent arithmetic reference tests and requires both the
public generated recipe and its native adapter; a handwritten fallback cannot
satisfy those tests. A decompiler regression follows MULX and TBM BEXTR through
an indirect branch to its recovered target.

Splice's AES rounds, inverse MixColumns, key assistance, carry-less
multiplication and all three GFNI operations now use these generated recipes
exclusively. Legacy SSE preserves the upper register bits; VEX/EVEX clear the
upper destination and apply the operation independently in each 128-bit lane.
GFNI retains its byte-mask and quadword-matrix behavior. The duplicate native
crypto module and separate AESENC lifter have been removed. Native reference
vectors, wide aliased destinations, actual executor register/memory/fault paths,
and an indirect-dispatch recovery case exercise the generated implementations.

SHLD/SHRD and RCL/RCR likewise have no handwritten native fallback. Recipe
admission restricts the architectural operand widths and SHLD/SHRD's register
source. Count masking, carry rings, CL aliases, high bytes, preserved and
undefined flags, long-mode r32 zero extension, and the unconditional read but
conditional store of a zero-count memory operand remain covered by the retained
exhaustive native arithmetic references. Public generated tests additionally
execute all 256 counts in every supported mode and width. Both the public tests
and native adapter enumerate every supported legacy, VEX and EVEX corpus form
in these migrated families; this does not admit separate MVEX state contracts.


Splice's packed-integer module is also replaced by generated ownership across
MMX, SSE, VEX and EVEX: ordinary and saturating arithmetic, comparisons,
multiply/average and horizontal operations, element and byte shifts, packs,
unpacks, immediate and byte shuffles, alignment, blends, widening, SAD and
minimum-position reductions, and PTEST. Widening memory operands read their
actual input width; EVEX masks suppress inactive input lanes and retain merging
or zeroing plus architectural upper-register clearing.

MMX recipes include the waiting x87 exception check, physical-register lookup
through incoming TOP, rotation into TOP=0, valid tags, and the destination's
all-ones exponent. These effects share the recipe's atomic transition: a pending
unmasked exception precedes operand memory reads and publishes nothing. Splice uses the generated MMX envelope for arithmetic and transfer instructions.
The removed integer module's independent reference tests now require generated
admission; corpus checks cover all migrated instruction names in 16-, 32- and
64-bit modes. Executor cases cover every incoming TOP and fault atomicity, and
the decompiler follows widening and byte shifts into a resolved indirect branch.


The vector movement and selection family is generated as well: scalar and
whole-vector transfers, MMX/XMM transfers, half-register and duplicating moves,
non-temporal transfers, broadcasts, inserts/extracts, shuffles, permutes, blends,
logical operations, sign-bit tests, masked loads/stores, and vector clearing.
Legacy SSE preserves upper storage; VEX/EVEX writes clear upper storage where
specified. Ordinary vector memory accesses retain their original width, while
masked accesses suppress each inactive element without evaluating its address.
Alignment checks use the effective linear address, including segment bases.
Generated operand metadata retains suppressed ASZ base registers, so MASKMOV
stores use DI, EDI or RDI according to the address size, including overrides.
Inactive source lanes and addresses remain unevaluated under an empty mask.

Restartable gathers use `Recipe.read_progress`, an ordered sequence of register
updates before or after individual ordered reads. Their inputs must be immutable
prefix bindings or completed read results; validation rejects direct state reads,
forward read references and reordered stages. VEX vector masks are normalized
before the first access; EVEX predicate masks retain only active bits. Completed
lanes publish their destination and cleared mask before a later lane can fault.
Successful completion clears the remaining destination upper bits. Aliased VSIB
registers and invalid addressing produce an instruction trap before memory.

`evaluate_with_progress` returns `EvaluationFailure` containing the classified
error and optional published restart transition. Consumers apply that transition
before delivering a fault. Ordinary `evaluate` retains its original error API;
consumers executing restartable instructions should use the progress API. Splice
lowers these publications directly between loads and enables prior-state fault
publication in its CPU adapter. Executor tests fault and resume both VEX and EVEX
gathers with completed addresses made unavailable, ensuring restart uses the
remaining mask. The handwritten movement module, transfer helpers and MMX
wrapping path have been removed; corpus checks require generated lowering for
all supported legacy, VEX and EVEX forms in this migrated family.

VZEROUPPER and VZEROALL clear through bit 511 of ZMM0–ZMM15 in 64-bit mode
and ZMM0–ZMM7 otherwise; VZEROUPPER preserves the low 128 bits. ZMM16–ZMM31
are preserved. This follows the MAXVL operation in the [Intel instruction
reference](https://cdrdv2-public.intel.com/789581/325383-sdm-vol-2abcd.pdf), and
corrects the handwritten helpers that stopped at bit 255.
