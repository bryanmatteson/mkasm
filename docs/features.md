# Architectural requirements

Generated A64, A32/Thumb, x86 and common fixed-field codec crates expose a
`requirements` module and `requirements_for(source_encoding_or_form_id)`.
A decoded instruction exposes `requirements()` and `evaluate_requirements(...)`.
These APIs describe architectural requirements from the imported specification.
They do not declare which instructions a downstream interpreter implements.
Successful structural decoding does not establish architectural admission.

```rust,ignore
use aarch64::requirements::{Satisfaction, UnknownPolicy};
let decoded = aarch64::decode(word)?;
let result = decoded.evaluate_requirements(&["FEAT_FP", "FEAT_FP16"], "a64");
if result.admit(UnknownPolicy::Reject) {
    // Separately check the consumer's implemented instruction semantics.
}
if result.admit_fallback(UnknownPolicy::Reject) {
    // This admits the explicitly reported alternate behavior, such as "nop".
    // It does not admit the primary instruction semantics.
}
```

`Requirements` exposes its immutable `expression`, optional `fallback`,
`fallback_behavior` and `source`. `Expr` preserves `Feature`, `All`, `Any`,
`Not`, `If`, `Mode`, masked `FieldEq` and `Unknown` nodes. A caller can inspect
this tree or call `Requirements::evaluate(features, mode, field_lookup)` without
allocating. Feature names are exact and case sensitive. No implicit feature
implication or CPU generation expansion occurs. `FieldEq` compares a named
unsigned field after applying its mask; `None` from the lookup means unknown.
The common codec's decoded helper supplies nonnegative semantic operand values.
Arm helpers supply extracted source encoding fields. The x86 decoded helper
supplies no additional field values; a custom context can supply them through
`Requirements::evaluate` when a catalog explicitly provides such expressions.

Evaluation uses three values: `Satisfied`, `Unsatisfied`, `Unknown`. A known
false conjunct rejects even if another conjunct is unknown; a known true
alternative satisfies even if another alternative is unknown. An unknown
condition in `If` resolves only when both branches have the same result.
Unknown results require an explicit `UnknownPolicy::Reject` or `Allow` at the
admission boundary. The default Rust APIs do not silently replace unknown
metadata with an empty feature set. A missing table ID returns an unknown
requirement. The Go IR provides the same expression model, evaluation and
explicit unknown policy.

Modes are `a64`, `a32`, `thumb`, `x86_16`, `x86_32` and `x86_64`.
An empty mode is unknown. A32 and Thumb remain separate even when emitted in
the same crate. x86's `Decoded::evaluate_requirements` takes its existing `Mode`
enum; other generated helpers take a mode string. Execution mode is independent
of feature selection. This API does not model privilege traps, operating-system
state, runtime control registers, or every pseudocode execution precondition.
Unsupported source conditions remain unknown where encountered; a consumer
must perform its own execution-state and implementation checks.

Arm imports preserve feature expressions in `encodingindex.xml` rather than
splitting `A || B` into mandatory tags. `arch_variant` declarations are scoped to
the owning instruction class and encoding. Variants within one group form
alternatives; inherited page, class and encoding groups remain conjunctive. Explicit feature
metadata and recognized feature-bearing `EndOfDecode(Decode_UNDEF)` guards are
combined. Field conditions such as
`ftype == '11' && !IsFeatureImplemented(FEAT_FP16)` become a conditional
requirement rather than making FP16 mandatory for every encoding field value.
Nested statement conditions remain attached to their guards. Conditional expressions
in assignments or call arguments do not introduce statement scope. Earlier decode
guards also constrain a later NOP fallback. Unrecognized feature-bearing
pseudocode is retained as an unknown expression.
Aliases inherit their canonical encoding's requirements. Alias-local fallbacks
also require canonical admission; a canonical fallback can establish that
admission only when its nonempty behavior name matches the local fallback.
Unavailable alias targets and cycles constrain both primary and fallback
requirements to unknown unless another condition already rejects them.
Explicit `Decode_NOP` feature guards expose a
separate `nop` fallback, including its mode constraint, so hint-space behavior
cannot accidentally authorize the primary optional semantics.

x86 imports retain record-level `metadata.isa` and `extensions`. The ISA string
becomes a requirement using the source's exact ISA-class names, including boolean
expressions when present. For example, `AVX512F_128` is a source ISA class, not a
claim that a single CPUID bit named `AVX512F_128` exists. The generator does not
guess CPUID/OSXSAVE/XCR0 dependencies from an opcode family or vector width.
Consumers must map supported source ISA classes to their actual CPU and execution
context. Record extensions are retained as provenance, not silently equated with
complete hardware requirements. Missing ISA metadata remains unknown. Mode
constraints come from the existing source mode mask.

The common codec JSON model accepts explicit structured `requirements`.
Its existing `features` and named profiles continue selecting overlapping
instruction catalogs. Those profile selectors are not evidence of complete
architectural requirements. Imported TableGen `Predicates` are also retained in
`source_predicates` and become opaque unknown requirement nodes; names such as
`HasFoo` are not automatically reclassified as hardware feature names. A
specification importer can set an explicit structured requirement when it has
sufficient source evidence, including
`"requirements":{"expression":{"op":"true"}}` for a known baseline.
Absent evidence remains unknown.
