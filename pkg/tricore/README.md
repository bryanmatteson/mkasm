# TriCore and PCP instruction codecs

`Parse(reader, "tricore")` imports the actual Ghidra TriCore SLEIGH source.
`Parse(reader, "tricore-pcp")` imports the separate Peripheral Control Processor
instruction stream. A nil reader uses the bundled source. A non-nil reader may
supply `tricore.sinc`, or that file concatenated with `tricore.pcp.sinc`; the PCP
import appends the bundled PCP include when it is absent. The importer reads
instruction constructors, token fields, register attachments, operand
subtables, relocation expressions, and revision predicates from that source.
It does not parse a hand-maintained instruction fixture.

The returned `Catalog` embeds `*codec.Catalog`: exact structured encoding,
stream decoding with consumed length, address-aware formatting and text
assembly use the common model. `GenerateRust` emits a standalone crate with
those APIs plus `Template::parse_at`, named bindings, repeated binding checks,
and wildcards. Generated crates carry Ghidra's license, notice, and source pin
in `UPSTREAM-LICENSE`; the runtime implementation has its own generated license.

The CPU uses little-endian 16-bit and 32-bit encodings. Its low opcode bit
selects the length. PCP is a separate context and has its own framing; callers
must select the appropriate target. Register classes preserve `d0`–`d15`,
`a0`–`a15`, even `e`/`p` pairs, explicitly displayed pairs such as `d4/d5`, and
circular/index/bit-reversed addressing. Scalar values preserve signed and split
fields, power-of-two scales, backward-only short loops, the V2 short-branch
bias, sparse absolute addresses, and 32-bit relative target wrapping. Invalid
pair indices, alignment gaps, field overflow, and truncated encodings are
rejected. Signed immediate text uses its mathematical signed range.

Use `FeatureSets["v2"]`, `FeatureSets["rider-d"]`, or
`FeatureSets["rider-b"]` with `DecodeWithFeatures`/`AssembleWithFeatures`.
`FeatureSets["default"]` selects V2; PCP has the `pcp` profile. The unfiltered
shared APIs admit the union of imported profiles. These profiles follow the
source's `TRICORE_V2`, `TRICORE_RIDER_D`, and `TRICORE_RIDER_B` predicates.
Ghidra's packaged `tc172x`, `tc176x`, and `tc29x` language IDs all use the same
V2 SLA and differ in processor metadata, so those names are not presented as
independent instruction-set filters.

The complete pinned source imports without unsupported instruction records:

| Target/profile | Active instruction constructors | Expanded source forms | Final codec forms |
| --- | ---: | ---: | ---: |
| TriCore V2 | 768 | 874 | 1,292 |
| TriCore Rider-D | 730 | 822 | 1,194 |
| TriCore Rider-B | 700 | 792 | 907 |
| PCP | 66 | 308 | 308 |

The CPU catalog has 3,393 forms across its three revision profiles. Source
subtables expand addressing modes and literal conditions. SLEIGH also gives
specific constructors precedence over broader ones: generic `cop` regions
contain defined FPU instructions, and `ji a11` is a return alias. The importer
subtracts those regions from the broad forms into disjoint bit patterns. This
preserves the same priority in exact encoding, text assembly, and templates,
instead of admitting a `cop` spelling for bytes reserved by `pack` or another
defined instruction. Partitioning explains the difference between expanded
source forms and final codec forms.

The importer models instruction encodings and source control-flow metadata.
It does not execute P-code, simulate the CPU/PCP, resolve object relocations, or
claim instructions absent from this upstream source. Upstream TODOs in execution
semantics remain upstream TODOs; they do not supply invented instruction forms.

## Source and attribution

Bundled files are unchanged from Ghidra commit
`42db038f3c88c6bd7e9bedbb919138111f8b77fd`:

- [TriCore source directory](https://github.com/NationalSecurityAgency/ghidra/tree/42db038f3c88c6bd7e9bedbb919138111f8b77fd/Ghidra/Processors/tricore/data/languages)
- `data/tricore.sinc`, SHA-256 `d184686bf1092ad6bb799102d6ed64b1c8ced07d8b8b4448ac54c939b5e9ccca`
- `data/tricore.pcp.sinc`, SHA-256 `70f47e558faf70902bde5dcb50ee2292193ff01995d0c6dc2b980ab4c4a03524`
- Ghidra's Apache 2.0 license and NOTICE are retained in `data/`.

## Validation

`go test ./pkg/tricore` checks source coverage for every active constructor,
structured and textual round trips across every final form, four operand samples
per form (ordinary, zero, maximum, and sign boundary), revision filtering,
source priority, malformed source, invalid operands, 32-bit target wrapping,
and a meaningful mixed-length store/load/compare/branch instruction sequence.

An optional independent Ghidra 12.1.2 oracle compiles three separate SLAs from
the pinned source with Ghidra's native SLEIGH compiler, then checks encoding,
disassembly text, instruction length, and flow metadata for every sample in
each matching revision. PCP requests set `PCPMode=1` for both directions.
Assembly may choose a shorter equivalent form; its chosen bytes must be among
the codec's results for that profile. The oracle never substitutes a V2 language
for a Rider revision. It requires an installed Ghidra and supported JDK.

```sh
MKASM_TRICORE_GHIDRA=1 \
MKASM_TRICORE_ARTIFACT="$HOME/Documents/Developer/go-mkasm/architecture-expansion/tricore/oracle" \
go test ./pkg/tricore -run TestIndependentGhidra -v
```

Set `MKASM_GHIDRA_HOME` to override `~/Ghidra`. Requests, responses, the independent
compiled SLAs, source files, and compiler logs are retained beneath the artifact
directory. Four samples across all 3,701 CPU/PCP forms produce 14,804 samples and
29,608 assembly/decode responses.

The standalone Rust test compiles both generated crates and invokes their public
APIs from separate integration tests. It covers exact encoders, caller-owned
buffers, structured decoding, text assembly/formatting, profiles, named and
repeated template bindings, wildcards, branch displacement bindings, malformed
input, and the same Ghidra-derived instruction sequence. Generated unit tests
also round-trip every imported form.

```sh
MKASM_TRICORE_RUST=1 \
MKASM_TRICORE_ARTIFACT="$HOME/Documents/Developer/go-mkasm/architecture-expansion/tricore/generated" \
go test ./pkg/tricore -run TestGeneratedRustConsumer -v
```
