# mkasm

`mkasm` is a streaming Arm A64 instruction-set parser and Go/Rust code
generator. It reads Arm's XML corpus from a directory, tarball, stdin, or URL,
resolves the instruction model, and emits standalone assembler and decoder
projects.

The implementation favors explicit data flow, bounded memory, hand-written
parsers, deterministic output, and independent verification over generated
framework machinery.

## Status

Using `ISA_A64_xml_A_profile-2026-06.tar.gz`:

| Stage | Current result |
|---|---:|
| Index parse | 4,334 canonical encodings + 291 aliases |
| IForm resolution | 4,623 / 4,623 |
| Go unit, vet, and generated-project checks | Passing |
| Rust generated-project checks | Passing |
| Independent LLVM parity for supported instructions | 100%; zero mismatches |
| Strict all-instruction LLVM parity | Open; 5 LLVM-unknown encodings |

Every encoding recognized by the installed LLVM oracle is byte-identical. Five
newer encodings are not recognized by that toolchain and remain explicitly
unverified; the strict gate stays red until an independent oracle accepts them.
Current results and toolchain versions are recorded in
[`tests/conformance`](tests/conformance/README.md).

## Quick start

Requires Go 1.24.2 or newer.

```bash
go install github.com/bryanmatteson/mkasm/cmd/mkasm@latest

CORPUS='https://developer.arm.com/-/cdn-downloads/permalink/Exploration-Tools-A64-ISA/ISA_A64/ISA_A64_xml_A_profile-2026-06.tar.gz'

# Generate a standalone Rust crate.
mkasm --codegen rust --output ./output-rs "$CORPUS"

# Emit deterministic IR JSON.
mkasm --json "$CORPUS" > arm-ir.json
```

From a source checkout:

```bash
go run ./cmd/mkasm --codegen go --output ./output "$CORPUS"
```

## CLI contract

```text
mkasm --codegen rust --output DIR INPUT
mkasm --codegen go   --output DIR INPUT
mkasm --json INPUT
mkasm --version
mkasm --help
```

`INPUT` may be:

- an extracted ISA XML directory;
- a `.tar` or `.tar.gz` filepath;
- an HTTP(S) URL;
- `-`, for a tar stream on stdin.

Progress and statistics are written to stderr. JSON mode writes only JSON to
stdout. Code generation writes only below `--output` and leaves stdout empty.
Invalid flag combinations exit with status 2; input, parse, validation, or
generation failures exit with status 1. Running `mkasm` without arguments,
`mkasm -h`, or `mkasm --help` prints the complete help screen to stdout.

## Architecture

```text
directory | tar | gzip | URL | stdin
                  |
          bounded corpus loader
                  |
       Pass 1: encoding index
                  |
       Pass 2: parallel IForms
                  |
         resolved A64 IR
             /         \
      JSON export    Pass 3 codegen
                       /      \
                     Go       Rust
```

The compressed-corpus path is one pass:

- gzip and tar are read sequentially; no extraction directory is created;
- XML members are parsed by a bounded worker pool;
- reusable power-of-two slabs bound queued expanded XML;
- compact parsed IForms are retained instead of raw instruction pages;
- `encodingindex.xml` is released after Pass 1;
- per-member and total expanded-size limits reject malformed archives.

Arm release bundles may include both the previous and current corpus. For named
archives, `mkasm` selects the dated root named by the archive and avoids
preparing the older release. For stdin, it selects the unique newest root only
when all roots belong to one dated product series. Unrelated roots remain an
error rather than being merged.

The similarly named `AARCHMRS_A_profile-2026-06_mc.tar.gz` contains feature
metadata, not instruction XML, and is rejected with a specific diagnostic.

## Generated projects

Go output contains:

```text
output/
  LICENSE
  go.mod
  encoders/     typed, exact, and checked-field encoding
  decoders/     decision-tree decode and generated tests
  registry/     lookup by encoding ID and mnemonic
  conformance/  all-encoding external-oracle ledger
```

Rust output contains:

```text
output-rs/
  LICENSE
  Cargo.toml
  src/
    asm_support.rs
    insns.rs
    encodings.rs
    raw.rs
    decoders.rs
    encoders.rs
    registry.rs
    insns_test.rs
  tests/
    conformance.rs        typed-call ledger consumed by the LLVM oracle
    exact_conformance.rs  all-encoding ledger consumed by the LLVM oracle
```

Generated project directories are verification products and are not committed.

## Verification

The default repository gate is deterministic and self-contained:

```bash
mise run verify
```

Additional explicit gates:

```bash
mise run build
mise run bench
mise run bench:micro
mise run generate:go
mise run generate:rust

mise run coverage:encodings
mise run conformance
mise run conformance:go
mise run conformance:rust
mise run conformance:disasm
mise run conformance:strict
ASL=/path/to/arm-asl-parser/asl mise run conformance:asl
```

Before tagging a release, run the complete supported-toolchain gate:

```bash
mise run release:check
VERSION=v0.1.0 mise run build
./dist/mkasm --version
```

`mise run build` produces a stripped, path-trimmed binary plus a versioned
`.tar.gz` containing `mkasm`, `LICENSE`, and `README.md`, with a SHA-256 checksum
beside it under `dist/`. `VERSION` is embedded in release builds; without it,
the task uses `git describe` so local artifacts remain identifiable. Set
`GOOS` and `GOARCH` to package another Go target.

`mise run conformance` proves byte identity for every instruction recognized by
the installed LLVM oracle and fails on any rejected spelling or byte mismatch.
Unsupported instructions remain visible and unverified. The separate
`mise run conformance:strict` gate also requires LLVM to recognize every
generated and printable encoding; it currently fails on the documented five
LLVM-unknown encodings. `mise run audit:disasm` is a separately named coverage
threshold report and is not presented as conformance.

`mise run coverage:encodings` proves that the Go and Rust exact ledgers each
contain every resolved encoding exactly once. Source statement coverage is a
separate `mise run coverage:source` regression metric; the two numbers are not
conflated. Current source coverage is 49.7% overall; `coverage:source` separately
holds the focused `pkg/coverage` package at 100%.

Benchmark methodology is documented in
[`tests/benchmarks`](tests/benchmarks/README.md). Independent-oracle contracts
and current results are documented in
[`tests/conformance`](tests/conformance/README.md).

## Repository map

| Path | Responsibility |
|---|---|
| [`cmd/mkasm`](cmd/mkasm) | Public CLI and JSON export |
| [`pkg/arm`](pkg/arm) | Corpus loading, orchestration, IForm parsing, code generation |
| [`pkg/parse`](pkg/parse) | Streaming XML event engine |
| [`pkg/ir`](pkg/ir) | Architecture-neutral instruction and bit-field model |
| [`pkg/decoder`](pkg/decoder) | Decoder-tree construction and matching |
| [`pkg/asl`](pkg/asl) | Hand-written parser for independent Arm ASL evidence |
| [`pkg/coverage`](pkg/coverage) | Exact expected-versus-emitted encoding coverage |
| [`templates`](templates) | Embedded Go and Rust project templates |
| [`tests/benchmarks`](tests/benchmarks) | Public corpus-scale benchmarks |
| [`tests/conformance`](tests/conformance) | External LLVM and ASL verification |

## Scope

`mkasm` targets A64 XML and deterministic assembler/decoder generation. It does
not execute architecture pseudocode cycle-for-cycle, replace an architectural
simulator, or treat internal encoder/decoder round trips as independent proof.
Arm's corpus is downloaded or supplied by the user and is not redistributed by
this repository.

## License

MIT. Generated Go modules and Rust crates receive the same license.
