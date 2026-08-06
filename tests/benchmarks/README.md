# Benchmarks

This directory contains corpus-scale benchmarks through mkasm's public API.
They use one explicit compressed corpus, downloaded or read once outside the
timed region, and never extract it.

```bash
mise run bench
mise run bench:micro
mise run bench:rust-decoder
X86_CORPUS=/path/to/x86_64.json.xz mise run bench:x86
X86_CORPUS=/path/to/x86_64.json.xz mise run bench:x86-rust
BENCHTIME=5x BENCHCOUNT=5 mise run bench
```

`mise run bench` measures:

- streaming gzip/tar load and compact IForm preparation;
- the complete Parse + Pass 1 + Pass 2 pipeline;
- the complete Rust generation pipeline, including project writes but excluding
  `cargo` compilation.

`mise run bench:micro` runs private hot-path benchmarks kept in
`pkg/arm/benchmarks_test.go`, where they can measure unexported parser routines
without expanding the production API.

`mise run bench:rust-decoder` generates the complete Rust crate, runs its tests,
then measures release-mode decode throughput over a stable mix of base A64
instructions. A counting global allocator reports allocations during the timed
loop. Override the default one million decodes with `ITERATIONS`.

`mise run bench:x86` imports the complete opcodesDB v3 catalog outside the
timed region, builds its direct prefix/map/opcode dispatcher, and measures a
stable legacy/REX/VEX/EVEX mix plus exact physical-field encoding. Both hot
paths write into caller-owned storage and report zero allocations.

`mise run bench:x86-rust` generates and tests the standalone x86 Rust crate,
then runs the same six-family decode mix in release mode with a counting global
allocator.

Override the source without changing the benchmark:

```bash
CORPUS=/path/to/ISA_A64_xml_A_profile-2026-06.tar.gz mise run bench
```

The benchmark reports allocations, compressed throughput, resolved instruction
count, and the loader's bounded peak in-flight XML buffers. Wall-clock results
should be compared on the same machine, Go version, corpus, and worker count.

## Optimization reference

The parser's structural index uses a hand-written, allocation-light XML scan;
the authoritative IForm model still uses Go's validating XML decoder. Page-level
explanations are decoded once and shared immutably, register diagrams transfer
slice ownership instead of being copied, and parser scopes allocate storage only
when a handler stores state.

The following is the median of seven one-iteration loader runs on an Apple M5
Max with Go 1.26.5 and `GOMAXPROCS=4`. Both revisions loaded the same compressed
2026-06 corpus and resolved all 4,623 encodings:

| Loader metric | Before | After | Change |
| --- | ---: | ---: | ---: |
| Time | 1.058 s | 0.832 s | -21.4% |
| Allocated bytes | 1,841,927,656 | 1,316,972,176 | -28.5% |
| Allocations | 43,879,046 | 31,941,805 | -27.2% |
| Peak in-flight XML | 8.102 MiB | 8.102 MiB | bounded |

Reproduce the controlled measurement with:

```bash
GOMAXPROCS=4 BENCHTIME=1x BENCHCOUNT=7 mise run bench
```

## Generated Rust decoder reference

The generated Rust decoder walks compact static node, edge, and leaf-candidate
tables. Fields and ambiguous matches are lazy views over the input word, so the
decode hot path does not allocate. A flat matcher remains as the correctness
fallback for tree misses.

The following is the median of five one-million-decode runs on an Apple M5 Max
with Rust 1.97.1. The before revision is `ab076b7`; both revisions used the same
2026-06 corpus and the benchmark's 13-word mix:

| Decoder metric | Linear table | Decision tree | Change |
| --- | ---: | ---: | ---: |
| Time per decode | 3,255.82 ns | 61.39 ns | 53.0x faster |
| Allocations / 1M decodes | 2,538,462 | 0 | eliminated |

Reproduce the current measurement with:

```bash
ITERATIONS=1000000 mise run bench:rust-decoder
```

## x86 codec reference

The x86 dispatcher normalizes legacy and vector prefixes once, indexes a fixed
prefix-family/map/opcode table, and checks only that bucket's mode, prefix,
ModR/M, and tail-width constraints. The measured catalog contains 7,289 syntax
forms imported from 3,509 opcodesDB encoding records.

The following is the median of five one-second runs on an Apple M5 Max with Go
1.26.5:

| Codec metric | Result |
| --- | ---: |
| Full-catalog decode | 46.35 ns/op |
| Representative exact encode | 8.50 ns/op |
| Allocations | 0 B/op, 0 allocs/op |

The generated Rust crate runs the same six-instruction full-catalog mix at a
15.09 ns/decode median across five one-million-decode runs, also with zero
timed allocations.

Reproduce it with:

```bash
X86_CORPUS=/path/to/x86_64.json.xz mise run bench:x86
```
