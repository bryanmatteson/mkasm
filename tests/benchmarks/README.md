# Benchmarks

This directory contains corpus-scale benchmarks through mkasm's public API.
They use one explicit compressed corpus, downloaded or read once outside the
timed region, and never extract it.

```bash
mise run bench
mise run bench:micro
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
