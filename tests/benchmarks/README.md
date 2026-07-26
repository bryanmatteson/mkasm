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
