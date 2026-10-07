# Conformance

This directory checks generated code against independent tools at corpus
scale. It is separate from the `pkg/arm` unit tests. Encoder and decoder round
trips derived from one XML parse prove internal consistency, not architectural
truth.

| Gate | Independent oracle | Contract |
|---|---|---|
| `make coverage-encodings` | `pkg/coverage` | Go and Rust exact ledgers contain every encoding exactly once |
| `make conformance-go` | clang and LLVM MC | Every supported Go exact encoder reproduces exact bytes; rejects and mismatches fail |
| `make conformance-rust` | clang and LLVM MC | Supported typed and exact Rust encoders reproduce exact bytes; rejects and mismatches fail |
| `make conformance-disasm` | clang and LLVM MC | Every supported rendered sample reassembles to its word; PC-relative labels keep their displacement sign |
| `make conformance` | clang and LLVM MC | All three supported-instruction gates above |
| `make conformance-strict` | clang and LLVM MC | The oracle must also recognize every generated and printable encoding |
| `make conformance-asl` | Arm ASL from `mra_tools` | Opcode bits and fields agree |
| `make audit-disasm` | clang and LLVM MC | Threshold report only; not conformance |

Each target is also a mise task, with `:` in place of `-`
(`mise run conformance:strict:go`).

Every gate reads the A64 corpus from `CORPUS`. The default is Arm's current
compressed A64 XML release, and nothing is extracted. An invalid or
unavailable corpus is a hard failure.

Ordinary `go test ./...` compiles these suites but skips their expensive
external work. The targets set the activation variables and the corpus
explicitly.

Rust generation writes typed and exact integration tests under `tests/`; Go
generation writes its exact ledger under `conformance/`. The exact ledgers
contain all 4,623 resolved encodings. The typed Rust ledger contains the 4,524
unique calls the operand-typed surface supports. The gates run these generated
tests and feed every emitted word through the independent LLVM oracle. They do
not patch or add source after generation.

Toolchain overrides:

```bash
make conformance-rust MKASM_CLANG=/path/to/clang MKASM_LLVM_MC=/path/to/llvm-mc
make conformance-asl ASL=/path/to/arm-asl-parser/asl
```

Without overrides, the gates use `xcrun --find clang` or `clang` from `PATH`,
and `llvm-mc` from `PATH` or Homebrew's LLVM.

The normal LLVM gates prove byte parity over everything the installed oracle
recognizes. Unsupported instructions are listed and excluded, never counted as
passing. `make conformance-strict` also requires toolchain coverage of every
case. It answers a separate question: can this installed LLVM verify the whole
selected corpus?

The disassembler gate complements the encoder gates. It also covers printable
encodings that only have exact encoders. Use `make audit-disasm` while
developing coverage; its threshold result is deliberately not called
conformance.

## Current result

The supported-instruction gates pass against
`ISA_A64_xml_A_profile-2026-06`. The all-opcode toolchain-coverage gate fails,
so the repository does not claim independent LLVM proof for all 4,623
encodings.

Observed on 2026-10-06 with Apple clang 21.0.0 and Homebrew LLVM MC 22.1.8:

| Gate | Rendered | Byte-identical | Rejected | Unsupported by LLVM |
|---|---:|---:|---:|---:|
| Go exact ledger | 4,623 | 4,618 | 0 | 5 |
| Typed Rust calls | 4,524 | 4,523 | 0 | 1 |
| Rust exact ledger | 4,623 | 4,618 | 0 | 5 |
| Disassembly samples | 4,578 | 4,573 | 0 | 5 |

None of the cases the independent assemblers accept differs by a single byte,
and they reject no generated spelling. The unsupported cases are `HINTE` and
the four authenticated PC-relative forms `RETAASPPC`, `RETABSPPC`, `AUTIASPPC`
and `AUTIBSPPC`, which LLVM MC 22.1.8 does not recognize. They remain
unverified, so `make conformance-strict` deliberately stays red.

These numbers record the work left to do; they waive nothing. The strict gate
fails until the installed independent oracle can verify every case.
