# Conformance

This directory contains corpus-scale verification against independent tools.
It is separate from `pkg/arm` unit tests because encoder/decoder round trips
derived from one XML parse prove internal consistency, not architectural truth.

| Gate | Independent oracle | Contract |
|---|---|---|
| `mise run coverage:encodings` | `pkg/coverage` | Go and Rust exact ledgers contain every encoding exactly once |
| `mise run conformance:go` | clang and LLVM MC | Every supported Go exact encoder reproduces exact bytes; rejects and mismatches fail |
| `mise run conformance:rust` | clang and LLVM MC | Supported typed and exact Rust encoders reproduce exact bytes; rejects and mismatches fail |
| `mise run conformance:disasm` | clang and LLVM MC | Every supported rendered sample reproduces exact bytes; rejects and mismatches fail |
| `mise run conformance:strict` | clang and LLVM MC | The oracle must recognize and verify every generated and printable encoding |
| `mise run conformance:asl` | Arm ASL from `mra_tools` | Opcode bits and fields agree |
| `mise run conformance:x86` | iced-x86 1.21.0 | Physical operands agree where structurally comparable and every supported Intel-format string agrees byte-for-byte |
| `mise run conformance` | clang and LLVM MC | Runs all supported-instruction LLVM byte-parity gates |
| `mise run audit:disasm` | clang and LLVM MC | Threshold report only; not conformance |

Every gate consumes the exact `CORPUS` value from `mise.toml` or the environment.
The default is Arm's current compressed A64 XML release; no extracted directory is required.
An invalid or unavailable corpus is a hard failure.

Ordinary `go test ./...` compiles these suites but skips their expensive external
work. The mise tasks set the activation flags and corpus explicitly.

The x86 oracle takes `X86_CORPUS=/path/to/x86_64.json.xz`. It is verification
only: generated crates retain no iced-x86 dependency. iced's formatter options
are explicitly pinned, and strings are compared byte-for-byte without
normalizing whitespace, aliases, case, pointer keywords, or number syntax. The
gate fails on any mkasm rejection, operand mismatch, or formatter mismatch and
prints iced-unsupported and structurally incomparable operand forms separately
instead of counting them as passing.

Rust generation writes typed and exact integration tests under `tests/`; Go
generation writes its exact ledger under `conformance/`. The exact ledgers
contain all 4,623 resolved encodings, while the typed Rust ledger contains the
4,524 unique calls supported by the operand-typed surface. The repository gates
run these generated tests and feed every emitted word through the independent
LLVM oracle. They do not patch or add source after generation.

Toolchain overrides:

```bash
MKASM_CLANG=/path/to/clang MKASM_LLVM_MC=/path/to/llvm-mc mise run conformance:rust
ASL=/path/to/arm-asl-parser/asl mise run conformance:asl
```

The normal LLVM gates prove byte parity over the complete subset the installed
oracle recognizes. Unsupported instructions are listed and excluded, never
counted as passing. `mise run conformance:strict` additionally requires
toolchain coverage of every case and therefore answers the separate question
“can this installed LLVM verify the entire selected corpus?”

The disassembler gate is complementary: it includes printable exact-only
encodings. Use `mise run audit:disasm` when developing coverage; its
threshold-based result is intentionally not labeled conformance.

## Current result

The supported-instruction gates are green against
`ISA_A64_xml_A_profile-2026-06.tar.gz`. The all-opcode toolchain-coverage gate
is red, so the repository does not claim independent LLVM proof for all 4,623
encodings.

Observed on 2026-07-26 with Apple clang 21.0.0 and Homebrew LLVM MC 22.1.8:

- Go exact ledger coverage and rendering: 4,623/4,623; LLVM accepted and
  verified 4,618 byte-identically, rejected 0, and did not support 5;
- typed Rust rendering: 4,524/4,524 calls; LLVM accepted and verified 4,523
  byte-identically, rejected 0, and did not support 1;
- Rust exact ledger coverage and rendering: 4,623/4,623; LLVM accepted and
  verified 4,618 byte-identically, rejected 0, and did not support 5;
- disassembly audit: 4,562 samples rendered; LLVM accepted and verified all
  4,557 toolchain-supported samples byte-identically, rejected 0, and did not
  support 5.

There are zero byte mismatches among cases accepted by the independent
assemblers and no generated spelling is rejected. The remaining unsupported
cases are `HINTE` and four authenticated PC-relative forms that LLVM MC 22.1.8
does not recognize; they remain unverified, so `mise run conformance:strict`
intentionally remains red.

These numbers are a work ledger, not a waiver. The strict task fails until the
installed independent oracle can verify every case.
