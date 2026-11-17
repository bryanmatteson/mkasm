# LoongArch TableGen importer

`Parse(reader, "loongarch32")` and `Parse(reader, "loongarch64")` import resolved
LLVM TableGen JSON. Generate input with LLVM's `llvm-tblgen --dump-json`, with
the LLVM include directory and `llvm/lib/Target/LoongArch` on the include path,
using `LoongArch.td` as the input.

The adapter imports fixed-width machine instructions, including floating-point,
LSX, LASX, LVZ, LBT and optional atomic extensions. It preserves LLVM predicate
names as feature metadata and filters `IsLA32` / `IsLA64` instructions by target.
Canonical numeric register spellings and GPR/FPR ABI aliases are accepted,
including the optional literal zero displacement on atomic memory operands.
Branch target operands are absolute addresses in `Catalog.Assemble(text, pc)`;
`Catalog.Encode` accepts their signed byte displacements. JIRL's immediate is a
register-relative displacement, with four-byte alignment.

The fifteen direct `InstAlias` records (including `nop`, `ret`, `move`, and
reversed/zero-register branches) are imported as concrete encodings. LLVM's
pseudo instructions and the thirteen aliases expanding into address-loading
pseudo instructions require instruction sequence expansion and relocation and
are outside the fixed-instruction catalog. They are deliberately excluded.
Unrepresentable concrete instructions are retained in `Catalog.Unsupported`.

The checked fixture in `testdata/llvm-loongarch.json` contains selected resolved
records from LLVM tag `llvmorg-22.1.8`, commit
`ca7933e47d3a3451d81e72ac174dcb5aa28b59d1`, with unused fields removed. It is
derived from LLVM, licensed Apache-2.0 WITH LLVM-exception. The full corpus can
be validated without adding the entire LLVM source or JSON dump to this repo:

```sh
MKASM_LOONGARCH_JSON=/path/to/loongarch.json \
LLVM_MC=/path/to/llvm-mc go test ./pkg/loongarch -v
```

With LLVM 22.1.8 this imports 1,863 LA32 and 2,103 LA64 encoding/syntax entries,
including fifteen direct aliases, 52 optional-zero atomic syntax variants, and
code-generator variants of concrete instructions. The full-corpus
test independently assembles a legal sample of every imported encoding with
`llvm-mc` and compares its bytes. The ordinary tests also cover negative signed
immediates, split backward branches, scaled offsets, biased operands, register
aliases, width exclusions and invalid atomic/bitfield operands.
