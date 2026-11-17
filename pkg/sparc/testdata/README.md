`llvm22-sparc.json` is a subset of genuine LLVM 22.1.8 `llvm-tblgen --dump-json`
output for `llvm/lib/Target/Sparc/Sparc.td`. It retains 21 selected source
instruction records, all InstAlias records targeting those instructions, and the
upstream register/operand records needed to interpret them. It is a source
fixture, not an independently invented instruction catalog. The full dump is
selected with `SPARC_TABLEGEN_JSON` for corpus and LLVM acceptance checks.

The source descriptions are Copyright LLVM contributors, licensed under
Apache-2.0 WITH LLVM-exception. The complete upstream license is included as
`LICENSE-LLVM.txt`.
