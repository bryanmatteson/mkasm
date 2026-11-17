# PowerPC TableGen adapter

`Parse(reader, architecture)` imports resolved LLVM `PPC.td --dump-json` output for
`powerpc32`, `powerpc64`, `powerpc32le`, and `powerpc64le`. It returns the common
`codec.Catalog` used by JSON export, Go assembly/disassembly and generated Rust.

The adapter handles PowerPC's MSB-first TableGen fields, 4-byte instructions and
8-byte prefix/suffix instructions, word-local little endian order, signed and
scaled displacements, PC-relative branches, split SPR/VSX fields, register pairs,
condition masks, and GNU addis/lis immediate truncation. It resolves the full
InstAlias corpus, including nested condition predicates, repeated register fields,
tied operands and fixed-register aliases. LLVM's extension predicates remain on
each encoding for explicit feature selection through the common catalog API.

Source records that expand during compiler emission are excluded. A catalog's
`Unsupported` list identifies remaining source forms, including TLS operands
that require relocation/symbol context rather than a standalone instruction.

Source forms whose LLVM printer cannot preserve physical identity have explicit
`enc[SourceID]` spellings. These retain every original encoded operand in the
structured API and ordinary text/template APIs:

- Composite-predicate branches expose `BIBO` and `CR`, for example
  `enc[BCC] 76, cr2, 0x100`. The low five `BIBO` bits encode BO; its upper two
  bits combine with `CR` to encode BI. All eleven source records, including
  `CTRL_DEP` and the 64-bit CTR variants, retain their original fields and modes.
- `enc[MFTB] mftb 3, 268` and the three exact source aliases preserve historical
  XO=371. Ordinary `mftb`/`mftbl`/`mftbu` assembly uses MFSPR XO=339, matching
  LLVM's `FeatureMFTB` lowering on modern CPUs. The native oracle uses CPU `601`
  for the legacy encoding; `PPCAsmParser.cpp` otherwise rewrites its opcode.
- `enc[EVFSCTUF] 1, 2`, `enc[EVFSCTUIZ] 1, 2`, and
  `enc[EVSEL] 1, 2, 3, cr4` preserve real SPE instructions whose source
  `PPCInstrSPE.td` AsmStrings contain signed-conversion mnemonic typos or literal
  `crD`. Independent LLVM disassembly checks their exact named MCInst, every
  decoded register, and re-emitted bytes; its ordinary parser cannot express
  these instructions faithfully.
- `enc[TAILBA] 0x100` and `enc[TAILBA8] 0x100` use the physical relative branch
  target. Their `PPCInstrInfo.td`/`PPCInstr64Bit.td` source records instantiate
  `IForm<18,0,0>` (AA=0), despite printing `ba` and declaring `abscalltarget`.
  Ordinary `ba` retains its absolute address semantics.

The pinned fixture retains all instruction and alias records plus their operand
and register dependencies. `go test ./pkg/powerpc` always exercises it. Set
`LLVM_MC` to an LLVM 22.1.8 `llvm-mc` executable to enable independent whole-corpus
parity in all four architecture modes. Every imported form has positive and,
where applicable, negative operand samples, with local assembly/formatting and
decoding checks before independent byte comparison. `MKASM_POWERPC_TABLEGEN_JSON`
selects a fresh complete dump; `MKASM_POWERPC_PARITY_DIR` writes per-mode results.

The LLVM oracle renders branch operands as parenthesized signed encoding
immediates. LLVM's relative-branch syntax denotes a displacement, whereas the
catalog's formatted text denotes the resolved target address. In particular,
32-bit negative targets remain wrapped addresses such as `0xfffffffc` in the
public catalog API; LLVM conditional-branch predicates require the corresponding
signed immediate `(-4)`. Parentheses also prevent LLVM's PowerPC lexer from
interpreting a leading minus as a branch prediction hint. Both dialects are
checked against the same bytes without changing target-width or alias semantics.
