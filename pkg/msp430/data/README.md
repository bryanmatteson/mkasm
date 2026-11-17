# MSP430 machine descriptions

`llvm22-msp430.json` retains the unmodified resolved records of the complete
MSP430 target instruction corpus from LLVM `llvmorg-22.1.8`, commit
`ca7933e47d3a3451d81e72ac174dcb5aa28b59d1` (the release tag is authoritative).
It contains all 343 records in the MSP430 instruction namespace, all 57 target
`InstAlias` records, and their operand/register dependencies, totaling 444
records plus `!instanceof`. Generic LLVM target-independent pseudo records are
omitted. It was extracted from the real `llvm-tblgen --dump-json` output of
`llvm/lib/Target/MSP430/MSP430.td`; record fields and bit arrays are preserved.
The importer accepts the original full dump as well as this target-only dump.
LLVM is licensed under Apache-2.0 WITH LLVM-exception; see
[LICENSE-LLVM.txt](LICENSE-LLVM.txt).

`TI430Common.sinc` and `TI430X.sinc` are exact Ghidra source files from
`Ghidra/Processors/TI_MSP430/data/languages/` at commit
`68270ac6d9fb523574fc36470b4ea2e0aee210eb`. They are licensed under Apache-2.0;
see [LICENSE-Ghidra.txt](LICENSE-Ghidra.txt). The original source is available at
[NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra/tree/68270ac6d9fb523574fc36470b4ea2e0aee210eb/Ghidra/Processors/TI_MSP430/data/languages).
The classic supplement reads the actual PUSH/POP addressing constructors;
the extended importer reads instruction constructors and token bit fields.

The importer corrects two source-description defects against independent
hardware documentation and GNU binutils: `imm_0_4` is a four-bit field despite
its five-bit Ghidra token declaration; single-operand extension high address
bits occupy bits7:10. CALLA symbolic addressing has a 20-bit displacement.
Read/modify/write immediate encodings described by Ghidra and accepted by GNU
are retained even where LLVM omits them. Register repetition is restricted to
As=0, and Ad=0 for Format I, as required by TI register-mode extension words;
GNU also accepts spellings that violate this hardware mode restriction.
For symbolic operands, the PC base is the addressed displacement word, including
the distinct source and destination words. The TI
[CPUX guide SLAU391F](https://www.ti.com/lit/ug/slau391f/slau391f.pdf), sections
1.4.3.1–1.4.3.3, specifies classic lower/upper-memory wrap behavior and extended
symbolic addressing. The
[MSP430FR guide SLAU367P](https://www.ti.com/lit/ug/slau367p/slau367p.pdf),
section4.4.3.3, supplies the two-symbolic-operands byte test.

The independent oracle is GNU binutils2.44, built with target `msp430-elf`.
Set `MSP430_AS` and `MSP430_LD` to its assembler and linker, and optionally
`MKASM_MSP430_AUDIT_ARCH=msp430x`, to run the complete encoding-form audit.
`MKASM_MSP430_TABLEGEN_JSON` selects an original full LLVM dump. The audit
spells equivalent underlying instructions when GNU chooses a different alias
encoding, uses CPU430X to retain short PUSH constants affected by classic CPU4,
and compensates for GNU2.44 extended PC-relative relocation addends that are
based at the prefix/opcode rather than the hardware displacement-word PC.
CPUX classic symbolic RLA/RLC aliases are assembly-only. Their two physical
displacement targets must agree at the actual instruction address, including
the special case where the source and destination PC bases straddle64KB.
Canonical ADD/ADDC decoding preserves both targets.

These adaptations preserve independently assembled opcode/operand bytes; the
TI example separately checks actual symbolic target semantics.

SHA-256:

- `llvm22-msp430.json`: `ed0633e9a87bd2377de8162d709fc3dbf0828957fb5390f889d56ef1324190de`
- `TI430Common.sinc`: `6b7276dbaedf447e78dcbf62814242c464a4a7612ff3080b30eae1a604492ee8`
- `TI430X.sinc`: `4c0e880b8c509214c97e490c223dfab5aafff68342359130f1edd236051c7912`
