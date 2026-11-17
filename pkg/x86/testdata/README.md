`opcodesdb-mode-fixture.json.gz` contains 171 real ENCODING records (253 syntax
forms) selected from the opcodesDB v3 x86 corpus for MOV, LEA, ADD, XOR, INC, DEC,
LDS, LES, BOUND, jumps, calls, returns, stack operations, NOP, XCHG and VPADDD.
It preserves the source fields and operands. It exercises execution-mode and
address-size differences through the generated Rust consumer.

Source: https://github.com/MahdiSafsafi/opcodesDB
The source distribution is licensed under MIT.

The full corpus can also be imported using `MKASM_X86_OPCODESDB`; generated
`asm_check --mode=32 representatives --emit OUTPUT` exports the real decoder's
representatives, and `asm_check --mode=32 verify INPUT` verifies independent
assembler encodings supplied as tab-separated `Intel text<TAB>hex bytes`.
