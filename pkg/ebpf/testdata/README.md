# LLVM BPF corpus

`llvm-22.1.8-bpf.json.gz` contains every one of the 201 BPF Instruction
records from the real LLVM 22.1.8 TableGen dump (tag `llvmorg-22.1.8`, commit
`ca7933e`), retaining each record and its fields without alteration. Non-BPF
records were removed and the Instruction instance index was restricted to those
201 records, then the JSON was compressed. This is a corpus, not hand-authored
instruction fixtures.

Source: https://github.com/llvm/llvm-project/tree/llvmorg-22.1.8/llvm/lib/Target/BPF

Generate the original dump with:

```sh
llvm-tblgen --dump-json -I llvm/include -I llvm/lib/Target/BPF \
  llvm/lib/Target/BPF/BPF.td -o bpf.json
```

The corpus has 184 machine records, 13 explicitly marked compiler pseudo
instructions, and four CO-RE operations whose opcodes are supplied by relocation
processing. The importer reports the four CO-RE operations as unsupported. NOP's
unused compiler operand is removed from its machine syntax; tied operands share
one encoding field. The 184 machine records expand into 192 forms: the LD_pseudo record is
specialized into seven source tags, and two Linux call tags are added. Both
endian layouts are checked against independent LLVM MC byte vectors and 190
LLVM-assemblable forms. NOP uses its equivalent r0 = r0 spelling for this
comparison. The two supplementary call forms are checked against UAPI bytes. BPF-to-BPF and kfunc call tags are supplemented from the Linux
BPF instruction definitions because LLVM's JAL record represents helper calls.

LLVM files are licensed under Apache-2.0 WITH LLVM-exception; see
`LLVM-LICENSE.txt`.
