# LLVM SystemZ corpus

`llvm-22.1.8-systemz.json.gz` retains the complete instruction corpus from
LLVM `llvmorg-22.1.8`, commit
`ca7933e47d3a3451d81e72ac174dcb5aa28b59d1` (the release checkout identifies
the commit with the prefix `ca7933e`). The input was generated with:

```sh
llvm-tblgen --dump-json \
  -I llvm/include -I llvm/lib/Target/SystemZ \
  llvm/lib/Target/SystemZ/SystemZ.td
```

The compressed fixture preserves original JSON records and their fields for
every SystemZ Instruction, every InstAlias, every processor model and facility,
and their operand, register-class, and address dependencies. Unrelated target
infrastructure records are omitted to keep the retained source small. The
`!instanceof` indexes retain all 2,976 Instruction records, all 52 InstAlias
records, all 49 SystemZFeature records, and all 17 ProcessorModel records.
It is source data, without generated expected instruction bytes. The optional
full-dump test verifies that filtering leaves the resulting catalog identical.

LLVM's Apache 2.0 license with LLVM exceptions is retained in
`LLVM-LICENSE.txt`. The upstream sources are available at
<https://github.com/llvm/llvm-project/tree/llvmorg-22.1.8/llvm/lib/Target/SystemZ>.
