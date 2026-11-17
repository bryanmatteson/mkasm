`avr.json` contains every AVR machine instruction (97) and instruction alias
(33) from LLVM 22.1.8, commit `ca7933e47d3a3451d81e72ac174dcb5aa28b59d1`, generated with:

```
llvm-tblgen --dump-json -I llvm/include -I llvm/lib/Target/AVR llvm/lib/Target/AVR/AVR.td
```

The fixture also retains all 380 Processor records, their feature implication
graph, and assembler predicates for device profile tests. Compiler pseudo
instructions and unrelated target metadata are omitted. All fields consumed by
this importer are retained. LLVM source is distributed under
Apache-2.0 WITH LLVM-exception; see https://llvm.org/LICENSE.txt.

Set `MKASM_LLVM_MC` to an AVR-capable llvm-mc executable to run independent byte
parity for every imported machine form and alias at three operand values. The
importer emits 202 forms: 97 original machine records, 14 additional pointer
addressing forms, 33 aliases, and 58 additional Tiny forms that restrict general
register operands to the physically present r16-r31. This gives 606 LLVM byte
comparisons across classic and Tiny encoding profiles.
