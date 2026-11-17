.text
.globl entry
.type entry,@function
entry:
  r0 = CONST32(#0x12345678)
  r1 = CONST32(#0x12345678)
  r3:2 = CONST64(#0x1122334455667788)
  {
    if (p1) call external_a
    if (!p1) call external_b
  }
.size entry,.-entry
