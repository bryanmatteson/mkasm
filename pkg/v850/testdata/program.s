.text
.global _start
_start:
 prepare {r20-r22,lp},4,sp
 mov 0x12345678,r20
 mov -3,r21
.Lagain:
 add r21,r20
 cmp 0,r20
 bnz .Lstore
 add 1,r20
.Lstore:
 ld.w 8[sp],r22
 st.w r20,12[sp]
 loop r21,.Lagain
 jarl .Lsub,lp
 dispose 4,{r20-r22,lp},[lp]
.Lsub:
 add 1,r20
 jmp [lp]
