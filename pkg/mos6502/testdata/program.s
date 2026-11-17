.setcpu "65SC02"
.segment "CODE"
_start:
 ldx #$ff
 txs
 stz $20
 ldx #10
loop:
 txa
 clc
 adc $20
 sta $20
 dex
 bne loop
 jsr twice
 cmp #110
 bne failure
 phx
 inx
 plx
 cpx #0
 bne failure
 lda #$ff
 inc a
 bne failure
 bra success
failure:
 lda #1
 jmp $fff9
success:
 lda #0
 jmp $fff9
 twice:
 lda $20
 asl a
 rts
