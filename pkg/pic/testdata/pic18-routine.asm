        processor 18f4520
        radix hex
        org 0
        movlw 5
        movwf 20,0
loop:   decfsz 20,1,0
        bra loop
        call finish,0
        lfsr 0,123
finish: return 0
        end
