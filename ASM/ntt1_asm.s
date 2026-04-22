; -----------------------------------------------------------------------------
; ntt1_asm.s
;
; Port of pqm3 crypto_sign/dilithium2/m3/ntt1_asm.S (GNU `as`, Thumb-2
; UAL) to ARM Compiler v5.06 `armasm` syntax, targeting an SC300
; (Cortex-M3 / ARMv7-M) core.  Dilithium forward NTT using schoolbook
; 32x32 multiplication built from MUL/MLA (no SMULL).
;
; Register binding (inline-expanded from the original .req table):
;   r0  = ptr_p     r1  = ptr_zeta   r2  = qinv     r3  = qh
;   r4  = cntr      r5  = pol0       r6  = pol1_h   r7  = pol1_l
;   r8  = ql        r9  = temp_h     r10 = temp_l
;   r11 = zeta_h    r12 = zeta_l     r14 = temp
;
; Source upstream: https://github.com/mupq/pqm3
; -----------------------------------------------------------------------------

        PRESERVE8
        THUMB

; Global counter reused by each WHILE/WEND replacement of the original
; `.rept N` blocks (levels 2 and 3).
        GBLA    count

        AREA    |.text|, CODE, READONLY

; -----------------------------------------------------------------------------
; Schoolbook 32x32 multiply with accumulate into {acc1:acc0}.
; -----------------------------------------------------------------------------
        MACRO
        const_mul32_acc $acc0, $acc1, $a0, $a1, $b0, $b1, $tmp
        mul     $tmp, $a0, $b0
        adds    $acc0, $acc0, $tmp
        mul     $tmp, $a1, $b1
        adc     $acc1, $acc1, $tmp
        mul     $tmp, $a1, $b0
        mla     $tmp, $a0, $b1, $tmp
        adds    $acc0, $acc0, $tmp, lsl #16
        adc    $acc1, $acc1, $tmp, asr #16
        MEND

; -----------------------------------------------------------------------------
; Schoolbook 32x32 multiply into {c1:c0}.
; -----------------------------------------------------------------------------
        MACRO
        const_mul32 $c0, $c1, $a0, $a1, $b0, $b1, $tmp
        mul     $c0, $a0, $b0
        mul     $c1, $a1, $b1
        mul     $tmp, $a1, $b0
        mla     $tmp, $a0, $b1, $tmp
        adds    $c0, $c0, $tmp, lsl #16
        adc    $c1, $c1, $tmp, asr #16
        MEND

; -----------------------------------------------------------------------------
; Constant-time Cooley-Tukey butterfly with Montgomery reduction using
; schoolbook multiplication.
; -----------------------------------------------------------------------------
        MACRO
        ct_butterfly_montg_const $pol0, $pol1_l, $pol1_h, $zeta_l, $zeta_h, $ql, $qh, $qinv, $th, $tl, $tmp
        const_mul32 $tl, $th, $pol1_l, $pol1_h, $zeta_l, $zeta_h, $tmp
        mul     $pol1_h, $tl, $qinv
        ubfx    $pol1_l, $pol1_h, #0, #16
        asr     $pol1_h, $pol1_h, #16
        const_mul32_acc $tl, $th, $pol1_l, $pol1_h, $ql, $qh, $tmp
        sub     $pol1_l, $pol0, $th
        add.w   $pol0, $pol0, $th
        MEND

; -----------------------------------------------------------------------------
; Load, butterfly, store one coefficient pair at stride `const`; advance
; ptr_p by 4 + `incr` after writing pol0 back.
; -----------------------------------------------------------------------------
        MACRO
        wrap_butterfly $const, $incr
        ldr.w   r5, [r0]                                 ; pol0
        ldrh.w  r7, [r0, #$const]                        ; pol1_l
        ldrsh.w r6, [r0, #($const)+2]                    ; pol1_h
        ct_butterfly_montg_const r5, r7, r6, r12, r11, r8, r3, r2, r9, r10, r14
        str.w   r5, [r0], #4+($incr)
        str.w   r7, [r0, #($const)-($incr)-4]
        MEND

; -----------------------------------------------------------------------------
; Load the next two zeta halves (low then high) from ptr_zeta.
; -----------------------------------------------------------------------------
        MACRO
        load_zeta
        ldrh.w  r12, [r1], #2                            ; zeta_l
        ldrh.w  r11, [r1], #2                            ; zeta_h
        MEND

; =============================================================================
; void ntt_asm_schoolbook(int32_t p[N], const uint32_t zetas_asm[N]);
; =============================================================================
        ALIGN   4
        EXPORT  ntt_asm_schoolbook
ntt_asm_schoolbook PROC
        push    {r4-r11, r14}

        ; qinv = 0xFC7FDFFF
        movw    r2, #0xDFFF
        movt    r2, #0xFC7F
        ; ql = 0xE001, qh = 0x7F  (q = 8380417 split as 16|16)
        movw    r8, #0xE001
        movw    r3, #0x7F

        add     r1, #4                                    ; &zeta[1]

        ; --------------------------------------------------------------
        ;  Level 7-4 iterate inside blocks
        ; --------------------------------------------------------------
        ; level 7
        movw    r4, #128
        load_zeta
ntt_sch_level_7
        wrap_butterfly 512, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_7
        sub     r0, #512

        ; level 6
        movw    r4, #64
        load_zeta
ntt_sch_level_6_1
        wrap_butterfly 256, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_6_1
        add     r0, #256

        movw    r4, #64
        load_zeta
ntt_sch_level_6_2
        wrap_butterfly 256, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_6_2
        sub     r0, #768

        ; level 5
        movw    r4, #32
        load_zeta
ntt_sch_level_5_1
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_5_1
        add     r0, #128

        movw    r4, #32
        load_zeta
ntt_sch_level_5_2
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_5_2
        add     r0, #128

        movw    r4, #32
        load_zeta
ntt_sch_level_5_3
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_5_3
        add     r0, #128

        movw    r4, #32
        load_zeta
ntt_sch_level_5_4
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_5_4
        sub     r0, #896

        ; level 4 (eight groups of 16)
        movw    r4, #16
        load_zeta
ntt_sch_level_4_1
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_1
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_2
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_2
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_3
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_3
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_4
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_4
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_5
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_5
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_6
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_6
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_7
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_7
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_8
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_8
        sub     r0, #960

        ; --------------------------------------------------------------
        ;  Level 3-0 iterate over blocks
        ; --------------------------------------------------------------

        ; level 3 — unrolled 7 times, then one "+incr" to skip the block
        movw    r4, #16
ntt_sch_level_3
        load_zeta
count   SETA    0
        WHILE   count < 7
        wrap_butterfly 32, 0
count   SETA    count + 1
        WEND
        wrap_butterfly 32, 32
        subs.w  r4, #1
        bne.w   ntt_sch_level_3
        sub     r0, #1024

        ; level 2 — unrolled 3 times, then one "+incr"
        movw    r4, #32
ntt_sch_level_2
        load_zeta
count   SETA    0
        WHILE   count < 3
        wrap_butterfly 16, 0
count   SETA    count + 1
        WEND
        wrap_butterfly 16, 16
        subs.w  r4, #1
        bne.w   ntt_sch_level_2
        sub     r0, #1024

        ; level 1
        movw    r4, #64
ntt_sch_level_1
        load_zeta
        wrap_butterfly 8, 0
        wrap_butterfly 8, 8
        subs.n  r4, #1
        bne.n   ntt_sch_level_1
        sub     r0, #1024

        ; level 0
        movw    r4, #128
ntt_sch_level_0
        load_zeta
        wrap_butterfly 4, 4
        subs.n  r4, #1
        bne.n   ntt_sch_level_0

        pop     {r4-r11, pc}
        ENDP

        END
