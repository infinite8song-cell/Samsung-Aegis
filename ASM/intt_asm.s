; -----------------------------------------------------------------------------
; intt_asm.s
;
; Port of pqm3 crypto_sign/dilithium2/m3/intt_asm.S (GNU `as`, Thumb-2
; UAL) to ARM Compiler v5.06 `armasm` syntax, targeting an SC300
; (Cortex-M3 / ARMv7-M) core.  Dilithium inverse NTT using schoolbook
; 32x32 multiplication built from MUL/MLA (no SMULL).
;
; Register binding (inline-expanded from the original .req table):
;   r0  = ptr_p     r1  = ptr_zeta (and later rebinds as `f` after level 7
;                                   zetas are loaded)
;   r2  = qinv      r3  = ql        r4  = cntr     r5  = pol0
;   r6  = pol1      r7  = qh        r8  = temp_1   r9  = temp_2
;   r10 = temp_3    r11 = zeta_l    r12 = zeta_h   r14 = temp_q
;
; Source upstream: https://github.com/mupq/pqm3
; -----------------------------------------------------------------------------

        PRESERVE8
        THUMB

        GBLA    count

        AREA    |.text|, CODE, READONLY

; -----------------------------------------------------------------------------
; Schoolbook 32x32 multiply-accumulate into {acc1:acc0}.
; -----------------------------------------------------------------------------
        MACRO
        const_mul32_acc $acc0, $acc1, $a0, $a1, $b0, $b1, $tmp
        mul.w   $tmp, $a0, $b0
        adds.w  $acc0, $acc0, $tmp
        mul.w   $tmp, $a1, $b1
        adc.w   $acc1, $acc1, $tmp
        mul.w   $tmp, $a1, $b0
        mla.w   $tmp, $a0, $b1, $tmp
        adds.w  $acc0, $acc0, $tmp, lsl #16
        adc.w   $acc1, $acc1, $tmp, asr #16
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
        adc     $c1, $c1, $tmp, asr #16
        MEND

; -----------------------------------------------------------------------------
; Schoolbook 32x16 multiply into {c1:c0}  (b1 = 0 optimization).
; -----------------------------------------------------------------------------
        MACRO
        const_mul32x16 $c0, $c1, $a0, $a1, $b0, $tmp
        mul     $c0, $a0, $b0
        mul     $tmp, $a1, $b0
        movw    $c1, #0
        adds    $c0, $c0, $tmp, lsl #16
        adc     $c1, $c1, $tmp, asr #16
        MEND

; -----------------------------------------------------------------------------
; Gentleman-Sande butterfly with Montgomery reduction (schoolbook mult).
; -----------------------------------------------------------------------------
        MACRO
        gs_butterfly_montg $pol0, $pol1, $zeta_l, $zeta_h, $ql, $qh, $qinv, $tmp1, $tmp2, $tmp3, $tmp_q
        sub     $tmp1, $pol0, $pol1
        add.w   $pol0, $pol0, $pol1
        ubfx    $tmp3, $tmp1, #0, #16               ; low16(tmp1)
        asr     $tmp1, $tmp1, #16                   ; high16(tmp1)
        const_mul32 $tmp2, $pol1, $tmp3, $tmp1, $zeta_l, $zeta_h, $tmp_q
        mul     $tmp1, $tmp2, $qinv
        ubfx    $tmp3, $tmp1, #0, #16
        asr     $tmp1, $tmp1, #16
        const_mul32_acc $tmp2, $pol1, $tmp3, $tmp1, $ql, $qh, $tmp_q
        MEND

; -----------------------------------------------------------------------------
; Standalone Montgomery reduction of a 32-bit value pol by constant f.
; -----------------------------------------------------------------------------
        MACRO
        montg_red $f, $pol, $ql, $qh, $qinv, $t0, $t1, $pol_l, $pol_h
        ubfx    $pol_l, $pol, #0, #16
        asr     $pol_h, $pol, #16
        const_mul32x16 $t1, $pol, $pol_l, $pol_h, $f, $t0
        mul     $t0, $t1, $qinv
        ubfx    $pol_l, $t0, #0, #16
        asr     $pol_h, $t0, #16
        const_mul32_acc $t1, $pol, $pol_l, $pol_h, $ql, $qh, $t0
        MEND

; -----------------------------------------------------------------------------
; Load pol0/pol1 at stride `const`, GS-butterfly, store back, advance
; ptr_p by 4+`incr`.
; -----------------------------------------------------------------------------
        MACRO
        wrap_butterfly $const, $incr
        ldr.w   r5, [r0]                            ; pol0
        ldr.w   r6, [r0, #$const]                   ; pol1
        gs_butterfly_montg r5, r6, r11, r12, r3, r7, r2, r8, r9, r10, r14
        str.w   r5, [r0], #4+($incr)
        str.w   r6, [r0, #($const)-4-($incr)]
        MEND

; -----------------------------------------------------------------------------
; Load one zeta pair (low halfword then signed high halfword).
; -----------------------------------------------------------------------------
        MACRO
        load_zeta
        ldrh    r11, [r1], #2                       ; zeta_l
        ldrsh   r12, [r1], #2                       ; zeta_h
        MEND

; =============================================================================
; void inv_ntt_asm_schoolbook(int32_t p[N], const uint32_t zetas_inv_asm[N]);
; =============================================================================
        ALIGN   4
        EXPORT  inv_ntt_asm_schoolbook
inv_ntt_asm_schoolbook PROC
        push    {r4-r11, r14}

        ldr     r2, inv_ntt_asm_neg_qinv_signed     ; qinv (= -q^{-1} signed)
        movw    r3, #0xE001                         ; ql
        movw    r7, #0x7F                           ; qh

        ; --------------------------------------------------------------
        ;  Level 0-3 iterate over blocks
        ; --------------------------------------------------------------

        ; level 0
        movw    r4, #128
inv_sch_level_0
        load_zeta
        wrap_butterfly 4, 4
        subs.n  r4, #1
        bne.n   inv_sch_level_0
        sub     r0, #1024

        ; level 1
        movw    r4, #64
inv_sch_level_1
        load_zeta
        wrap_butterfly 8, 0
        wrap_butterfly 8, 8
        subs.n  r4, #1
        bne.n   inv_sch_level_1
        sub     r0, #1024

        ; level 2: 3 inner butterflies then one "+incr"
        movw    r4, #32
inv_sch_level_2
        load_zeta
count   SETA    0
        WHILE   count < 3
        wrap_butterfly 16, 0
count   SETA    count + 1
        WEND
        wrap_butterfly 16, 16
        subs.w  r4, #1
        bne.w   inv_sch_level_2
        sub     r0, #1024

        ; level 3: 7 inner butterflies then one "+incr"
        movw    r4, #16
inv_sch_level_3
        load_zeta
count   SETA    0
        WHILE   count < 7
        wrap_butterfly 32, 0
count   SETA    count + 1
        WEND
        wrap_butterfly 32, 32
        subs.w  r4, #1
        bne.w   inv_sch_level_3
        sub     r0, #1024

        ; --------------------------------------------------------------
        ;  Level 4-7 iterate inside blocks
        ; --------------------------------------------------------------
        ; level 4 (eight groups of 16)
        load_zeta
        movw    r4, #16
inv_sch_level_4_1
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_1
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_2
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_2
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_3
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_3
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_4
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_4
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_5
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_5
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_6
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_6
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_7
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_7
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_8
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_8
        sub.w   r0, r0, #960

        ; level 5 (four groups of 32)
        load_zeta
        movw    r4, #32
inv_sch_level_5_1
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_5_1
        add     r0, r0, #128

        load_zeta
        movw    r4, #32
inv_sch_level_5_2
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_5_2
        add     r0, r0, #128

        load_zeta
        movw    r4, #32
inv_sch_level_5_3
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_5_3
        add     r0, r0, #128

        load_zeta
        movw    r4, #32
inv_sch_level_5_4
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_5_4
        sub     r0, r0, #896

        ; level 6 (two groups of 64)
        load_zeta
        movw    r4, #64
inv_sch_level_6_1
        wrap_butterfly 256, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_6_1
        add     r0, r0, #256

        load_zeta
        movw    r4, #64
inv_sch_level_6_2
        wrap_butterfly 256, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_6_2
        sub     r0, r0, #768

        ; level 7 — after this load, ptr_zeta (r1) is no longer needed
        ; and r1 gets reused below to hold the final-reduction constant f
        ; (= 41978 = 0xA3FA).  No armasm directive is needed for the
        ; rebind; inline-expansion means it's just "use r1 differently".
        load_zeta
        movw    r4, #128

        movw    r1, #41978                          ; r1 now holds f
inv_sch_level_7
        ldr.w   r5, [r0]                            ; pol0
        ldr.w   r6, [r0, #512]                      ; pol1 (p + 128*4)
        gs_butterfly_montg r5, r6, r11, r12, r3, r7, r2, r8, r9, r10, r14
        add     r10, r3, r7, lsl #16                ; stale in GNU original, preserved
        montg_red r1, r5, r3, r7, r2, r8, r9, r10, r14
        str.w   r5, [r0], #4
        str.w   r6, [r0, #508]
        subs.n  r4, #1
        bne.n   inv_sch_level_7

        pop     {r4-r11, pc}
        ENDP

        ALIGN   4
inv_ntt_asm_neg_qinv_signed
        DCD     0xFC7FDFFF

        END
