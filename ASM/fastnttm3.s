; -----------------------------------------------------------------------------
; fastnttm3.s
;
; Port of pqm3 crypto_kem/kyber768/m3/fastnttm3.S (GNU `as`, Thumb-2 UAL) to
; ARM Compiler v5.06 `armasm` syntax, targeting an SC300 (Cortex-M3 / ARMv7-M)
; core.  Implements the forward number-theoretic transform used by Kyber-768.
;
; Register aliases from the original .req table (inline-expanded in the body):
;   r0  = poly          r1  = twiddle_ptr
;   r2  = poly0         r3  = poly1   r4 = poly2   r5 = poly3
;   r6  = poly4         r7  = poly5   r8 = poly6   r9 = poly7
;   r10 = twiddle / barrettconst      r11 = qinv    r12 = q    r14 = tmp
;
; Source upstream: https://github.com/mupq/pqm3  (public-domain / CC0)
; -----------------------------------------------------------------------------

        PRESERVE8
        THUMB

; Global assembler variable used by the WHILE/WEND unroll that replaces the
; original `.rept 4` + `.set k` construct in LAYER 4+3+2.
        GBLA    k

barrett_constant EQU 20159

        AREA    |.text|, CODE, READONLY

; -----------------------------------------------------------------------------
; Macro: butterflym3
;   Cooley-Tukey butterfly with Montgomery-reduced twiddle.
;   $a0 : poly[i]   (in/out)
;   $a1 : poly[j]   (in/out)
;   $twiddle : twiddle factor
;   $q   : modulus q
;   $qinv: q^{-1} mod 2^16
;   $tmp : scratch
; -----------------------------------------------------------------------------
        MACRO
        butterflym3 $a0, $a1, $twiddle, $q, $qinv, $tmp
        mul.w   $a1, $a1, $twiddle
        mul.w   $tmp, $a1, $qinv
        sxth.w  $tmp, $tmp
        mla.w   $tmp, $tmp, $q, $a1
        sub.w   $a1, $a0, $tmp, asr #16
        add.w   $a0, $a0, $tmp, asr #16
        MEND

; -----------------------------------------------------------------------------
; Macro: barrettm3
;   Unsigned Barrett reduction.
; -----------------------------------------------------------------------------
        MACRO
        barrettm3 $a, $tmp, $q, $barrettconst
        mul.w   $tmp, $a, $barrettconst
        asr.w   $tmp, $tmp, #26
        mul.w   $tmp, $tmp, $q
        sub.w   $a, $a, $tmp
        MEND

; =============================================================================
; ntt_fast_m3(int16_t *poly, const int16_t *twiddles)
;   r0 = poly, r1 = twiddle_ptr
; =============================================================================
        ALIGN   4
        EXPORT  ntt_fast_m3
ntt_fast_m3 PROC
        push.w  {r4-r11, r14}

        movw    r11, #3327          ; qinv
        movw    r12, #3329          ; q

        ; ### LAYER 7+6+5
        movw    r14, #32            ; tmp = outer loop counter
ntt_L1
        push.w  {r14}

        ldrsh.w r2, [r0]
        ldrsh.w r3, [r0, #64]
        ldrsh.w r4, [r0, #128]
        ldrsh.w r5, [r0, #192]
        ldrsh.w r6, [r0, #256]
        ldrsh.w r7, [r0, #320]
        ldrsh.w r8, [r0, #384]
        ldrsh.w r9, [r0, #448]

        ldrsh.w r10, [r1]
        butterflym3 r2, r6, r10, r12, r11, r14
        butterflym3 r3, r7, r10, r12, r11, r14
        butterflym3 r4, r8, r10, r12, r11, r14
        butterflym3 r5, r9, r10, r12, r11, r14

        ldrsh.w r10, [r1, #2]
        butterflym3 r2, r4, r10, r12, r11, r14
        butterflym3 r3, r5, r10, r12, r11, r14
        ldrsh.w r10, [r1, #4]
        butterflym3 r6, r8, r10, r12, r11, r14
        butterflym3 r7, r9, r10, r12, r11, r14

        ldrsh.w r10, [r1, #6]
        butterflym3 r2, r3, r10, r12, r11, r14
        ldrsh.w r10, [r1, #8]
        butterflym3 r4, r5, r10, r12, r11, r14
        ldrsh.w r10, [r1, #10]
        butterflym3 r6, r7, r10, r12, r11, r14
        ldrsh.w r10, [r1, #12]
        butterflym3 r8, r9, r10, r12, r11, r14

        strh.w  r3, [r0, #64]
        strh.w  r4, [r0, #128]
        strh.w  r5, [r0, #192]
        strh.w  r6, [r0, #256]
        strh.w  r7, [r0, #320]
        strh.w  r8, [r0, #384]
        strh.w  r9, [r0, #448]
        strh.w  r2, [r0], #2

        pop.w   {r14}
        subs.w  r14, #1
        bne.w   ntt_L1

        sub.w   r0, #64
        add.w   r1, #14

        ; ### LAYER 4+3+2
        movw    r14, #8
ntt_L2
        push.w  {r14}

k       SETA    1
        WHILE   k <= 4
        ldrsh.w r2, [r0]
        ldrsh.w r3, [r0, #8]
        ldrsh.w r4, [r0, #16]
        ldrsh.w r5, [r0, #24]
        ldrsh.w r6, [r0, #32]
        ldrsh.w r7, [r0, #40]
        ldrsh.w r8, [r0, #48]
        ldrsh.w r9, [r0, #56]

        ldrsh.w r10, [r1]
        butterflym3 r2, r6, r10, r12, r11, r14
        butterflym3 r3, r7, r10, r12, r11, r14
        butterflym3 r4, r8, r10, r12, r11, r14
        butterflym3 r5, r9, r10, r12, r11, r14

        ldrsh.w r10, [r1, #2]
        butterflym3 r2, r4, r10, r12, r11, r14
        butterflym3 r3, r5, r10, r12, r11, r14
        ldrsh.w r10, [r1, #4]
        butterflym3 r6, r8, r10, r12, r11, r14
        butterflym3 r7, r9, r10, r12, r11, r14

        ldrsh.w r10, [r1, #6]
        butterflym3 r2, r3, r10, r12, r11, r14
        ldrsh.w r10, [r1, #8]
        butterflym3 r4, r5, r10, r12, r11, r14
        ldrsh.w r10, [r1, #10]
        butterflym3 r6, r7, r10, r12, r11, r14
        ldrsh.w r10, [r1, #12]
        butterflym3 r8, r9, r10, r12, r11, r14

        strh.w  r3, [r0, #8]
        strh.w  r4, [r0, #16]
        strh.w  r5, [r0, #24]
        strh.w  r6, [r0, #32]
        strh.w  r7, [r0, #40]
        strh.w  r8, [r0, #48]
        strh.w  r9, [r0, #56]
        IF k != 4
        strh.w  r2, [r0], #2
        ELSE
        strh.w  r2, [r0], #58
        ENDIF
k       SETA    k + 1
        WEND
        add.w   r1, #14

        pop.w   {r14}
        subs.w  r14, #1
        bne.w   ntt_L2

        sub.w   r0, #512

        ; ### LAYER 1 (skip layer 0)
        movw    r14, #32
ntt_L4
        push.w  {r14}

        ldrsh.w r2, [r0]
        ldrsh.w r3, [r0, #2]
        ldrsh.w r4, [r0, #4]
        ldrsh.w r5, [r0, #6]
        ldrsh.w r6, [r0, #8]
        ldrsh.w r7, [r0, #10]
        ldrsh.w r8, [r0, #12]
        ldrsh.w r9, [r0, #14]

        ldrsh.w r10, [r1], #2
        butterflym3 r2, r4, r10, r12, r11, r14
        butterflym3 r3, r5, r10, r12, r11, r14
        ldrsh.w r10, [r1], #2
        butterflym3 r6, r8, r10, r12, r11, r14
        butterflym3 r7, r9, r10, r12, r11, r14

        movw    r10, #barrett_constant
        barrettm3 r2, r14, r12, r10
        barrettm3 r3, r14, r12, r10
        barrettm3 r4, r14, r12, r10
        barrettm3 r5, r14, r12, r10
        barrettm3 r6, r14, r12, r10
        barrettm3 r7, r14, r12, r10
        barrettm3 r8, r14, r12, r10
        barrettm3 r9, r14, r12, r10

        strh.w  r3, [r0, #2]
        strh.w  r4, [r0, #4]
        strh.w  r5, [r0, #6]
        strh.w  r6, [r0, #8]
        strh.w  r7, [r0, #10]
        strh.w  r8, [r0, #12]
        strh.w  r9, [r0, #14]
        strh.w  r2, [r0], #16

        pop.w   {r14}
        subs.w  r14, #1
        bne.w   ntt_L4

        pop.w   {r4-r11, pc}
        ENDP

        END
