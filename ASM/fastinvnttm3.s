; -----------------------------------------------------------------------------
; fastinvnttm3.s
;
; Port of pqm3 crypto_kem/kyber768/m3/fastinvnttm3.S (GNU `as`, Thumb-2 UAL) to
; ARM Compiler v5.06 `armasm` syntax, targeting an SC300 (Cortex-M3 / ARMv7-M)
; core.  Implements the inverse number-theoretic transform used by Kyber-768.
;
; Register aliases from the original .req table (inline-expanded in the body):
;   r0  = poly          r1  = twiddle_ptr
;   r2  = poly0         r3  = poly1   r4 = poly2   r5 = poly3
;   r6  = poly4         r7  = poly5   r8 = poly6   r9 = poly7
;   r10 = twiddle / montconst / barrettconst
;   r11 = q             r12 = tmp     r14 = qinv
;
; NOTE on signed_barrettm3:
; The GNU source adds the literal `#67108864` (= 0x04000000 = 2^26) inside the
; macro.  That immediate is NOT representable in the Thumb-2 ADD imm12
; modified-immediate encoding; GNU `as` silently expands it into a MOVW/MOVT
; sequence plus an ADD, but armasm v5.06 rejects the literal outright.  All
; registers in invntt_fast_m3 are already bound, so we cannot allocate an
; extra scratch at the call sites.  The fix is to rebuild 0x04000000 from
; MOVW/MOVT into $barrettconst *inside* the macro (after the initial MUL,
; at which point $barrettconst is dead for the rest of this invocation) and
; to move the `MOVW #25218 / SXTH` reseed inside the macro too so every
; invocation starts from a clean barrettconst.  The computed value is
; identical to the GNU version; only the instruction stream differs.
;
; Source upstream: https://github.com/mupq/pqm3  (public-domain / CC0)
; -----------------------------------------------------------------------------

        AREA    |.text|, CODE, READONLY
        THUMB
        PRESERVE8

; Global assembler variable used by the WHILE/WEND unroll that replaces the
; original `.rept 4` + `.set k` construct in LAYER 2+3+4.
        GBLA    k

; -----------------------------------------------------------------------------
; Macro: montgomerym3
;   Signed Montgomery reduction of a 32-bit value.
; -----------------------------------------------------------------------------
        MACRO
        montgomerym3 $q, $qinv, $a, $tmp
        mul.w   $tmp, $a, $qinv
        sxth.w  $tmp, $tmp
        mla.w   $a, $tmp, $q, $a
        asr.w   $a, $a, #16
        MEND

; -----------------------------------------------------------------------------
; Macro: gsbutterflym3
;   Gentleman-Sande butterfly with Montgomery-reduced twiddle.
; -----------------------------------------------------------------------------
        MACRO
        gsbutterflym3 $poly0, $poly1, $twiddle, $tmp, $q, $qinv
        sub.w   $tmp, $poly0, $poly1
        add.w   $poly0, $poly0, $poly1

        mul.w   $poly1, $tmp, $twiddle
        montgomerym3 $q, $qinv, $poly1, $tmp
        MEND

; -----------------------------------------------------------------------------
; Macro: fqmulprecompm3
;   Multiply $a by a pre-Montgomery-scaled twiddle and reduce.
; -----------------------------------------------------------------------------
        MACRO
        fqmulprecompm3 $a, $twiddle, $tmp, $q, $qinv
        mul.w   $a, $a, $twiddle
        montgomerym3 $q, $qinv, $a, $tmp
        MEND

; -----------------------------------------------------------------------------
; Macro: signed_barrettm3
;   Signed Barrett reduction.  See file header for why the reseed of
;   $barrettconst and the MOVW/MOVT rebuild of 2^26 live inside the macro.
; -----------------------------------------------------------------------------
        MACRO
        signed_barrettm3 $a, $q, $tmp, $barrettconst
        movw    $barrettconst, #25218
        sxth    $barrettconst, $barrettconst
        mul.w   $tmp, $a, $barrettconst
        movw    $barrettconst, #0x0000
        movt    $barrettconst, #0x0400
        add.w   $tmp, $tmp, $barrettconst
        asr.w   $tmp, $tmp, #27
        mla.w   $a, $tmp, $q, $a
        MEND

; =============================================================================
; invntt_fast_m3(int16_t *poly, const int16_t *twiddles)
;   r0 = poly, r1 = twiddle_ptr
; =============================================================================
        EXPORT  invntt_fast_m3

        ALIGN   4
invntt_fast_m3 PROC
        push.w  {r4-r11, r14}

        movw    r11, #3329          ; q
        movw    r14, #3327          ; qinv

        ; ### LAYER 1 (skip layer 0)
        movw    r12, #32            ; tmp = outer loop counter
invntt_L1
        push.w  {r12}

        ldrsh.w r2, [r0, #0]
        ldrsh.w r3, [r0, #2]
        ldrsh.w r4, [r0, #4]
        ldrsh.w r5, [r0, #6]
        ldrsh.w r6, [r0, #8]
        ldrsh.w r7, [r0, #10]
        ldrsh.w r8, [r0, #12]
        ldrsh.w r9, [r0, #14]

        ldrsh.w r10, [r1], #2
        gsbutterflym3 r2, r4, r10, r12, r11, r14
        gsbutterflym3 r3, r5, r10, r12, r11, r14

        ldrsh.w r10, [r1], #2
        gsbutterflym3 r6, r8, r10, r12, r11, r14
        gsbutterflym3 r7, r9, r10, r12, r11, r14

        signed_barrettm3 r2, r11, r12, r10
        signed_barrettm3 r3, r11, r12, r10
        signed_barrettm3 r6, r11, r12, r10
        signed_barrettm3 r7, r11, r12, r10

        strh.w  r3, [r0, #2]
        strh.w  r4, [r0, #4]
        strh.w  r5, [r0, #6]
        strh.w  r6, [r0, #8]
        strh.w  r7, [r0, #10]
        strh.w  r8, [r0, #12]
        strh.w  r9, [r0, #14]
        strh.w  r2, [r0], #16

        pop.w   {r12}
        subs.w  r12, #1
        bne.w   invntt_L1

        sub.w   r0, #512

        ; ### LAYER 2+3+4
        movw    r12, #8
invntt_L2
        push.w  {r12}

k       SETA    1
        WHILE   k <= 4
        ldrsh.w r2, [r0, #0]
        ldrsh.w r3, [r0, #8]
        ldrsh.w r4, [r0, #16]
        ldrsh.w r5, [r0, #24]
        ldrsh.w r6, [r0, #32]
        ldrsh.w r7, [r0, #40]
        ldrsh.w r8, [r0, #48]
        ldrsh.w r9, [r0, #56]

        ldrsh.w r10, [r1, #0]
        gsbutterflym3 r2, r3, r10, r12, r11, r14
        ldrsh.w r10, [r1, #2]
        gsbutterflym3 r4, r5, r10, r12, r11, r14
        ldrsh.w r10, [r1, #4]
        gsbutterflym3 r6, r7, r10, r12, r11, r14
        ldrsh.w r10, [r1, #6]
        gsbutterflym3 r8, r9, r10, r12, r11, r14

        ldrsh.w r10, [r1, #8]
        gsbutterflym3 r2, r4, r10, r12, r11, r14
        gsbutterflym3 r3, r5, r10, r12, r11, r14

        ldrsh.w r10, [r1, #10]
        gsbutterflym3 r6, r8, r10, r12, r11, r14
        gsbutterflym3 r7, r9, r10, r12, r11, r14

        ldrsh.w r10, [r1, #12]
        gsbutterflym3 r2, r6, r10, r12, r11, r14
        gsbutterflym3 r3, r7, r10, r12, r11, r14
        gsbutterflym3 r4, r8, r10, r12, r11, r14
        gsbutterflym3 r5, r9, r10, r12, r11, r14

        movw    r10, #2285
        fqmulprecompm3 r2, r10, r12, r11, r14
        fqmulprecompm3 r3, r10, r12, r11, r14
        fqmulprecompm3 r4, r10, r12, r11, r14
        fqmulprecompm3 r5, r10, r12, r11, r14

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

        pop.w   {r12}
        subs.w  r12, #1
        bne.w   invntt_L2

        sub.w   r0, #512

        ; ### LAYER 5+6+7
        movw    r12, #32
invntt_L3
        push.w  {r12}

        ldrsh.w r2, [r0, #0]
        ldrsh.w r3, [r0, #64]
        ldrsh.w r4, [r0, #128]
        ldrsh.w r5, [r0, #192]
        ldrsh.w r6, [r0, #256]
        ldrsh.w r7, [r0, #320]
        ldrsh.w r8, [r0, #384]
        ldrsh.w r9, [r0, #448]

        ldrsh.w r10, [r1]
        gsbutterflym3 r2, r3, r10, r12, r11, r14
        ldrsh.w r10, [r1, #2]
        gsbutterflym3 r4, r5, r10, r12, r11, r14
        ldrsh.w r10, [r1, #4]
        gsbutterflym3 r6, r7, r10, r12, r11, r14
        ldrsh.w r10, [r1, #6]
        gsbutterflym3 r8, r9, r10, r12, r11, r14

        ldrsh.w r10, [r1, #8]
        gsbutterflym3 r2, r4, r10, r12, r11, r14
        gsbutterflym3 r3, r5, r10, r12, r11, r14
        ldrsh.w r10, [r1, #10]
        gsbutterflym3 r6, r8, r10, r12, r11, r14
        gsbutterflym3 r7, r9, r10, r12, r11, r14

        ldrsh.w r10, [r1, #12]
        gsbutterflym3 r2, r6, r10, r12, r11, r14
        gsbutterflym3 r3, r7, r10, r12, r11, r14
        gsbutterflym3 r4, r8, r10, r12, r11, r14
        gsbutterflym3 r5, r9, r10, r12, r11, r14

        ldrsh.w r10, [r1, #14]
        fqmulprecompm3 r2, r10, r12, r11, r14
        fqmulprecompm3 r3, r10, r12, r11, r14
        fqmulprecompm3 r4, r10, r12, r11, r14
        fqmulprecompm3 r5, r10, r12, r11, r14

        strh.w  r3, [r0, #64]
        strh.w  r4, [r0, #128]
        strh.w  r5, [r0, #192]
        strh.w  r6, [r0, #256]
        strh.w  r7, [r0, #320]
        strh.w  r8, [r0, #384]
        strh.w  r9, [r0, #448]
        strh.w  r2, [r0], #2

        pop.w   {r12}
        subs.w  r12, #1
        bne.w   invntt_L3

        pop.w   {r4-r11, pc}
        ENDP

        END
