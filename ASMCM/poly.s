; -----------------------------------------------------------------------------
; poly.s
;
; Port of dilithium-cortexm/dilithium/m3/poly.S (GNU `as`, Thumb-2 UAL) to
; ARM Compiler v5.06 `armasm` syntax, targeting an SC300 (Cortex-M3 /
; ARMv7-M) core.  Four Dilithium polynomial-level helpers:
;
;   poly_reduce_asm  : in-place reduction to (-Q/2, Q/2]-style range via a
;                      UBFX/ASR split + LSL #13 recombination + csubq
;   poly_freeze_asm  : like poly_reduce_asm but also unconditionally folds
;                      negative results by +Q (i.e. into [0, Q))
;   poly_csubq_asm   : conditional subtract/add Q only (no Barrett step)
;   rej_uniform_asm  : rejection sampling 23-bit candidates from a byte buf
;
; The Barrett-style `redq` here differs from the 2^22 / ASR #23 variant in
; pqm3 vector.s — no `ADD #4194304` appears; instead bitfield extraction
; and a `LSL #13` recombination approximate the same modular class, plus
; an explicit csubq.
;
; Keil canonical directive order is used (AREA before THUMB / PRESERVE8)
; to guarantee each exported symbol inherits the Thumb interworking bit
; required by armlink when C code resolves it.
;
; Source upstream:
;   https://github.com/dilithium-cortexm/dilithium-cortexm  (public domain)
; -----------------------------------------------------------------------------

        AREA    |.text|, CODE, READONLY
        THUMB
        PRESERVE8

; -----------------------------------------------------------------------------
; Macro: redq
;   Partial Barrett-style reduction.
;   tmp = a & ((1<<23)-1)         (low 23 bits, unsigned)
;   a   = a >> 23  (arith)        (high bits, signed)
;   tmp = tmp - a
;   a   = tmp + (a << 13)
;   if a >= q: a -= q             (csubq tail)
; -----------------------------------------------------------------------------
        MACRO
        redq $a, $tmp, $q
        ubfx    $tmp, $a, #0, #23
        asr.w   $a, $a, #23
        sub.w   $tmp, $tmp, $a
        add.w   $a, $tmp, $a, lsl #13
        cmp.n   $a, $q
        it      ge
        subge.w $a, $a, $q
        MEND

; -----------------------------------------------------------------------------
; Macro: freezeq
;   Same as redq followed by a conditional add-q when a < 0.  Produces a
;   canonical representative in [0, q).
; -----------------------------------------------------------------------------
        MACRO
        freezeq $a, $tmp, $q
        ubfx    $tmp, $a, #0, #23
        asr.w   $a, $a, #23
        sub.w   $tmp, $tmp, $a
        add.w   $a, $tmp, $a, lsl #13
        cmp.n   $a, $q
        it      ge
        subge.w $a, $a, $q
        cmp     $a, #0
        it      mi
        addmi.w $a, $a, $q
        MEND

; -----------------------------------------------------------------------------
; Macro: csubq
;   Signed conditional subtract/add of q to bring a into [0, q).
; -----------------------------------------------------------------------------
        MACRO
        csubq $a, $tmp, $q
        cmp.n   $a, $q
        it      ge
        subge.w $a, $a, $q
        cmp     $a, #0
        it      mi
        addmi.w $a, $a, $q
        MEND

; =============================================================================
; void poly_reduce_asm(int32_t a[N])
;   r0 = a
; =============================================================================
        EXPORT  poly_reduce_asm

        ALIGN   4
poly_reduce_asm PROC
        push    {r4-r10}

        ; r12 = q = 8380417 = 0x007FE001
        movw    r12, #0xE001
        movt    r12, #0x007F

        movw    r10, #32                    ; 32 * 8 = 256 coefficients
poly_reduce_L1
        ldr.w   r1, [r0]
        ldr.w   r2, [r0, #1*4]
        ldr.w   r3, [r0, #2*4]
        ldr.w   r4, [r0, #3*4]
        ldr.w   r5, [r0, #4*4]
        ldr.w   r6, [r0, #5*4]
        ldr.w   r7, [r0, #6*4]
        ldr.w   r8, [r0, #7*4]

        redq    r1, r9, r12
        redq    r2, r9, r12
        redq    r3, r9, r12
        redq    r4, r9, r12
        redq    r5, r9, r12
        redq    r6, r9, r12
        redq    r7, r9, r12
        redq    r8, r9, r12

        str.w   r2, [r0, #1*4]
        str.w   r3, [r0, #2*4]
        str.w   r4, [r0, #3*4]
        str.w   r5, [r0, #4*4]
        str.w   r6, [r0, #5*4]
        str.w   r7, [r0, #6*4]
        str.w   r8, [r0, #7*4]
        str     r1, [r0], #8*4
        subs    r10, #1
        bne.w   poly_reduce_L1

        pop     {r4-r10}
        bx      lr
        ENDP

; =============================================================================
; void poly_freeze_asm(int32_t a[N])
;   r0 = a
; =============================================================================
        EXPORT  poly_freeze_asm

        ALIGN   4
poly_freeze_asm PROC
        push    {r4-r10}

        movw    r12, #0xE001
        movt    r12, #0x007F

        movw    r10, #32
poly_freeze_L1
        ldr.w   r1, [r0]
        ldr.w   r2, [r0, #1*4]
        ldr.w   r3, [r0, #2*4]
        ldr.w   r4, [r0, #3*4]
        ldr.w   r5, [r0, #4*4]
        ldr.w   r6, [r0, #5*4]
        ldr.w   r7, [r0, #6*4]
        ldr.w   r8, [r0, #7*4]

        freezeq r1, r9, r12
        freezeq r2, r9, r12
        freezeq r3, r9, r12
        freezeq r4, r9, r12
        freezeq r5, r9, r12
        freezeq r6, r9, r12
        freezeq r7, r9, r12
        freezeq r8, r9, r12

        str.w   r2, [r0, #1*4]
        str.w   r3, [r0, #2*4]
        str.w   r4, [r0, #3*4]
        str.w   r5, [r0, #4*4]
        str.w   r6, [r0, #5*4]
        str.w   r7, [r0, #6*4]
        str.w   r8, [r0, #7*4]
        str     r1, [r0], #8*4
        subs    r10, #1
        bne.w   poly_freeze_L1

        pop     {r4-r10}
        bx      lr
        ENDP

; =============================================================================
; void poly_csubq_asm(int32_t a[N])
;   r0 = a
; =============================================================================
        EXPORT  poly_csubq_asm

        ALIGN   4
poly_csubq_asm PROC
        push    {r4-r10}

        movw    r12, #0xE001
        movt    r12, #0x007F

        movw    r10, #32
poly_csubq_L1
        ldr.w   r1, [r0]
        ldr.w   r2, [r0, #1*4]
        ldr.w   r3, [r0, #2*4]
        ldr.w   r4, [r0, #3*4]
        ldr.w   r5, [r0, #4*4]
        ldr.w   r6, [r0, #5*4]
        ldr.w   r7, [r0, #6*4]
        ldr.w   r8, [r0, #7*4]

        csubq   r1, r9, r12
        csubq   r2, r9, r12
        csubq   r3, r9, r12
        csubq   r4, r9, r12
        csubq   r5, r9, r12
        csubq   r6, r9, r12
        csubq   r7, r9, r12
        csubq   r8, r9, r12

        str.w   r2, [r0, #1*4]
        str.w   r3, [r0, #2*4]
        str.w   r4, [r0, #3*4]
        str.w   r5, [r0, #4*4]
        str.w   r6, [r0, #5*4]
        str.w   r7, [r0, #6*4]
        str.w   r8, [r0, #7*4]
        str     r1, [r0], #8*4
        subs    r10, #1
        bne.w   poly_csubq_L1

        pop     {r4-r10}
        bx      lr
        ENDP

; =============================================================================
; unsigned int rej_uniform_asm(
;     int32_t *a,             ; r0
;     unsigned int len,       ; r1  (saved on stack, reloaded at exit)
;     const uint8_t *buf,     ; r2
;     unsigned int buflen)    ; r3
;
; Returns (in r0) the number of coefficients actually written.
;
; Note: this is identical to pqcrystals_dilithium_asm_rej_uniform in
; vector.s but with a different symbol name; both may coexist in one
; build without conflict.
; =============================================================================
        EXPORT  rej_uniform_asm

        ALIGN   4
rej_uniform_asm PROC
        push.w  {r4-r6}
        push.w  {r1}

        ; r12 = Q-1 = 8380416 = 0x007FE000
        movw    r12, #0xE000
        movt    r12, #0x007F

        add.w   r6, r0, r1, lsl #2
        add.w   r3, r2, r3
        sub.w   r3, r3, #2

rej_uniform_asm_L1
        cmp.w   r3, r2
        ble.w   rej_uniform_asm_end

        ldr     r5, [r2], #3
        ubfx    r5, r5, #0, #23

        cmp.n   r5, r12
        it      le
        strle   r5, [r0], #4

        cmp.n   r0, r6
        bne.n   rej_uniform_asm_L1

rej_uniform_asm_end
        pop.w   {r5}

        sub.w   r0, r6, r0
        sub.w   r0, r5, r0, lsr #2
        pop.w   {r4-r6}
        bx      lr
        ENDP

        END
