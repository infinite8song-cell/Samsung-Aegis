; -----------------------------------------------------------------------------
; vector.s
;
; Port of pqm3 crypto_sign/dilithium2/m3/vector.s (GNU `as`, Thumb-2 UAL)
; to ARM Compiler v5.06 `armasm` syntax, targeting an SC300 (Cortex-M3 /
; ARMv7-M) core.  Three Dilithium polynomial-vector helpers:
;
;   pqcrystals_dilithium_asm_reduce32  : Montgomery reduction on int32_t[N]
;   pqcrystals_dilithium_asm_caddq     : conditional add-q on int32_t[N]
;   pqcrystals_dilithium_asm_rej_uniform : rejection sampling from buf
;
; Source upstream: https://github.com/mupq/pqm3
; -----------------------------------------------------------------------------

        AREA    |.text|, CODE, READONLY
        THUMB
        PRESERVE8

; -----------------------------------------------------------------------------
; redq : one-step Barrett-style reduction of a signed 32-bit value.
;   a    : value to reduce (in/out)
;   tmp  : scratch
;   q    : Dilithium q = 8380417
; -----------------------------------------------------------------------------
        MACRO
        redq $a, $tmp, $q
        add     $tmp, $a, #4194304
        asrs    $tmp, $tmp, #23
        mls     $a, $tmp, $q, $a
        MEND

; -----------------------------------------------------------------------------
; caddq : if a < 0 then a += q  (branch-free using arithmetic-shift mask).
; -----------------------------------------------------------------------------
        MACRO
        caddq $a, $tmp, $q
        and     $tmp, $q, $a, asr #31
        add     $a, $a, $tmp
        MEND

; =============================================================================
; void pqcrystals_dilithium_asm_reduce32(int32_t a[N])
;   r0 = a
; =============================================================================
        ALIGN   4
        EXPORT  pqcrystals_dilithium_asm_reduce32
pqcrystals_dilithium_asm_reduce32 PROC
        push    {r4-r10}

        ; r12 = q = 8380417 = 0x007FE001
        movw    r12, #0xE001
        movt    r12, #0x007F

        movw    r10, #32                    ; loop count (32 * 8 = 256)
reduce32_L1
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
        bne.w   reduce32_L1

        pop     {r4-r10}
        bx      lr
        ENDP

; =============================================================================
; void pqcrystals_dilithium_asm_caddq(int32_t a[N])
;   r0 = a
; =============================================================================
        ALIGN   4
        EXPORT  pqcrystals_dilithium_asm_caddq
pqcrystals_dilithium_asm_caddq PROC
        push    {r4-r10}

        movw    r12, #0xE001
        movt    r12, #0x007F

        movw    r10, #32
caddq_L1
        ldr.w   r1, [r0]
        ldr.w   r2, [r0, #1*4]
        ldr.w   r3, [r0, #2*4]
        ldr.w   r4, [r0, #3*4]
        ldr.w   r5, [r0, #4*4]
        ldr.w   r6, [r0, #5*4]
        ldr.w   r7, [r0, #6*4]
        ldr.w   r8, [r0, #7*4]

        caddq   r1, r9, r12
        caddq   r2, r9, r12
        caddq   r3, r9, r12
        caddq   r4, r9, r12
        caddq   r5, r9, r12
        caddq   r6, r9, r12
        caddq   r7, r9, r12
        caddq   r8, r9, r12

        str.w   r2, [r0, #1*4]
        str.w   r3, [r0, #2*4]
        str.w   r4, [r0, #3*4]
        str.w   r5, [r0, #4*4]
        str.w   r6, [r0, #5*4]
        str.w   r7, [r0, #6*4]
        str.w   r8, [r0, #7*4]
        str     r1, [r0], #8*4
        subs    r10, #1
        bne.w   caddq_L1

        pop     {r4-r10}
        bx      lr
        ENDP

; =============================================================================
; unsigned int pqcrystals_dilithium_asm_rej_uniform(
;     int32_t *a,             ; r0
;     unsigned int len,       ; r1  (saved on stack, reloaded as count)
;     const uint8_t *buf,     ; r2
;     unsigned int buflen)    ; r3
;
; Returns (in r0) the number of coefficients actually written.
; =============================================================================
        ALIGN   4
        EXPORT  pqcrystals_dilithium_asm_rej_uniform
pqcrystals_dilithium_asm_rej_uniform PROC
        push.w  {r4-r6}
        push.w  {r1}

        ; r12 = Q-1 = 8380416 = 0x007FE000
        movw    r12, #0xE000
        movt    r12, #0x007F

        add.w   r6, r0, r1, lsl #2          ; r6 = a + len   (end of target)
        add.w   r3, r2, r3                  ; r3 = buf + buflen
        sub.w   r3, r3, #2                  ; r3 = buf + buflen - 2

rej_uniform_L1
        ; need at least 3 bytes; r3 - r2 < 0 means 2 or fewer remain
        cmp.w   r3, r2
        ble.w   rej_uniform_end

        ldr     r5, [r2], #3                ; load 3 bytes (reads 4, we advance by 3)
        ubfx    r5, r5, #0, #23             ; mask to 23 bits

        cmp.n   r5, r12
        it      le
        strle   r5, [r0], #4

        cmp.n   r0, r6
        bne.n   rej_uniform_L1

rej_uniform_end
        pop.w   {r5}                        ; r5 = original len

        sub.w   r0, r6, r0                  ; r0 = (end - cur) bytes
        sub.w   r0, r5, r0, lsr #2          ; r0 = len - remaining_slots = written

        pop.w   {r4-r6}
        bx      lr
        ENDP

        END
