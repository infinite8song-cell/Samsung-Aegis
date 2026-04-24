; -----------------------------------------------------------------------------
; pointwise_smull.s
;
; Port of pqm3 crypto_sign/dilithium2/m3/pointwise_smull.S (GNU `as`,
; Thumb-2 UAL) to ARM Compiler v5.06 `armasm` syntax, targeting an SC300
; (Cortex-M3 / ARMv7-M) core.  Coefficient-wise Montgomery multiplication
; using the SMULL/SMLAL 32x32→64 long-multiply path.
;
; Source upstream: https://github.com/mupq/pqm3
; -----------------------------------------------------------------------------

        AREA    |.text|, CODE, READONLY
        THUMB
        PRESERVE8

; -----------------------------------------------------------------------------
; Montgomery multiplication via SMULL+SMLAL.
;   res:pa = pa * pb         (signed 64-bit)
;   pb     = low(res:pa) * qinv    (qinv is -q^{-1} mod 2^32)
;   res:pa += pb * q               (folds pb*q back in)
;   result = res   (the low 32 bits are discarded after the SMLAL)
; -----------------------------------------------------------------------------
        MACRO
        montgomery_multiplication $res, $pa, $pb, $q, $qinv
        smull   $pa, $res, $pa, $pb
        mul     $pb, $pa, $qinv
        smlal   $pa, $res, $pb, $q
        MEND

; =============================================================================
; poly_pointwise_invmontgomery_asm_smull
;   c[i] = a[i] * b[i] * 2^-32 mod q   (Dilithium q = 8380417)
;
; Register binding (inline-expanded from original .req table):
;   r0=c_ptr  r1=a_ptr  r2=b_ptr  r3=qinv  r4=q
;   r5=pa0  r6=pa1  r7=pa2  r8=pb0  r9=pb1  r10=pb2
;   r11=tmp0  r12=ctr  r14=res
; Processing pattern: 85 iterations of three coefficients + a 256th tail.
; =============================================================================
        ALIGN   4
        EXPORT  poly_pointwise_invmontgomery_asm_smull
poly_pointwise_invmontgomery_asm_smull PROC
        push.w  {r4-r11, r14}

        ; qinv = 0xFC7FDFFF  (= -q^{-1} mod 2^32)
        movw    r3, #0xDFFF
        movt    r3, #0xFC7F
        ; q = 8380417 = 0x007FE001
        movw    r4, #0xE001
        movt    r4, #0x007F

        ; 85x3 = 255 coefficients
        movw    r12, #85
pp_smull_L1
        ldr.w   r6,  [r1, #4]               ; pa1
        ldr.w   r7,  [r1, #8]               ; pa2
        ldr     r5,  [r1], #12              ; pa0
        ldr.w   r9,  [r2, #4]               ; pb1
        ldr.w   r10, [r2, #8]               ; pb2
        ldr     r8,  [r2], #12              ; pb0

        montgomery_multiplication r14, r5, r8, r4, r3
        str     r14, [r0], #4
        montgomery_multiplication r14, r6, r9, r4, r3
        str     r14, [r0], #4
        montgomery_multiplication r14, r7, r10, r4, r3
        str     r14, [r0], #4

        subs    r12, #1
        bne.w   pp_smull_L1

        ; final 256th coefficient
        ldr.w   r5, [r1]
        ldr.w   r8, [r2]
        montgomery_multiplication r14, r5, r8, r4, r3
        str.w   r14, [r0]

        pop.w   {r4-r11, pc}
        ENDP

; =============================================================================
; poly_pointwise_acc_invmontgomery_asm_smull
;   c[i] += a[i] * b[i] * 2^-32 mod q
; Same register binding as above; accumulator loads from c_ptr reuse
; pb0..pb2 registers after the multiplications have consumed them.
; =============================================================================
        ALIGN   4
        EXPORT  poly_pointwise_acc_invmontgomery_asm_smull
poly_pointwise_acc_invmontgomery_asm_smull PROC
        push.w  {r4-r11, r14}

        movw    r3, #0xDFFF
        movt    r3, #0xFC7F
        movw    r4, #0xE001
        movt    r4, #0x007F

        movw    r12, #85
pp_smull_acc_L1
        ldr.w   r6,  [r1, #4]               ; pa1
        ldr.w   r7,  [r1, #8]               ; pa2
        ldr     r5,  [r1], #12              ; pa0
        ldr.w   r9,  [r2, #4]               ; pb1
        ldr.w   r10, [r2, #8]               ; pb2
        ldr     r8,  [r2], #12              ; pb0

        montgomery_multiplication r14, r5, r8, r4, r3      ; r14 = a0*b0*R^-1
        montgomery_multiplication r5,  r6, r9, r4, r3      ; r5  = a1*b1*R^-1
        montgomery_multiplication r6,  r7, r10, r4, r3     ; r6  = a2*b2*R^-1

        ldr.w   r8,  [r0]
        ldr.w   r9,  [r0, #4]
        ldr.w   r10, [r0, #8]
        add.w   r14, r14, r8
        str     r14, [r0], #12
        add.w   r5, r5, r9
        str     r5, [r0, #-8]
        add.w   r6, r6, r10
        str     r6, [r0, #-4]

        subs    r12, #1
        bne.w   pp_smull_acc_L1

        ; final 256th coefficient
        ldr.w   r5, [r1]
        ldr.w   r8, [r2]
        ldr.w   r6, [r0]
        montgomery_multiplication r14, r5, r8, r4, r3
        add.w   r14, r14, r6
        str.w   r14, [r0]

        pop.w   {r4-r11, pc}
        ENDP

        END
