/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/dilithium_kernels.S — ARMv7-M Thumb-2 ML-DSA scalar kernels for SC300.
 *
 * Direct port of pqm3 (mupq/pqm3) crypto_sign/dilithium2/m3 hand-tuned assembly:
 *   - pointwise_smull.S  (poly_pointwise_invmontgomery / poly_pointwise_acc)
 *   - vector.s           (asm_reduce32, asm_caddq)
 *
 * No DSP extensions — uses only smull, smlal, mul, mls (base ARMv7-M Thumb-2).
 * Toolchain target: ARMClang 6 (--target=arm-arm-none-eabi -mcpu=cortex-m3 -mthumb)
 *                   and arm-none-eabi-gcc Thumb-2.
 *
 * Exported with PQCLEAN_MLDSA{44,65}_CLEAN_ aliases — they are identical
 * up to the namespace prefix (the kernels are param-set independent;
 * Q, QINV, N=256 are the same for ML-DSA-44 and ML-DSA-65).
 *
 * Constants:
 *   Q    = 8380417   = 0x007FE001
 *   QINV = -0x03802001 (signed) = 0xFC7FDFFF
 *
 * Calling conventions:
 *   void poly_pointwise_montgomery(poly *c, const poly *a, const poly *b)
 *       — c[i] = mont(a[i] * b[i]) for i=0..255
 *   void poly_pointwise_acc_montgomery(poly *c, const poly *a, const poly *b)
 *       — c[i] += mont(a[i] * b[i])
 *   void poly_reduce_asm(poly *a)        — Barrett-style reduce32 of all 256 coefs
 *   void poly_caddq_asm(poly *a)         — conditional add Q if coef negative
 */

.syntax unified
.thumb

/* ------------------------------------------------------------------ */
/* poly_pointwise_montgomery  (replaces ref/poly.c MLDSA_NAMESPACE)    */
/* ------------------------------------------------------------------ */
.macro montgomery_multiplication res, pa, pb, q, qinv
    smull \pa, \res, \pa, \pb
    mul   \pb, \pa, \qinv
    smlal \pa, \res, \pb, \q
.endm

.global PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery_asm
.type   PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery_asm, %function
.thumb_func
.align 2
PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery_asm:
    push.w {r4-r11, r14}

    c_ptr .req r0
    a_ptr .req r1
    b_ptr .req r2
    qinv  .req r3
    q     .req r4
    pa0   .req r5
    pa1   .req r6
    pa2   .req r7
    pb0   .req r8
    pb1   .req r9
    pb2   .req r10
    ctr   .req r12
    res   .req r14

    movw qinv, #:lower16:0xfc7fdfff
    movt qinv, #:upper16:0xfc7fdfff
    movw q,    #0xE001
    movt q,    #0x007F

    /* 85 iterations × 3 coefficients = 255 ; final coefficient handled below.
     * ldmia replaces 3 ldr.w (4 cycles total vs 6 for individual loads). */
    movw ctr, #85
1:
    ldmia a_ptr!, {pa0, pa1, pa2}
    ldmia b_ptr!, {pb0, pb1, pb2}

    montgomery_multiplication res, pa0, pb0, q, qinv
    str   res, [c_ptr], #4
    montgomery_multiplication res, pa1, pb1, q, qinv
    str   res, [c_ptr], #4
    montgomery_multiplication res, pa2, pb2, q, qinv
    str   res, [c_ptr], #4
    subs  ctr, #1
    bne.w 1b

    /* final coefficient */
    ldr.w pa0, [a_ptr]
    ldr.w pb0, [b_ptr]
    montgomery_multiplication res, pa0, pb0, q, qinv
    str.w res, [c_ptr]

    pop.w {r4-r11, pc}

    .unreq c_ptr
    .unreq a_ptr
    .unreq b_ptr
    .unreq qinv
    .unreq q
    .unreq pa0
    .unreq pa1
    .unreq pa2
    .unreq pb0
    .unreq pb1
    .unreq pb2
    .unreq ctr
    .unreq res
.size PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery_asm, . - PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery_asm

/* ML-DSA-44 alias: param-set independent (same ring, same Q, same N). */
.global PQCLEAN_MLDSA44_CLEAN_poly_pointwise_montgomery_asm
.set    PQCLEAN_MLDSA44_CLEAN_poly_pointwise_montgomery_asm, PQCLEAN_MLDSA65_CLEAN_poly_pointwise_montgomery_asm


/* ------------------------------------------------------------------ */
/* poly_reduce  (Barrett-style reduce32 of 256 int32 coefficients)     */
/*   redq(a): t = (a + 2^22) >> 23 ;  a = a - t*Q                       */
/* ------------------------------------------------------------------ */
.macro redq a, tmp, q
    add  \tmp, \a, #4194304
    asrs \tmp, \tmp, #23
    mls  \a, \tmp, \q, \a
.endm

.global PQCLEAN_MLDSA65_CLEAN_poly_reduce_asm
.type   PQCLEAN_MLDSA65_CLEAN_poly_reduce_asm, %function
.thumb_func
.align 2
PQCLEAN_MLDSA65_CLEAN_poly_reduce_asm:
    push {r4-r10}

    movw r12, #:lower16:8380417
    movt r12, #:upper16:8380417
    movw r10, #32          /* 32 iterations × 8 coeffs = 256 */
1:
    /* ldmia/stmia replace 8x ldr.w/str.w (-7 cycles each on the inner loop;
     * total ≈ -14 cyc/iter × 32 iter = -448 cyc per poly_reduce). */
    ldmia r0, {r1-r8}

    redq r1, r9, r12
    redq r2, r9, r12
    redq r3, r9, r12
    redq r4, r9, r12
    redq r5, r9, r12
    redq r6, r9, r12
    redq r7, r9, r12
    redq r8, r9, r12

    stmia r0!, {r1-r8}
    subs  r10, #1
    bne.w 1b

    pop {r4-r10}
    bx lr
.size PQCLEAN_MLDSA65_CLEAN_poly_reduce_asm, . - PQCLEAN_MLDSA65_CLEAN_poly_reduce_asm

.global PQCLEAN_MLDSA44_CLEAN_poly_reduce_asm
.set    PQCLEAN_MLDSA44_CLEAN_poly_reduce_asm, PQCLEAN_MLDSA65_CLEAN_poly_reduce_asm


/* ------------------------------------------------------------------ */
/* poly_caddq  (conditional Q-add for negative coefficients)            */
/*   caddq(a): t = (a >> 31) & q ;  a = a + t                           */
/* ------------------------------------------------------------------ */
.macro caddq_m a, tmp, q
    and \tmp, \q, \a, asr #31
    add \a, \a, \tmp
.endm

.global PQCLEAN_MLDSA65_CLEAN_poly_caddq_asm
.type   PQCLEAN_MLDSA65_CLEAN_poly_caddq_asm, %function
.thumb_func
.align 2
PQCLEAN_MLDSA65_CLEAN_poly_caddq_asm:
    push {r4-r10}

    movw r12, #:lower16:8380417
    movt r12, #:upper16:8380417

    movw r10, #32
1:
    ldmia r0, {r1-r8}

    caddq_m r1, r9, r12
    caddq_m r2, r9, r12
    caddq_m r3, r9, r12
    caddq_m r4, r9, r12
    caddq_m r5, r9, r12
    caddq_m r6, r9, r12
    caddq_m r7, r9, r12
    caddq_m r8, r9, r12

    stmia r0!, {r1-r8}
    subs  r10, #1
    bne.w 1b

    pop {r4-r10}
    bx lr
.size PQCLEAN_MLDSA65_CLEAN_poly_caddq_asm, . - PQCLEAN_MLDSA65_CLEAN_poly_caddq_asm

.global PQCLEAN_MLDSA44_CLEAN_poly_caddq_asm
.set    PQCLEAN_MLDSA44_CLEAN_poly_caddq_asm, PQCLEAN_MLDSA65_CLEAN_poly_caddq_asm


/* ------------------------------------------------------------------ */
/* poly_add / poly_sub  (no modular reduction; vector int32 op)         */
/*   Using ldmia/stmia for 8-coeff blocks: 256 / 8 = 32 iterations.     */
/*   Per iteration: 9 + 8 + 9 ≈ 26 cycles vs ~32 from tight C loop.     */
/* ------------------------------------------------------------------ */
.global PQCLEAN_MLDSA65_CLEAN_poly_add_asm
.type   PQCLEAN_MLDSA65_CLEAN_poly_add_asm, %function
.thumb_func
.align 2
PQCLEAN_MLDSA65_CLEAN_poly_add_asm:
    push.w {r4-r11, lr}
    /* r0 = c, r1 = a, r2 = b */
    movw  r12, #32
1:
    ldmia r1!, {r3, r4, r5, r6, r7, r8, r9, r10}
    ldmia r2!, {r11, lr}
    add.w r3, r3, r11
    add.w r4, r4, lr
    ldmia r2!, {r11, lr}
    add.w r5, r5, r11
    add.w r6, r6, lr
    ldmia r2!, {r11, lr}
    add.w r7, r7, r11
    add.w r8, r8, lr
    ldmia r2!, {r11, lr}
    add.w r9, r9, r11
    add.w r10, r10, lr
    stmia r0!, {r3, r4, r5, r6, r7, r8, r9, r10}
    subs  r12, #1
    bne.w 1b
    pop.w {r4-r11, pc}
.size PQCLEAN_MLDSA65_CLEAN_poly_add_asm, . - PQCLEAN_MLDSA65_CLEAN_poly_add_asm

.global PQCLEAN_MLDSA44_CLEAN_poly_add_asm
.set    PQCLEAN_MLDSA44_CLEAN_poly_add_asm, PQCLEAN_MLDSA65_CLEAN_poly_add_asm


.global PQCLEAN_MLDSA65_CLEAN_poly_sub_asm
.type   PQCLEAN_MLDSA65_CLEAN_poly_sub_asm, %function
.thumb_func
.align 2
PQCLEAN_MLDSA65_CLEAN_poly_sub_asm:
    push.w {r4-r11, lr}
    movw  r12, #32
1:
    ldmia r1!, {r3, r4, r5, r6, r7, r8, r9, r10}
    ldmia r2!, {r11, lr}
    sub.w r3, r3, r11
    sub.w r4, r4, lr
    ldmia r2!, {r11, lr}
    sub.w r5, r5, r11
    sub.w r6, r6, lr
    ldmia r2!, {r11, lr}
    sub.w r7, r7, r11
    sub.w r8, r8, lr
    ldmia r2!, {r11, lr}
    sub.w r9, r9, r11
    sub.w r10, r10, lr
    stmia r0!, {r3, r4, r5, r6, r7, r8, r9, r10}
    subs  r12, #1
    bne.w 1b
    pop.w {r4-r11, pc}
.size PQCLEAN_MLDSA65_CLEAN_poly_sub_asm, . - PQCLEAN_MLDSA65_CLEAN_poly_sub_asm

.global PQCLEAN_MLDSA44_CLEAN_poly_sub_asm
.set    PQCLEAN_MLDSA44_CLEAN_poly_sub_asm, PQCLEAN_MLDSA65_CLEAN_poly_sub_asm


/* ------------------------------------------------------------------ */
/* rej_uniform  (port of pqm3 vector.s asm_rej_uniform)                 */
/*   Sample uniform mod-Q coeffs from a buffer of bytes.  Reads 3 bytes,*/
/*   masks to 23 bits via ubfx, accepts if < Q.  ubfx is base ARMv7-M.  */
/*                                                                      */
/* unsigned int rej_uniform(int32_t *a, unsigned int len,               */
/*                          const uint8_t *buf, unsigned int buflen);   */
/*   r0 = a (out), r1 = len, r2 = buf, r3 = buflen.                     */
/*   Returns ctr (number of accepted samples).                          */
/* ------------------------------------------------------------------ */
.global PQCLEAN_MLDSA65_CLEAN_rej_uniform_asm
.type   PQCLEAN_MLDSA65_CLEAN_rej_uniform_asm, %function
.thumb_func
.align 2
PQCLEAN_MLDSA65_CLEAN_rej_uniform_asm:
    push.w {r4-r6}
    push.w {r1}                  /* save initial len for return ctr calc */
    /* r12 = Q-1 = 8380416 */
    movw r12, #:lower16:8380416
    movt r12, #:upper16:8380416

    add.w r6, r0, r1, lsl #2     /* r6 = end-of-output pointer (a + len*4) */
    add.w r3, r2, r3             /* r3 = end-of-buffer pointer */
    sub.w r3, r3, #2             /* leave 3 bytes available for last read */
1:
    cmp.w r3, r2
    ble.w 2f                     /* not enough buffer left → return */

    ldr   r5, [r2], #3           /* read 3 bytes (over-read OK; we mask) */
    ubfx  r5, r5, #0, #23        /* keep 23 bits */

    cmp.n r5, r12
    it    le
    strle r5, [r0], #4

    cmp.n r0, r6
    bne.n 1b
2:
    pop.w {r5}                   /* r5 = initial len */
    sub.w r0, r6, r0             /* r0 = (end - cur) bytes remaining */
    sub.w r0, r5, r0, lsr #2     /* r0 = ctr = len - remaining_count */
    pop.w {r4-r6}
    bx lr
.size PQCLEAN_MLDSA65_CLEAN_rej_uniform_asm, . - PQCLEAN_MLDSA65_CLEAN_rej_uniform_asm

.global PQCLEAN_MLDSA44_CLEAN_rej_uniform_asm
.set    PQCLEAN_MLDSA44_CLEAN_rej_uniform_asm, PQCLEAN_MLDSA65_CLEAN_rej_uniform_asm
