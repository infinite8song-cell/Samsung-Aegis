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

    /* 85 iterations × 3 coefficients = 255 ; final coefficient handled below */
    movw ctr, #85
1:
    ldr.w pa1, [a_ptr, #4]
    ldr.w pa2, [a_ptr, #8]
    ldr   pa0, [a_ptr], #12
    ldr.w pb1, [b_ptr, #4]
    ldr.w pb2, [b_ptr, #8]
    ldr   pb0, [b_ptr], #12

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
    ldr.w r1, [r0]
    ldr.w r2, [r0, #1*4]
    ldr.w r3, [r0, #2*4]
    ldr.w r4, [r0, #3*4]
    ldr.w r5, [r0, #4*4]
    ldr.w r6, [r0, #5*4]
    ldr.w r7, [r0, #6*4]
    ldr.w r8, [r0, #7*4]

    redq r1, r9, r12
    redq r2, r9, r12
    redq r3, r9, r12
    redq r4, r9, r12
    redq r5, r9, r12
    redq r6, r9, r12
    redq r7, r9, r12
    redq r8, r9, r12

    str.w r2, [r0, #1*4]
    str.w r3, [r0, #2*4]
    str.w r4, [r0, #3*4]
    str.w r5, [r0, #4*4]
    str.w r6, [r0, #5*4]
    str.w r7, [r0, #6*4]
    str.w r8, [r0, #7*4]
    str   r1, [r0], #8*4
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
    ldr.w r1, [r0]
    ldr.w r2, [r0, #1*4]
    ldr.w r3, [r0, #2*4]
    ldr.w r4, [r0, #3*4]
    ldr.w r5, [r0, #4*4]
    ldr.w r6, [r0, #5*4]
    ldr.w r7, [r0, #6*4]
    ldr.w r8, [r0, #7*4]

    caddq_m r1, r9, r12
    caddq_m r2, r9, r12
    caddq_m r3, r9, r12
    caddq_m r4, r9, r12
    caddq_m r5, r9, r12
    caddq_m r6, r9, r12
    caddq_m r7, r9, r12
    caddq_m r8, r9, r12

    str.w r2, [r0, #1*4]
    str.w r3, [r0, #2*4]
    str.w r4, [r0, #3*4]
    str.w r5, [r0, #4*4]
    str.w r6, [r0, #5*4]
    str.w r7, [r0, #6*4]
    str.w r8, [r0, #7*4]
    str   r1, [r0], #8*4
    subs  r10, #1
    bne.w 1b

    pop {r4-r10}
    bx lr
.size PQCLEAN_MLDSA65_CLEAN_poly_caddq_asm, . - PQCLEAN_MLDSA65_CLEAN_poly_caddq_asm

.global PQCLEAN_MLDSA44_CLEAN_poly_caddq_asm
.set    PQCLEAN_MLDSA44_CLEAN_poly_caddq_asm, PQCLEAN_MLDSA65_CLEAN_poly_caddq_asm
