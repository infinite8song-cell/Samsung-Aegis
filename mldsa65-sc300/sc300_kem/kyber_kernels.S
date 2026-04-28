/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300_kem/kyber_kernels.S — ARMv7-M Thumb-2 Kyber/ML-KEM-768 kernels for SC300.
 *
 * Direct port of pqm3 (mupq/pqm3) crypto_kem/kyber768/m3 hand-tuned assembly:
 *   - fastnttm3.S        (Markus Krausz's M3 NTT)
 *   - fastinvnttm3.S     (M3 inverse NTT)
 *   - kyberm3.S          (basemul, frommont, barrett_reduce, pointwise add/sub)
 *
 * No DSP extensions — uses only base ARMv7-M Thumb-2 (mul/mla/sxth/asr).
 * Toolchain target: ARMClang 6 (--target=arm-arm-none-eabi -mcpu=cortex-m3 -mthumb)
 *                   and arm-none-eabi-gcc Thumb-2.
 *
 * Internal entry points retain pqm3 names for audit-trail; PQCLEAN_MLKEM768_CLEAN_
 * aliases are provided for direct linkage from sc300_kem/ntt.c and (optionally)
 * sc300_kem/poly_asm.c.
 *
 * Calling convention:
 *   ntt_fast_m3       (int16_t *poly, const int16_t *zetas_asm)
 *   invntt_fast_m3    (int16_t *poly, const int16_t *zetas_inv_asm)
 *   basemul_asm_m3    (int16_t *r, const int16_t *a, const int16_t *b,
 *                      const int16_t *zetas_basemul)
 *   basemul_asm_acc_m3(int16_t *r, ..., const int16_t *zetas_basemul)
 *   doublebasemul_asm_m3      (int16_t *r, const int16_t *a, const int16_t *b,
 *                               int16_t zeta)   [single zeta, 4-coeff block]
 *   doublebasemul_asm_acc_m3  (int16_t *r, ..., int16_t zeta)
 *   asm_barrett_reduce_m3     (int16_t *r)
 *   asm_frommont_m3           (int16_t *r)     [r * R^{-1} mod q via Montgomery]
 *   pointwise_add_m3          (int16_t *r, const int16_t *a, const int16_t *b)
 *   pointwise_sub_m3          (int16_t *r, const int16_t *a, const int16_t *b)
 */

.syntax unified
.thumb

/* ------------------------------------------------------------------ */
/* Forward NTT (layered 7+6+5 / 4+3+2 / 1, skip layer 0)               */
/* ------------------------------------------------------------------ */
.macro butterflym3 a0, a1, twiddle, q, qinv, tmp
    mul.w \a1, \a1, \twiddle
    mul.w \tmp, \a1, \qinv
    sxth.w \tmp, \tmp
    mla.w \tmp, \tmp, \q, \a1
    sub.w \a1, \a0, \tmp, asr#16
    add.w \a0, \a0, \tmp, asr#16
.endm

.macro barrettm3 a, tmp, q, barrettconst
    mul.w \tmp, \a, \barrettconst
    asr.w \tmp, \tmp, #26
    mul.w \tmp, \tmp, \q
    sub.w \a, \a, \tmp
.endm

.global ntt_fast_m3
.type   ntt_fast_m3, %function
.thumb_func
.align 2
ntt_fast_m3:
    push.w {r4-r11, r14}

    poly        .req r0
    twiddle_ptr .req r1
    poly0       .req r2
    poly1       .req r3
    poly2       .req r4
    poly3       .req r5
    poly4       .req r6
    poly5       .req r7
    poly6       .req r8
    poly7       .req r9
    twiddle     .req r10
    barrettconst .req r10
    qinv        .req r11
    q           .req r12
    tmp         .req r14

    .equ ntt_barrett_constant, 20159

    movw qinv, #3327
    movw q, #3329

    /* LAYER 7+6+5 */
    movw tmp, #32
1:
    push.w {tmp}

    ldrsh.w poly0, [poly]
    ldrsh.w poly1, [poly, #64]
    ldrsh.w poly2, [poly, #128]
    ldrsh.w poly3, [poly, #192]
    ldrsh.w poly4, [poly, #256]
    ldrsh.w poly5, [poly, #320]
    ldrsh.w poly6, [poly, #384]
    ldrsh.w poly7, [poly, #448]

    ldrsh.w twiddle, [twiddle_ptr]
    butterflym3 poly0, poly4, twiddle, q, qinv, tmp
    butterflym3 poly1, poly5, twiddle, q, qinv, tmp
    butterflym3 poly2, poly6, twiddle, q, qinv, tmp
    butterflym3 poly3, poly7, twiddle, q, qinv, tmp

    ldrsh.w twiddle, [twiddle_ptr, #2]
    butterflym3 poly0, poly2, twiddle, q, qinv, tmp
    butterflym3 poly1, poly3, twiddle, q, qinv, tmp
    ldrsh.w twiddle, [twiddle_ptr, #4]
    butterflym3 poly4, poly6, twiddle, q, qinv, tmp
    butterflym3 poly5, poly7, twiddle, q, qinv, tmp

    ldrsh.w twiddle, [twiddle_ptr, #6]
    butterflym3 poly0, poly1, twiddle, q, qinv, tmp
    ldrsh.w twiddle, [twiddle_ptr, #8]
    butterflym3 poly2, poly3, twiddle, q, qinv, tmp
    ldrsh.w twiddle, [twiddle_ptr, #10]
    butterflym3 poly4, poly5, twiddle, q, qinv, tmp
    ldrsh.w twiddle, [twiddle_ptr, #12]
    butterflym3 poly6, poly7, twiddle, q, qinv, tmp

    strh.w poly1, [poly, #64]
    strh.w poly2, [poly, #128]
    strh.w poly3, [poly, #192]
    strh.w poly4, [poly, #256]
    strh.w poly5, [poly, #320]
    strh.w poly6, [poly, #384]
    strh.w poly7, [poly, #448]
    strh.w poly0, [poly], #2

    pop.w {tmp}
    subs.w tmp, #1
    bne.w 1b

    sub.w poly, #64
    add.w twiddle_ptr, #14

    /* LAYER 4+3+2 */
    movw tmp, #8
2:
    push.w {tmp}

    .set k, 1
    .rept 4
      ldrsh.w poly0, [poly]
      ldrsh.w poly1, [poly, #8]
      ldrsh.w poly2, [poly, #16]
      ldrsh.w poly3, [poly, #24]
      ldrsh.w poly4, [poly, #32]
      ldrsh.w poly5, [poly, #40]
      ldrsh.w poly6, [poly, #48]
      ldrsh.w poly7, [poly, #56]

      ldrsh.w twiddle, [twiddle_ptr]
      butterflym3 poly0, poly4, twiddle, q, qinv, tmp
      butterflym3 poly1, poly5, twiddle, q, qinv, tmp
      butterflym3 poly2, poly6, twiddle, q, qinv, tmp
      butterflym3 poly3, poly7, twiddle, q, qinv, tmp

      ldrsh.w twiddle, [twiddle_ptr, #2]
      butterflym3 poly0, poly2, twiddle, q, qinv, tmp
      butterflym3 poly1, poly3, twiddle, q, qinv, tmp
      ldrsh.w twiddle, [twiddle_ptr, #4]
      butterflym3 poly4, poly6, twiddle, q, qinv, tmp
      butterflym3 poly5, poly7, twiddle, q, qinv, tmp

      ldrsh.w twiddle, [twiddle_ptr, #6]
      butterflym3 poly0, poly1, twiddle, q, qinv, tmp
      ldrsh.w twiddle, [twiddle_ptr, #8]
      butterflym3 poly2, poly3, twiddle, q, qinv, tmp
      ldrsh.w twiddle, [twiddle_ptr, #10]
      butterflym3 poly4, poly5, twiddle, q, qinv, tmp
      ldrsh.w twiddle, [twiddle_ptr, #12]
      butterflym3 poly6, poly7, twiddle, q, qinv, tmp

      strh.w poly1, [poly, #8]
      strh.w poly2, [poly, #16]
      strh.w poly3, [poly, #24]
      strh.w poly4, [poly, #32]
      strh.w poly5, [poly, #40]
      strh.w poly6, [poly, #48]
      strh.w poly7, [poly, #56]
      .if k != 4
      strh.w poly0, [poly], #2
      .else
      strh.w poly0, [poly], #58
      .endif
      .set k, k+1
    .endr
    add.w twiddle_ptr, #14

    pop.w {tmp}
    subs.w tmp, #1
    bne.w 2b

    sub.w poly, #512

    /* LAYER 1 (skip layer 0) */
    movw tmp, #32
4:
    push.w {tmp}

    ldrsh.w poly0, [poly]
    ldrsh.w poly1, [poly, #2]
    ldrsh.w poly2, [poly, #4]
    ldrsh.w poly3, [poly, #6]
    ldrsh.w poly4, [poly, #8]
    ldrsh.w poly5, [poly, #10]
    ldrsh.w poly6, [poly, #12]
    ldrsh.w poly7, [poly, #14]

    ldrsh.w twiddle, [twiddle_ptr], #2
    butterflym3 poly0, poly2, twiddle, q, qinv, tmp
    butterflym3 poly1, poly3, twiddle, q, qinv, tmp
    ldrsh.w twiddle, [twiddle_ptr], #2
    butterflym3 poly4, poly6, twiddle, q, qinv, tmp
    butterflym3 poly5, poly7, twiddle, q, qinv, tmp

    movw barrettconst, #ntt_barrett_constant
    barrettm3 poly0, tmp, q, barrettconst
    barrettm3 poly1, tmp, q, barrettconst
    barrettm3 poly2, tmp, q, barrettconst
    barrettm3 poly3, tmp, q, barrettconst
    barrettm3 poly4, tmp, q, barrettconst
    barrettm3 poly5, tmp, q, barrettconst
    barrettm3 poly6, tmp, q, barrettconst
    barrettm3 poly7, tmp, q, barrettconst

    strh.w poly1, [poly, #2]
    strh.w poly2, [poly, #4]
    strh.w poly3, [poly, #6]
    strh.w poly4, [poly, #8]
    strh.w poly5, [poly, #10]
    strh.w poly6, [poly, #12]
    strh.w poly7, [poly, #14]
    strh.w poly0, [poly], #16

    pop.w {tmp}
    subs.w tmp, #1
    bne.w 4b
    pop.w {r4-r11, pc}

    .unreq poly
    .unreq twiddle_ptr
    .unreq poly0
    .unreq poly1
    .unreq poly2
    .unreq poly3
    .unreq poly4
    .unreq poly5
    .unreq poly6
    .unreq poly7
    .unreq twiddle
    .unreq barrettconst
    .unreq qinv
    .unreq q
    .unreq tmp
.size ntt_fast_m3, . - ntt_fast_m3

.global PQCLEAN_MLKEM768_CLEAN_ntt_fast_asm
.set    PQCLEAN_MLKEM768_CLEAN_ntt_fast_asm, ntt_fast_m3


/* ------------------------------------------------------------------ */
/* Inverse NTT (layered 1 / 2+3+4 / 5+6+7, multiplied by 2^16/128)     */
/* ------------------------------------------------------------------ */
.macro montgomerym3 q, qinv, a, tmp
    mul.w \tmp, \a, \qinv
    sxth.w \tmp, \tmp
    mla.w \a, \tmp, \q, \a
    asr.w \a, \a, #16
.endm

.macro gsbutterflym3 poly0, poly1, twiddle, tmp, q, qinv
    sub.w \tmp, \poly0, \poly1
    add.w \poly0, \poly0, \poly1

    mul.w \poly1, \tmp, \twiddle
    montgomerym3 \q, \qinv, \poly1, \tmp
.endm

.macro fqmulprecompm3 a, twiddle, tmp, q, qinv
    mul.w \a, \a, \twiddle
    montgomerym3 \q, \qinv, \a, \tmp
.endm

.macro signed_barrettm3 a, q, tmp, barrettconst
    mul.w \tmp, \a, \barrettconst
    /* +2^26 */
    add.w \tmp, \tmp, #67108864
    asr.w \tmp, \tmp, #27
    mla.w \a, \tmp, \q, \a
.endm

.global invntt_fast_m3
.type   invntt_fast_m3, %function
.thumb_func
.align 2
invntt_fast_m3:
    push.w {r4-r11, r14}

    poly        .req r0
    twiddle_ptr .req r1
    poly0       .req r2
    poly1       .req r3
    poly2       .req r4
    poly3       .req r5
    poly4       .req r6
    poly5       .req r7
    poly6       .req r8
    poly7       .req r9
    twiddle     .req r10
    montconst   .req r10
    barrettconst .req r10

    qinv        .req r14
    q           .req r11
    tmp         .req r12

    movw q, #3329
    movw qinv, #3327

    /* LAYER 1 (skip layer 0) */
    movw tmp, #32
1:
    push.w {tmp}

    ldrsh.w poly0, [poly, #0]
    ldrsh.w poly1, [poly, #2]
    ldrsh.w poly2, [poly, #4]
    ldrsh.w poly3, [poly, #6]
    ldrsh.w poly4, [poly, #8]
    ldrsh.w poly5, [poly, #10]
    ldrsh.w poly6, [poly, #12]
    ldrsh.w poly7, [poly, #14]

    ldrsh.w twiddle, [twiddle_ptr], #2
    gsbutterflym3 poly0, poly2, twiddle, tmp, q, qinv
    gsbutterflym3 poly1, poly3, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr], #2
    gsbutterflym3 poly4, poly6, twiddle, tmp, q, qinv
    gsbutterflym3 poly5, poly7, twiddle, tmp, q, qinv

    /* signed barrett with const = -40318 (sxth of 25218) */
    movw barrettconst, #25218
    sxth barrettconst, barrettconst
    signed_barrettm3 poly0, q, tmp, barrettconst
    signed_barrettm3 poly1, q, tmp, barrettconst
    signed_barrettm3 poly4, q, tmp, barrettconst
    signed_barrettm3 poly5, q, tmp, barrettconst

    strh.w poly1, [poly, #2]
    strh.w poly2, [poly, #4]
    strh.w poly3, [poly, #6]
    strh.w poly4, [poly, #8]
    strh.w poly5, [poly, #10]
    strh.w poly6, [poly, #12]
    strh.w poly7, [poly, #14]
    strh.w poly0, [poly], #16

    pop.w {tmp}
    subs.w tmp, #1
    bne.w 1b

    sub.w poly, #512

    /* LAYER 2+3+4 */
    movw tmp, #8
2:
    push.w {tmp}

    .set k, 1
    .rept 4
    ldrsh.w poly0, [poly, #0]
    ldrsh.w poly1, [poly, #8]
    ldrsh.w poly2, [poly, #16]
    ldrsh.w poly3, [poly, #24]
    ldrsh.w poly4, [poly, #32]
    ldrsh.w poly5, [poly, #40]
    ldrsh.w poly6, [poly, #48]
    ldrsh.w poly7, [poly, #56]

    ldrsh.w twiddle, [twiddle_ptr, #0]
    gsbutterflym3 poly0, poly1, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #2]
    gsbutterflym3 poly2, poly3, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #4]
    gsbutterflym3 poly4, poly5, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #6]
    gsbutterflym3 poly6, poly7, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #8]
    gsbutterflym3 poly0, poly2, twiddle, tmp, q, qinv
    gsbutterflym3 poly1, poly3, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #10]
    gsbutterflym3 poly4, poly6, twiddle, tmp, q, qinv
    gsbutterflym3 poly5, poly7, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #12]
    gsbutterflym3 poly0, poly4, twiddle, tmp, q, qinv
    gsbutterflym3 poly1, poly5, twiddle, tmp, q, qinv
    gsbutterflym3 poly2, poly6, twiddle, tmp, q, qinv
    gsbutterflym3 poly3, poly7, twiddle, tmp, q, qinv

    /* explicit Montgomery factor, since signed_barrett path was disabled
     * upstream (see pqm3 fastinvnttm3.S comment); 2285 = mont_const tuned
     * to keep coefficients small after layer-4. */
    movw montconst, #2285
    fqmulprecompm3 poly0, montconst, tmp, q, qinv
    fqmulprecompm3 poly1, montconst, tmp, q, qinv
    fqmulprecompm3 poly2, montconst, tmp, q, qinv
    fqmulprecompm3 poly3, montconst, tmp, q, qinv

    strh.w poly1, [poly, #8]
    strh.w poly2, [poly, #16]
    strh.w poly3, [poly, #24]
    strh.w poly4, [poly, #32]
    strh.w poly5, [poly, #40]
    strh.w poly6, [poly, #48]
    strh.w poly7, [poly, #56]
    .if k != 4
    strh.w poly0, [poly], #2
    .else
    strh.w poly0, [poly], #58
    .endif
    .set k, k+1
    .endr
    add.w twiddle_ptr, #14
    pop.w {tmp}
    subs.w tmp, #1
    bne.w 2b
    sub poly, #512

    /* LAYER 5+6+7 */
    movw tmp, #32
3:
    push.w {tmp}

    ldrsh.w poly0, [poly, #0]
    ldrsh.w poly1, [poly, #64]
    ldrsh.w poly2, [poly, #128]
    ldrsh.w poly3, [poly, #192]
    ldrsh.w poly4, [poly, #256]
    ldrsh.w poly5, [poly, #320]
    ldrsh.w poly6, [poly, #384]
    ldrsh.w poly7, [poly, #448]

    ldrsh.w twiddle, [twiddle_ptr]
    gsbutterflym3 poly0, poly1, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #2]
    gsbutterflym3 poly2, poly3, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #4]
    gsbutterflym3 poly4, poly5, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #6]
    gsbutterflym3 poly6, poly7, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #8]
    gsbutterflym3 poly0, poly2, twiddle, tmp, q, qinv
    gsbutterflym3 poly1, poly3, twiddle, tmp, q, qinv
    ldrsh.w twiddle, [twiddle_ptr, #10]
    gsbutterflym3 poly4, poly6, twiddle, tmp, q, qinv
    gsbutterflym3 poly5, poly7, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #12]
    gsbutterflym3 poly0, poly4, twiddle, tmp, q, qinv
    gsbutterflym3 poly1, poly5, twiddle, tmp, q, qinv
    gsbutterflym3 poly2, poly6, twiddle, tmp, q, qinv
    gsbutterflym3 poly3, poly7, twiddle, tmp, q, qinv

    ldrsh.w twiddle, [twiddle_ptr, #14]
    fqmulprecompm3 poly0, twiddle, tmp, q, qinv
    fqmulprecompm3 poly1, twiddle, tmp, q, qinv
    fqmulprecompm3 poly2, twiddle, tmp, q, qinv
    fqmulprecompm3 poly3, twiddle, tmp, q, qinv

    strh.w poly1, [poly, #64]
    strh.w poly2, [poly, #128]
    strh.w poly3, [poly, #192]
    strh.w poly4, [poly, #256]
    strh.w poly5, [poly, #320]
    strh.w poly6, [poly, #384]
    strh.w poly7, [poly, #448]
    strh.w poly0, [poly], #2

    pop.w {tmp}
    subs.w tmp, #1
    bne.w 3b
    pop.w {r4-r11, pc}

    .unreq poly
    .unreq twiddle_ptr
    .unreq poly0
    .unreq poly1
    .unreq poly2
    .unreq poly3
    .unreq poly4
    .unreq poly5
    .unreq poly6
    .unreq poly7
    .unreq twiddle
    .unreq montconst
    .unreq barrettconst
    .unreq qinv
    .unreq q
    .unreq tmp
.size invntt_fast_m3, . - invntt_fast_m3

.global PQCLEAN_MLKEM768_CLEAN_invntt_fast_asm
.set    PQCLEAN_MLKEM768_CLEAN_invntt_fast_asm, invntt_fast_m3


/* ------------------------------------------------------------------ */
/* Pointwise add / sub (256 int16 coefficients each)                   */
/* ------------------------------------------------------------------ */
.global pointwise_sub_m3
.type   pointwise_sub_m3, %function
.thumb_func
.align 2
pointwise_sub_m3:
    push.w {r4-r11, lr}

    movw r14, #51
1:
    ldrsh.w r4, [r1, #2]
    ldrsh.w r5, [r1, #4]
    ldrsh.w r6, [r1, #6]
    ldrsh.w r7, [r1, #8]
    ldrsh.w r3, [r1], #10
    ldrsh.w r9, [r2, #2]
    ldrsh.w r10, [r2, #4]
    ldrsh.w r11, [r2, #6]
    ldrsh.w r12, [r2, #8]
    ldrsh.w r8, [r2], #10

    sub.w r3, r3, r8
    sub.w r4, r4, r9
    sub.w r5, r5, r10
    sub.w r6, r6, r11
    sub.w r7, r7, r12

    strh.w r4, [r0, #2]
    strh.w r5, [r0, #4]
    strh.w r6, [r0, #6]
    strh.w r7, [r0, #8]
    strh.w r3, [r0], #10
    subs.w r14, #1
    bne.w 1b

    ldrsh.w r3, [r1]
    ldrsh.w r4, [r2]
    sub.w r3, r3, r4
    strh.w r3, [r0]

    pop.w {r4-r11, pc}
.size pointwise_sub_m3, . - pointwise_sub_m3

.global PQCLEAN_MLKEM768_CLEAN_poly_sub_asm
.set    PQCLEAN_MLKEM768_CLEAN_poly_sub_asm, pointwise_sub_m3


.global pointwise_add_m3
.type   pointwise_add_m3, %function
.thumb_func
.align 2
pointwise_add_m3:
    push.w {r4-r11, lr}
    movw.w r14, #51
1:
    ldrsh.w r4, [r1, #2]
    ldrsh.w r5, [r1, #4]
    ldrsh.w r6, [r1, #6]
    ldrsh.w r7, [r1, #8]
    ldrsh.w r3, [r1], #10
    ldrsh.w r9, [r2, #2]
    ldrsh.w r10, [r2, #4]
    ldrsh.w r11, [r2, #6]
    ldrsh.w r12, [r2, #8]
    ldrsh.w r8, [r2], #10

    add.w r3, r3, r8
    add.w r4, r4, r9
    add.w r5, r5, r10
    add.w r6, r6, r11
    add.w r7, r7, r12

    strh.w r4, [r0, #2]
    strh.w r5, [r0, #4]
    strh.w r6, [r0, #6]
    strh.w r7, [r0, #8]
    strh.w r3, [r0], #10
    subs.w r14, #1
    bne.w 1b

    ldrsh.w r3, [r1]
    ldrsh.w r4, [r2]
    add.w r3, r3, r4
    strh.w r3, [r0]
    pop.w {r4-r11, pc}
.size pointwise_add_m3, . - pointwise_add_m3

.global PQCLEAN_MLKEM768_CLEAN_poly_add_asm
.set    PQCLEAN_MLKEM768_CLEAN_poly_add_asm, pointwise_add_m3


/* ------------------------------------------------------------------ */
/* Barrett reduce (poly *r) — full polynomial in place                  */
/* ------------------------------------------------------------------ */
.macro barrettm3_b a, tmp, q, barrettconst
    mul.w \tmp, \a, \barrettconst
    asr.w \tmp, \tmp, #26
    mul.w \tmp, \tmp, \q
    sub.w \a, \a, \tmp
.endm

.global asm_barrett_reduce_m3
.type   asm_barrett_reduce_m3, %function
.thumb_func
.align 2
asm_barrett_reduce_m3:
    push.w {r4-r11, r14}

    poly        .req r0
    poly0       .req r1
    poly1       .req r2
    poly2       .req r3
    poly3       .req r4
    poly4       .req r5
    poly5       .req r6
    poly6       .req r7
    poly7       .req r8
    poly8       .req r14
    loop        .req r9
    barrettconst .req r10
    q           .req r11
    tmp         .req r12

    movw barrettconst, #20159
    movw q, #3329

    movw loop, #28
1:
    ldrsh.w poly0, [poly, #0]
    ldrsh.w poly1, [poly, #2]
    ldrsh.w poly2, [poly, #4]
    ldrsh.w poly3, [poly, #6]
    ldrsh.w poly4, [poly, #8]
    ldrsh.w poly5, [poly, #10]
    ldrsh.w poly6, [poly, #12]
    ldrsh.w poly7, [poly, #14]
    ldrsh.w poly8, [poly, #16]

    barrettm3_b poly0, tmp, q, barrettconst
    barrettm3_b poly1, tmp, q, barrettconst
    barrettm3_b poly2, tmp, q, barrettconst
    barrettm3_b poly3, tmp, q, barrettconst
    barrettm3_b poly4, tmp, q, barrettconst
    barrettm3_b poly5, tmp, q, barrettconst
    barrettm3_b poly6, tmp, q, barrettconst
    barrettm3_b poly7, tmp, q, barrettconst
    barrettm3_b poly8, tmp, q, barrettconst

    strh.w poly1, [poly, #2]
    strh.w poly2, [poly, #4]
    strh.w poly3, [poly, #6]
    strh.w poly4, [poly, #8]
    strh.w poly5, [poly, #10]
    strh.w poly6, [poly, #12]
    strh.w poly7, [poly, #14]
    strh.w poly8, [poly, #16]
    strh.w poly0, [poly], #18
    subs.w loop, #1
    bne.w 1b

    /* tail: 4 remaining (28*9 = 252, plus 4 = 256) */
    ldrsh.w poly0, [poly, #0]
    ldrsh.w poly1, [poly, #2]
    ldrsh.w poly2, [poly, #4]
    ldrsh.w poly3, [poly, #6]
    barrettm3_b poly0, tmp, q, barrettconst
    barrettm3_b poly1, tmp, q, barrettconst
    barrettm3_b poly2, tmp, q, barrettconst
    barrettm3_b poly3, tmp, q, barrettconst
    strh.w poly0, [poly, #0]
    strh.w poly1, [poly, #2]
    strh.w poly2, [poly, #4]
    strh.w poly3, [poly, #6]
    pop.w {r4-r11, pc}

    .unreq poly
    .unreq poly0
    .unreq poly1
    .unreq poly2
    .unreq poly3
    .unreq poly4
    .unreq poly5
    .unreq poly6
    .unreq poly7
    .unreq poly8
    .unreq loop
    .unreq barrettconst
    .unreq q
    .unreq tmp
.size asm_barrett_reduce_m3, . - asm_barrett_reduce_m3

.global PQCLEAN_MLKEM768_CLEAN_poly_reduce_asm
.set    PQCLEAN_MLKEM768_CLEAN_poly_reduce_asm, asm_barrett_reduce_m3


/* ------------------------------------------------------------------ */
/* poly_tomont (frommont) — multiply each coeff by 2^32 mod q          */
/* (constant 1353 = (2^32 mod q) * R^{-1} encoded for Mont)            */
/* ------------------------------------------------------------------ */
.macro montgomerym3_f q, qinv, a, tmp
    mul.w \tmp, \a, \qinv
    sxth.w \tmp, \tmp
    mla.w \a, \tmp, \q, \a
    asr.w \a, \a, #16
.endm

.global asm_frommont_m3
.type   asm_frommont_m3, %function
.thumb_func
.align 2
asm_frommont_m3:
    push.w {r4-r11, r14}

    poly        .req r0
    poly0       .req r1
    poly1       .req r2
    poly2       .req r3
    poly3       .req r4
    poly4       .req r5
    poly5       .req r6
    poly6       .req r7
    poly7       .req r8
    loop        .req r9
    constant    .req r10
    qinv        .req r14
    q           .req r11
    tmp         .req r12

    movw q, #3329
    movw qinv, #3327

    movw constant, #1353

    movw loop, #32
1:
    ldrsh.w poly0, [poly, #0]
    ldrsh.w poly1, [poly, #2]
    ldrsh.w poly2, [poly, #4]
    ldrsh.w poly3, [poly, #6]
    ldrsh.w poly4, [poly, #8]
    ldrsh.w poly5, [poly, #10]
    ldrsh.w poly6, [poly, #12]
    ldrsh.w poly7, [poly, #14]

    mul.w poly0, poly0, constant
    mul.w poly1, poly1, constant
    mul.w poly2, poly2, constant
    mul.w poly3, poly3, constant
    mul.w poly4, poly4, constant
    mul.w poly5, poly5, constant
    mul.w poly6, poly6, constant
    mul.w poly7, poly7, constant
    montgomerym3_f q, qinv, poly0, tmp
    montgomerym3_f q, qinv, poly1, tmp
    montgomerym3_f q, qinv, poly2, tmp
    montgomerym3_f q, qinv, poly3, tmp
    montgomerym3_f q, qinv, poly4, tmp
    montgomerym3_f q, qinv, poly5, tmp
    montgomerym3_f q, qinv, poly6, tmp
    montgomerym3_f q, qinv, poly7, tmp

    strh.w poly1, [poly, #2]
    strh.w poly2, [poly, #4]
    strh.w poly3, [poly, #6]
    strh.w poly4, [poly, #8]
    strh.w poly5, [poly, #10]
    strh.w poly6, [poly, #12]
    strh.w poly7, [poly, #14]
    strh.w poly0, [poly], #16

    subs.w loop, #1
    bne.w 1b

    pop.w {r4-r11, pc}

    .unreq poly
    .unreq poly0
    .unreq poly1
    .unreq poly2
    .unreq poly3
    .unreq poly4
    .unreq poly5
    .unreq poly6
    .unreq poly7
    .unreq loop
    .unreq constant
    .unreq qinv
    .unreq q
    .unreq tmp
.size asm_frommont_m3, . - asm_frommont_m3

.global PQCLEAN_MLKEM768_CLEAN_poly_tomont_asm
.set    PQCLEAN_MLKEM768_CLEAN_poly_tomont_asm, asm_frommont_m3


/* ------------------------------------------------------------------ */
/* doublebasemul (single 4-coeff block; r += or = a · b in Z_q[X^2-z]) */
/* ------------------------------------------------------------------ */
.macro montgomerym3_d q, qinv, a, tmp
    mul.w \tmp, \a, \qinv
    sxth.w \tmp, \tmp
    mla.w \a, \tmp, \q, \a
    asr.w \a, \a, #16
.endm

.global doublebasemul_asm_m3
.type   doublebasemul_asm_m3, %function
.thumb_func
.align 2
doublebasemul_asm_m3:
    push.w {r4-r11, lr}

    rptr  .req r0
    aptr  .req r1
    bptr  .req r2
    zeta  .req r3
    poly0 .req r4
    poly1 .req r6
    poly2 .req r5
    poly3 .req r7
    q     .req r8
    qinv  .req r14
    tmp   .req r9
    tmp2  .req r10

    movw  q, #3329
    movw qinv, #3327

    ldrsh.w poly0, [aptr, #0]
    ldrsh.w poly1, [aptr, #2]
    ldrsh.w poly2, [bptr, #0]
    ldrsh.w poly3, [bptr, #2]

    mul.w tmp, poly1, poly3
    montgomerym3_d q, qinv, tmp, tmp2
    mul.w tmp, tmp, zeta
    mla.w tmp, poly0, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    strh.w tmp, [rptr, #0]

    mul.w tmp, poly0, poly3
    mla.w tmp, poly1, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    strh.w tmp, [rptr, #2]

    neg.w zeta, zeta

    ldrsh.w poly0, [aptr, #4]
    ldrsh.w poly1, [aptr, #6]
    ldrsh.w poly2, [bptr, #4]
    ldrsh.w poly3, [bptr, #6]

    mul.w tmp, poly1, poly3
    montgomerym3_d q, qinv, tmp, tmp2
    mul.w tmp, tmp, zeta
    mla.w tmp, poly0, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    strh.w tmp, [rptr, #4]

    mul.w tmp, poly0, poly3
    mla.w tmp, poly1, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    strh.w tmp, [rptr, #6]

    pop.w {r4-r11, pc}

    .unreq rptr
    .unreq aptr
    .unreq bptr
    .unreq zeta
    .unreq poly0
    .unreq poly1
    .unreq poly2
    .unreq poly3
    .unreq q
    .unreq qinv
    .unreq tmp
    .unreq tmp2
.size doublebasemul_asm_m3, . - doublebasemul_asm_m3


.global doublebasemul_asm_acc_m3
.type   doublebasemul_asm_acc_m3, %function
.thumb_func
.align 2
doublebasemul_asm_acc_m3:
    push.w {r4-r11, lr}

    rptr  .req r0
    aptr  .req r1
    bptr  .req r2
    zeta  .req r3
    poly0 .req r4
    poly1 .req r6
    poly2 .req r5
    poly3 .req r7
    q     .req r8
    qinv  .req r11
    tmp   .req r9
    tmp2  .req r10
    res0  .req r12
    res1  .req r14

    movw  q, #3329
    movw qinv, #3327

    ldrsh.w poly0, [aptr, #0]
    ldrsh.w poly1, [aptr, #2]
    ldrsh.w poly2, [bptr, #0]
    ldrsh.w poly3, [bptr, #2]
    ldrsh.w res0, [rptr, #0]
    ldrsh.w res1, [rptr, #2]

    mul.w tmp, poly1, poly3
    montgomerym3_d q, qinv, tmp, tmp2
    mul.w tmp, tmp, zeta
    mla.w tmp, poly0, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    add.w res0, res0, tmp
    strh.w res0, [rptr, #0]

    mul.w tmp, poly0, poly3
    mla.w tmp, poly1, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    add.w res1, res1, tmp
    strh.w res1, [rptr, #2]

    neg.w zeta, zeta

    ldrsh.w poly0, [aptr, #4]
    ldrsh.w poly1, [aptr, #6]
    ldrsh.w poly2, [bptr, #4]
    ldrsh.w poly3, [bptr, #6]
    ldrsh.w res0, [rptr, #4]
    ldrsh.w res1, [rptr, #6]

    mul.w tmp, poly1, poly3
    montgomerym3_d q, qinv, tmp, tmp2
    mul.w tmp, tmp, zeta
    mla.w tmp, poly0, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    add.w res0, res0, tmp
    strh.w res0, [rptr, #4]

    mul.w tmp, poly0, poly3
    mla.w tmp, poly1, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    add.w res1, res1, tmp
    strh.w res1, [rptr, #6]

    pop.w {r4-r11, pc}

    .unreq rptr
    .unreq aptr
    .unreq bptr
    .unreq zeta
    .unreq poly0
    .unreq poly1
    .unreq poly2
    .unreq poly3
    .unreq q
    .unreq qinv
    .unreq tmp
    .unreq tmp2
    .unreq res0
    .unreq res1
.size doublebasemul_asm_acc_m3, . - doublebasemul_asm_acc_m3


/* ------------------------------------------------------------------ */
/* basemul / basemul_acc — full poly using zetaptr (64 zetas)          */
/* ------------------------------------------------------------------ */
.global basemul_asm_m3
.type   basemul_asm_m3, %function
.thumb_func
.align 2
basemul_asm_m3:
    push.w {r4-r11, lr}

    rptr    .req r0
    aptr    .req r1
    bptr    .req r2
    zetaptr .req r3
    poly0   .req r4
    poly1   .req r6
    poly2   .req r5
    poly3   .req r7
    q       .req r8
    qinv    .req r11
    tmp     .req r9
    tmp2    .req r10
    zeta    .req r12
    loop    .req r14

    movw q, #3329
    movw qinv, #3327

    movw loop, #64
1:
    ldrsh.w zeta, [zetaptr], #2

    ldrsh.w poly1, [aptr, #2]
    ldrsh.w poly0, [aptr], #4
    ldrsh.w poly3, [bptr, #2]
    ldrsh.w poly2, [bptr], #4

    mul.w tmp, poly1, poly3
    montgomerym3_d q, qinv, tmp, tmp2
    mul.w tmp, tmp, zeta
    mla.w tmp, poly0, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    strh.w tmp, [rptr], #2

    mul.w tmp, poly0, poly3
    mla.w tmp, poly1, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    strh.w tmp, [rptr], #2

    neg.w zeta, zeta

    ldrsh.w poly1, [aptr, #2]
    ldrsh.w poly0, [aptr], #4
    ldrsh.w poly3, [bptr, #2]
    ldrsh.w poly2, [bptr], #4

    mul.w tmp, poly1, poly3
    montgomerym3_d q, qinv, tmp, tmp2
    mul.w tmp, tmp, zeta
    mla.w tmp, poly0, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    strh.w tmp, [rptr], #2

    mul.w tmp, poly0, poly3
    mla.w tmp, poly1, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    strh.w tmp, [rptr], #2

    subs.w loop, #1
    bne.w 1b

    pop.w {r4-r11, pc}

    .unreq rptr
    .unreq aptr
    .unreq bptr
    .unreq zetaptr
    .unreq poly0
    .unreq poly1
    .unreq poly2
    .unreq poly3
    .unreq q
    .unreq qinv
    .unreq tmp
    .unreq tmp2
    .unreq zeta
    .unreq loop
.size basemul_asm_m3, . - basemul_asm_m3

.global PQCLEAN_MLKEM768_CLEAN_basemul_asm
.set    PQCLEAN_MLKEM768_CLEAN_basemul_asm, basemul_asm_m3


.global basemul_asm_acc_m3
.type   basemul_asm_acc_m3, %function
.thumb_func
.align 2
basemul_asm_acc_m3:
    push.w {r4-r11, lr}

    rptr    .req r0
    aptr    .req r1
    bptr    .req r2
    zetaptr .req r3
    poly0   .req r4
    poly1   .req r6
    poly2   .req r5
    poly3   .req r7
    q       .req r8
    qinv    .req r11
    tmp     .req r9
    tmp2    .req r10
    zeta    .req r12
    loop    .req r14

    movw q, #3329
    movw qinv, #3327

    movw loop, #64
1:
    ldrsh.w zeta, [zetaptr], #2

    ldrsh.w poly1, [aptr, #2]
    ldrsh.w poly0, [aptr], #4
    ldrsh.w poly3, [bptr, #2]
    ldrsh.w poly2, [bptr], #4

    mul.w tmp, poly1, poly3
    montgomerym3_d q, qinv, tmp, tmp2
    mul.w tmp, tmp, zeta
    mla.w tmp, poly0, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    ldrsh.w tmp2, [rptr]
    add.w tmp, tmp, tmp2
    strh.w tmp, [rptr], #2

    mul.w tmp, poly0, poly3
    mla.w tmp, poly1, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    ldrsh.w tmp2, [rptr]
    add.w tmp, tmp, tmp2
    strh.w tmp, [rptr], #2

    neg.w zeta, zeta

    ldrsh.w poly1, [aptr, #2]
    ldrsh.w poly0, [aptr], #4
    ldrsh.w poly3, [bptr, #2]
    ldrsh.w poly2, [bptr], #4

    mul.w tmp, poly1, poly3
    montgomerym3_d q, qinv, tmp, tmp2
    mul.w tmp, tmp, zeta
    mla.w tmp, poly0, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    ldrsh.w tmp2, [rptr]
    add.w tmp, tmp, tmp2
    strh.w tmp, [rptr], #2

    mul.w tmp, poly0, poly3
    mla.w tmp, poly1, poly2, tmp
    montgomerym3_d q, qinv, tmp, tmp2
    ldrsh.w tmp2, [rptr]
    add.w tmp, tmp, tmp2
    strh.w tmp, [rptr], #2

    subs.w loop, #1
    bne.w 1b

    pop.w {r4-r11, pc}
.size basemul_asm_acc_m3, . - basemul_asm_acc_m3

.global PQCLEAN_MLKEM768_CLEAN_basemul_acc_asm
.set    PQCLEAN_MLKEM768_CLEAN_basemul_acc_asm, basemul_asm_acc_m3
