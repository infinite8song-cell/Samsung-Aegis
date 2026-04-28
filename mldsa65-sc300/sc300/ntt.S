/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/sc300/ntt.S — ARMv7-M Thumb-2 NTT for ML-DSA-65 (S8)
 *
 * No DSP extensions (no smlad/smuad/pkhbt). Uses only:
 *   smull  (32×32→64, signed, base ARMv7-M)
 *   smlal  (64-bit signed accumulate, base ARMv7-M)
 *   mul    (32×32→32 low)
 *
 * Montgomery: Q=8380417, QINV=58728449 (= -Q^{-1} mod 2^32 = 0x03802001)
 *
 * Forward NTT (Cooley-Tukey):
 *   for len in [128,64,32,16,8,4,2,1]:
 *     for each group:
 *       zeta = zetas[k++]
 *       for j in group: t=mont(zeta*a[j+len]); a[j+len]=a[j]-t; a[j]+=t
 *
 * Inverse NTT (Gentleman-Sande):
 *   for len in [1,2,4,...,128]:
 *     for each group:
 *       zeta = -zetas[--k]   (same table, reversed, negated)
 *       for j in group: t=a[j]; a[j]=t+a[j+len]; a[j+len]=mont(zeta*(t-a[j+len]))
 *   for j in [0..255]: a[j] = mont(41978 * a[j])
 *
 * Register layout (inner loops):
 *   r0  = lower-half pointer (&a[j])
 *   r1  = upper-half pointer (&a[j+len])
 *   r2  = a[j]
 *   r3  = a[j+len] / smull1_lo / scratch
 *   r4  = a-array base pointer (constant)
 *   r5  = QINV = 0x03802001
 *   r6  = Q    = 0x007FE001
 *   r7  = len  (round parameter)
 *   r8  = zeta-table pointer
 *   r9  = group-start pointer
 *   r10 = smull1_hi / montgomery result
 *   r11 = current zeta
 *   r12 = inner-loop counter
 *   lr  = t (= smull1_lo * QINV); repurposed per step
 */

.syntax unified
.thumb

.text

/* ------------------------------------------------------------------ */
/* Forward NTT                                                          */
/* ------------------------------------------------------------------ */
.global PQCLEAN_MLDSA65_CLEAN_ntt
.type   PQCLEAN_MLDSA65_CLEAN_ntt, %function
.thumb_func
PQCLEAN_MLDSA65_CLEAN_ntt:
    push    {r4-r11, lr}

    mov     r4, r0                      /* r4 = a base */

    movw    r5, #0x2001
    movt    r5, #0x0380                 /* r5 = QINV = 58728449 */

    movw    r6, #0xE001
    movt    r6, #0x007F                 /* r6 = Q = 8380417 */

    ldr     r8, =sc300_ntt_zetas
    add     r8, r8, #4                  /* r8 = &zetas[1] (skip zetas[0]=0) */

    mov     r7, #128                    /* r7 = len, start at 128 */

.Lntt_round:
    mov     r9, r4                      /* r9 = &a[start=0] */

.Lntt_group:
    ldr     r11, [r8], #4              /* r11 = zetas[k++] */

    mov     r0, r9                      /* r0 = &a[start] */
    add     r1, r9, r7, lsl #2         /* r1 = &a[start+len] */
    mov     r12, r7                     /* r12 = inner-loop count */

.Lntt_inner:
    ldr     r2,  [r0]
    ldr     r3,  [r1]
    smull   r3,  r10, r11, r3
    mul     lr,  r3, r5
    rsb     lr,  lr, #0
    smlal   r3,  r10, lr, r6
    sub     r3,  r2, r10
    add     r2,  r2, r10
    str     r2,  [r0], #4
    str     r3,  [r1], #4
    subs    r12, r12, #1
    bne     .Lntt_inner

.Lntt_group_end:
    mov     r9, r1                      /* next group start = end of upper half */
    add     r2, r4, #(256*4)
    cmp     r9, r2
    blo     .Lntt_group

    lsrs    r7, r7, #1
    cmp     r7, #2
    bhi     .Lntt_round                 /* loop while r7 > 2 (i.e. r7 >= 4) */

    /* --- Merged final two rounds: len=2 then len=1 ---
     * Process 4 consecutive coefficients per iteration (4 butterflies).
     * zeta indexing:
     *   r8 currently points at &zetas[64] (start of len=2 zetas; 64 entries)
     *   len=1 zetas follow at &zetas[128] (128 entries)
     *   Per quad: 1 shared zeta (len=2, 2 butterflies), 2 zetas (len=1).
     * Register layout:
     *   r0 = data ptr; r1 = end (&a[256])
     *   r2,r3,r11,r12 = a0,a1,a2,a3
     *   r4=base, r5=QINV, r6=Q
     *   r8 = zeta_len2 ptr; r9 = zeta_len1 ptr
     *   r10 = montgomery hi; lr = scratch (zeta / mul)               */
    mov     r0, r4                      /* p   = &a[0]            */
    add     r1, r4, #(256*4)            /* end = &a[256]          */
    add     r9, r8, #(64*4)             /* r9  = &zetas[len=1]    */

.Lntt_merged_loop:
    ldmia   r0, {r2, r3, r11, r12}     /* a0, a1, a2, a3         */

    /* --- len=2 butterfly on (a0, a2) using z_len2 --- */
    ldr     lr,  [r8]                   /* z_len2 (keep; reload next BF) */
    smull   r11, r10, lr, r11          /* {r10:r11} = z * a2     */
    mul     lr,  r11, r5
    rsb     lr,  lr, #0
    smlal   r11, r10, lr, r6           /* r10 = mont(z*a2) = t1  */
    sub     r11, r2,  r10              /* new a2 = a0 - t1       */
    add     r2,  r2,  r10              /* new a0 = a0 + t1       */

    /* --- len=2 butterfly on (a1, a3) same z_len2 --- */
    ldr     lr,  [r8], #4              /* reload z_len2, advance */
    smull   r12, r10, lr, r12          /* {r10:r12} = z * a3     */
    mul     lr,  r12, r5
    rsb     lr,  lr, #0
    smlal   r12, r10, lr, r6           /* r10 = t2               */
    sub     r12, r3,  r10              /* new a3 = a1 - t2       */
    add     r3,  r3,  r10              /* new a1 = a1 + t2       */

    /* --- len=1 butterfly on (a0, a1) using zeta_a --- */
    ldr     lr,  [r9], #4              /* z_len1_a               */
    smull   r3,  r10, lr, r3           /* {r10:r3} = z * a1      */
    mul     lr,  r3,  r5
    rsb     lr,  lr, #0
    smlal   r3,  r10, lr, r6           /* r10 = t3               */
    sub     r3,  r2,  r10              /* new a1 = a0 - t3       */
    add     r2,  r2,  r10              /* new a0 = a0 + t3       */

    /* --- len=1 butterfly on (a2, a3) using zeta_b --- */
    ldr     lr,  [r9], #4              /* z_len1_b               */
    smull   r12, r10, lr, r12          /* {r10:r12} = z * a3     */
    mul     lr,  r12, r5
    rsb     lr,  lr, #0
    smlal   r12, r10, lr, r6           /* r10 = t4               */
    sub     r12, r11, r10              /* new a3 = a2 - t4       */
    add     r11, r11, r10              /* new a2 = a2 + t4       */

    stmia   r0!, {r2, r3, r11, r12}    /* store a0..a3; r0 += 16 */
    cmp     r0,  r1
    blo     .Lntt_merged_loop

    pop     {r4-r11, pc}

.size PQCLEAN_MLDSA65_CLEAN_ntt, . - PQCLEAN_MLDSA65_CLEAN_ntt


/* ------------------------------------------------------------------ */
/* Inverse NTT                                                          */
/* ------------------------------------------------------------------ */
.global PQCLEAN_MLDSA65_CLEAN_invntt_tomont
.type   PQCLEAN_MLDSA65_CLEAN_invntt_tomont, %function
.thumb_func
PQCLEAN_MLDSA65_CLEAN_invntt_tomont:
    push    {r4-r11, lr}

    mov     r4, r0

    movw    r5, #0x2001
    movt    r5, #0x0380                 /* QINV */

    movw    r6, #0xE001
    movt    r6, #0x007F                 /* Q */

    /* r8 = &zetas[256] (one past end; pre-decrement reads go backward) */
    ldr     r8, =sc300_ntt_zetas
    add     r8, r8, #(256*4)

    mov     r7, #1                      /* r7 = len, start at 1 */

.Linvntt_round:
    mov     r9, r4

.Linvntt_group:
    ldr     r11, [r8, #-4]!            /* r11 = zetas[--k] */
    rsb     r11, r11, #0                /* r11 = -zetas[k] */

    mov     r0, r9
    add     r1, r9, r7, lsl #2
    mov     r12, r7

.Linvntt_inner:
    ldr     r2, [r0]                    /* r2 = a[j] = t */
    ldr     r3, [r1]                    /* r3 = a[j+len] */

    add     lr, r2, r3                  /* lr = t + a[j+len] = new a[j] */
    sub     r3, r2, r3                  /* r3 = t - a[j+len] */
    str     lr, [r0], #4               /* store new a[j] */

    /* t2 = mont(zeta * r3) → r10 */
    smull   r3, r10, r11, r3
    mul     lr, r3, r5
    rsb     lr, lr, #0
    smlal   r3, r10, lr, r6

    str     r10, [r1], #4
    subs    r12, r12, #1
    bne     .Linvntt_inner

    mov     r9, r1
    add     r2, r4, #(256*4)
    cmp     r9, r2
    blo     .Linvntt_group

    lsl     r7, r7, #1
    cmp     r7, #256
    blo     .Linvntt_round

    /* Final scaling: a[j] = mont(41978 * a[j]) for j=0..255 */
    mov     r0, r4
    movw    r11, #41978
    mov     r9, #256

.Linvntt_scale:
    ldr     r2, [r0]
    smull   r3, r10, r11, r2
    mul     lr, r3, r5
    rsb     lr, lr, #0
    smlal   r3, r10, lr, r6
    str     r10, [r0], #4
    subs    r9, r9, #1
    bne     .Linvntt_scale

    pop     {r4-r11, pc}

.size PQCLEAN_MLDSA65_CLEAN_invntt_tomont, . - PQCLEAN_MLDSA65_CLEAN_invntt_tomont

/* ML-DSA-44 aliases: NTT is param-independent (same ring Z_q[X]/(X^256+1)). */
.global PQCLEAN_MLDSA44_CLEAN_ntt
.set    PQCLEAN_MLDSA44_CLEAN_ntt, PQCLEAN_MLDSA65_CLEAN_ntt
.global PQCLEAN_MLDSA44_CLEAN_invntt_tomont
.set    PQCLEAN_MLDSA44_CLEAN_invntt_tomont, PQCLEAN_MLDSA65_CLEAN_invntt_tomont


/* ------------------------------------------------------------------ */
/* Zeta table (256 × int32, same values as ref/ntt.c)                  */
/* ------------------------------------------------------------------ */
.section .rodata
.balign 4
sc300_ntt_zetas:
    .word       0,    25847, -2608894,  -518909,   237124,  -777960,  -876248,   466468
    .word 1826347,  2353451,  -359251, -2091905,  3119733, -2884855,  3111497,  2680103
    .word 2725464,  1024112, -1079900,  3585928,  -549488, -1119584,  2619752, -2108549
    .word -2118186, -3859737, -1399561, -3277672,  1757237,   -19422,  4010497,   280005
    .word 2706023,    95776,  3077325,  3530437, -1661693, -3592148, -2537516,  3915439
    .word -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299
    .word -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596
    .word  811944,   531354,   954230,  3881043,  3900724, -2556880,  2071892, -2797779
    .word -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221
    .word -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922
    .word 3412210,  -983419,  2147896,  2715295, -2967645, -3693493,  -411027, -2477047
    .word  -671102, -1228525,   -22981, -1308169,  -381987,  1349076,  1852771, -1430430
    .word -3343383,   264944,   508951,  3097992,    44288, -1100098,   904516,  3958618
    .word -3724342,    -8578,  1653064, -3249728,  2389356,  -210977,   759969, -1316856
    .word  189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330
    .word 1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961
    .word 2091667,  3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462
    .word  266997,  2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378
    .word  900702,  1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500
    .word  -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838
    .word  342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044
    .word 2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974
    .word -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970
    .word -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642
    .word -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880,  3406031
    .word  -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993
    .word -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385
    .word -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107
    .word -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735,   472078
    .word  -426683,  1723600, -1803090,  1910376, -1667432, -1104333,  -260646, -3833893
    .word -2939036, -2235985,  -420899, -2286327,   183443,  -976891,  1612842, -3545687
    .word  -554416,  3919660,   -48306, -1362209,  3937738,  1400424,  -846154,  1976782
