/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300_kem/ntt.c — ML-KEM-768 NTT wrappers backed by sc300_kem/kyber_kernels.S.
 *
 * Replaces ref_kem/ntt.c.  Provides:
 *   - PQCLEAN_MLKEM768_CLEAN_zetas[128]      (original PQClean centered table,
 *                                             still consumed by ref_kem/poly.c
 *                                             basemul loop and by basemul wrappers)
 *   - PQCLEAN_MLKEM768_CLEAN_zetas_asm[128]      (interleaved, non-negative,
 *                                                 read by ntt_fast_m3)
 *   - PQCLEAN_MLKEM768_CLEAN_zetas_inv_asm[128]  (interleaved inverse,
 *                                                 read by invntt_fast_m3)
 *   - PQCLEAN_MLKEM768_CLEAN_zetas_basemul[64]   (pqm3 layout for basemul_asm_m3)
 *   - PQCLEAN_MLKEM768_CLEAN_ntt(r)        — calls assembly forward NTT
 *   - PQCLEAN_MLKEM768_CLEAN_invntt(r)     — calls assembly inverse NTT
 *   - PQCLEAN_MLKEM768_CLEAN_basemul(...)  — single-pair basemul kept as C so the
 *                                            existing PQClean basemul-loop in
 *                                            ref_kem/poly.c still works unmodified.
 *
 * The interleaved tables are reproduced verbatim from
 * mupq/pqm3 crypto_kem/kyber768/m3/ntt.c (zetas_asm / zetas_inv_asm).
 */

#include "ntt.h"
#include "params.h"
#include "reduce.h"
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* PQClean centered zetas — kept identical to upstream ref_kem/ntt.c.   */
/* Used by ref_kem/poly.c::poly_basemul_montgomery (2-coeff loop).      */
/* ------------------------------------------------------------------ */
const int16_t PQCLEAN_MLKEM768_CLEAN_zetas[128] = {
    -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
    -171,   622,  1577,   182,   962, -1202, -1474,  1468,
    573, -1325,   264,   383,  -829,  1458, -1602,  -130,
    -681,  1017,   732,   608, -1542,   411,  -205, -1571,
    1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
    516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
    -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
    -398,   961, -1508,  -725,   448, -1065,   677, -1275,
    -1103,   430,   555,   843, -1251,   871,  1550,   105,
    422,   587,   177,  -235,  -291,  -460,  1574,  1653,
    -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
    -1590,   644,  -872,   349,   418,   329,  -156,   -75,
    817,  1097,   603,   610,  1322, -1285, -1465,   384,
    -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
    -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
    -108,  -308,   996,   991,   958, -1460,  1522,  1628
};

/* ------------------------------------------------------------------ */
/* Interleaved forward-NTT zetas (pqm3 layout)                          */
/*   layout: 7 zetas for layers 7+6+5, then 8x7 zetas for 4+3+2,        */
/*           then 64 zetas for layer 1 (skip layer 0).                  */
/* All values ∈ [0, q-1].                                               */
/* ------------------------------------------------------------------ */
const int16_t PQCLEAN_MLKEM768_CLEAN_zetas_asm[128] = {
    /* layers 7+6+5 */
    2571, 2970, 1812, 1493, 1422, 287, 202,
    /* 1st loop of 4+3+2 */
    3158, 573, 2004, 1223, 652, 2777, 1015,
    /* 2nd loop of 4+3+2 */
    622, 264, 383, 2036, 1491, 3047, 1785,
    /* 3rd loop of 4+3+2 */
    1577, 2500, 1458, 516, 3321, 3009, 2663,
    /* 4th loop of 4+3+2 */
    182, 1727, 3199, 1711, 2167, 126, 1469,
    /* 5th loop of 4+3+2 */
    962, 2648, 1017, 2476, 3239, 3058, 830,
    /* 6th loop of 4+3+2 */
    2127, 732, 608, 107, 1908, 3082, 2378,
    /* 7th loop of 4+3+2 */
    1855, 1787, 411, 2931, 961, 1821, 2604,
    /* 8th loop of 4+3+2 */
    1468, 3124, 1758, 448, 2264, 677, 2054,
    /* layer 1 */
    2226, 430, 555, 843, 2078, 871, 1550, 105,
    422, 587, 177, 3094, 3038, 2869, 1574, 1653,
    3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739, 644, 2457, 349, 418, 329, 3173, 3254,
    817, 1097, 603, 610, 1322, 2044, 1864, 384,
    2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
    2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
    3221, 3021, 996, 991, 958, 1869, 1522, 1628
};

const int16_t PQCLEAN_MLKEM768_CLEAN_zetas_inv_asm[128] = {
    /* layer 1 */
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108,
    2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109, 874, 1335, 2111, 136, 1215,
    2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
    75, 156, 3000, 2911, 2980, 872, 2685, 1590,
    2210, 602, 1846, 777, 147, 2170, 2551, 246,
    1676, 1755, 460, 291, 235, 3152, 2742, 2907,
    3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103,
    /* 1st loop of 2+3+4 */
    1275, 2652, 1065, 2881, 1571, 205, 1861,
    /* 2nd loop of 2+3+4 */
    725, 1508, 2368, 398, 2918, 1542, 1474,
    /* 3rd loop of 2+3+4 */
    951, 247, 1421, 3222, 2721, 2597, 1202,
    /* 4th loop of 2+3+4 */
    2499, 271, 90, 853, 2312, 681, 2367,
    /* 5th loop of 2+3+4 */
    1860, 3203, 1162, 1618, 130, 1602, 3147,
    /* 6th loop of 2+3+4 */
    666, 320, 8, 2813, 1871, 829, 1752,
    /* 7th loop of 2+3+4 */
    1544, 282, 1838, 1293, 2946, 3065, 2707,
    /* 8th loop of 2+3+4 */
    2314, 552, 2677, 2106, 1325, 2756, 171,
    /* layers 5+6+7 */
    3127, 3042, 1907, 1836, 1517, 359, 1932,
    /* 128^-1 * 2^32 mod q (final scaling factor for layer-7 fqmulprecomp) */
    1441
};

/* ------------------------------------------------------------------ */
/* Basemul zetas (pqm3 layout, 64 positive entries, exposed for use     */
/* by sc300_kem/poly_asm.c if/when the basemul loop is replaced).       */
/* ------------------------------------------------------------------ */
const int16_t PQCLEAN_MLKEM768_CLEAN_zetas_basemul[64] = {
    2226, 430, 555, 843, 2078, 871, 1550, 105,
    422, 587, 177, 3094, 3038, 2869, 1574, 1653,
    3083, 778, 1159, 3182, 2552, 1483, 2727, 1119,
    1739, 644, 2457, 349, 418, 329, 3173, 3254,
    817, 1097, 603, 610, 1322, 2044, 1864, 384,
    2114, 3193, 1218, 1994, 2455, 220, 2142, 1670,
    2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
    3221, 3021, 996, 991, 958, 1869, 1522, 1628
};

/* ------------------------------------------------------------------ */
/* Asm prototypes (defined in sc300_kem/kyber_kernels.S)                */
/* ------------------------------------------------------------------ */
extern void ntt_fast_m3(int16_t *poly, const int16_t *zetas);
extern void invntt_fast_m3(int16_t *poly, const int16_t *zetas);

/* ------------------------------------------------------------------ */
/* Public NTT entry points                                              */
/* ------------------------------------------------------------------ */
void PQCLEAN_MLKEM768_CLEAN_ntt(int16_t r[256]) {
    ntt_fast_m3(r, PQCLEAN_MLKEM768_CLEAN_zetas_asm);
}

void PQCLEAN_MLKEM768_CLEAN_invntt(int16_t r[256]) {
    invntt_fast_m3(r, PQCLEAN_MLKEM768_CLEAN_zetas_inv_asm);
}

/* ------------------------------------------------------------------ */
/* Single-pair basemul (Z_q[X]/(X^2-zeta)).  Kept as C so that the      */
/* existing reference loop in ref_kem/poly.c still functions unmodified.*/
/* sc300_kem/poly_asm.c provides a higher-throughput basemul path that   */
/* operates on a full polynomial via pqm3's basemul_asm_m3 — but it is   */
/* opted-in via -DSC300_KYBER_BASEMUL_ASM to avoid forcing a layout      */
/* migration on callers that already work with the centered zetas.      */
/* ------------------------------------------------------------------ */
static int16_t fqmul(int16_t a, int16_t b) {
    return PQCLEAN_MLKEM768_CLEAN_montgomery_reduce((int32_t)a * b);
}

void PQCLEAN_MLKEM768_CLEAN_basemul(int16_t r[2],
                                    const int16_t a[2],
                                    const int16_t b[2],
                                    int16_t zeta) {
    r[0]  = fqmul(a[1], b[1]);
    r[0]  = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);
    r[1]  = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}
