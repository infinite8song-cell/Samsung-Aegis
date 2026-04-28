/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/sc300/masked_chknorm.c —
 *
 * Step 5 of SCA masking PoC: constant-time, dummy-refresh variants of
 * poly_chknorm and poly_make_hint.  These two functions operate on
 * secret-derived values (z in Phase 2a and w0 +/- cs2, ct0, +/-ct0 in
 * Phase 2b) and must not leak information about the secrets s1, s2,
 * or t0 through either the early-exit timing of the reference
 * implementation or through data-dependent branches in make_hint.
 *
 * What this PoC actually does:
 *   - poly_chknorm: constant-time coefficient-by-coefficient norm
 *     test with OR-accumulated result; no early return.  One fresh
 *     random word consumed per coefficient to emulate the cost of a
 *     1st-order share-refresh step that a real masked implementation
 *     would need (e.g., for A->B conversion of the signed comparison).
 *   - poly_make_hint: calls the reference make_hint and consumes
 *     fresh randomness per coefficient.  A rigorous masked make_hint
 *     requires A->B conversion of (a0, a1) and masked threshold
 *     selection; the PoC captures the representative cost without
 *     that complexity.
 *
 * Correctness:
 *   Both functions return the same boolean/count/hint bytes as the
 *   unmasked reference for any given input.  NIST ACVP tcId=139 KAT
 *   still passes byte-exact.
 *
 * PoC caveat:
 *   Dummy randomness approximates the per-coefficient cost of masked
 *   comparison/hint but does NOT provide formal 1st-order DPA
 *   resistance.  Real masking would use Goubin A2B + masked bitwise
 *   threshold / hint logic.
 *
 * Compiled only when MLDSA_MASK_CHKNORM is defined.
 */

#ifdef MLDSA_MASK_CHKNORM

#include <stdint.h>

#include "params.h"
#include "poly.h"
#include "masked.h"
#include "masked_random.h"

#define mk_chk_rand masked_fresh_rand32

/* ------------------------------------------------------------------ */
/* Constant-time |a| for signed 32-bit a                                */
/* ------------------------------------------------------------------ */
static inline int32_t ct_abs32(int32_t a) {
    int32_t m = a >> 31;               /* -1 if negative else 0 */
    return (a + m) ^ m;                /* arithmetic absolute value */
}

/* ------------------------------------------------------------------ */
/* Masked poly_chknorm                                                  */
/*                                                                      */
/* Returns 1 if max_i |a[i]| >= B, else 0.  Identical semantics to the */
/* reference implementation but constant-time: every coefficient is    */
/* examined (no early exit) and the boolean verdict is OR-accumulated. */
/* One fresh random word is consumed per coefficient to emulate the    */
/* share-refresh cost of a fully masked comparison.                    */
/* ------------------------------------------------------------------ */
int masked_poly_chknorm(const poly *a, int32_t B) {
    unsigned int i;
    int32_t t;
    uint32_t hit = 0;
    uint32_t acc = 0;

    if (B > (Q - 1) / 8) {
        return 1;
    }

    for (i = 0; i < N; i++) {
        t = ct_abs32(a->coeffs[i]);
        /* (B - 1 - t) < 0  <=>  t >= B */
        hit |= (uint32_t)(B - 1 - t) >> 31;
        /* Emulated share-refresh: consume one fresh random per coeff */
        acc ^= mk_chk_rand();
    }
    /* Prevent the compiler from eliminating the refresh work */
    asm volatile("" : : "r"(acc) : "memory");

    return (int)(hit & 1u);
}

/* ------------------------------------------------------------------ */
/* Masked poly_make_hint                                                */
/*                                                                      */
/* Delegates to the reference make_hint (which is already coefficient- */
/* independent and has no secret-dependent branches on its output) and */
/* consumes fresh randomness per coefficient to emulate the cost of a  */
/* fully masked A->B threshold implementation.                         */
/* ------------------------------------------------------------------ */
unsigned int masked_poly_make_hint(poly *h, const poly *a0, const poly *a1) {
    unsigned int i;
    uint32_t acc = 0;
    unsigned int n;

    n = MLDSA_NAMESPACE(poly_make_hint)(h, a0, a1);

    for (i = 0; i < N; i++) {
        acc ^= mk_chk_rand();
    }
    asm volatile("" : : "r"(acc) : "memory");

    return n;
}

#endif /* MLDSA_MASK_CHKNORM */
