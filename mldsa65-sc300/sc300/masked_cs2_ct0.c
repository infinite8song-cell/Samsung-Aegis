/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/sc300/masked_cs2_ct0.c —
 *
 * Step 3 of SCA masking PoC: arithmetic (mod q) masking of the
 * Phase 2b cs2 and ct0 chains.  For each per-k iteration in sign:
 *
 *   s2[k] / t0[k] unpacked -> held as (share_a, share_b)
 *   NTT on both shares
 *   cp * <share>hat on both shares                 (cp is public)
 *   INVNTT on both shares
 *   cs_res = share_a + share_b                     (combine)
 *
 * cs_res is then used unchanged by the surrounding sign logic
 *   (poly_sub for cs2, chknorm/add/make_hint for ct0).
 *
 * Correctness: same Z_q-linearity argument as Step 2.
 *
 * PoC scope: same as Step 2 — shares from xorshift64; replace with
 * TRNG for production deployment.
 *
 * Compiled only when MLDSA_MASK_CS2_CT0 is defined.
 */

#ifdef MLDSA_MASK_CS2_CT0

#include <stdint.h>
#include <stddef.h>

#include "params.h"
#include "poly.h"
#include "masked.h"
#include "masked_random.h"

#define masked_cs2_fresh_rand masked_fresh_rand32

/* ------------------------------------------------------------------ */
/* masked_cp_times_s                                                   */
/*                                                                      */
/* Given a poly `s_inout` holding the unmasked secret polynomial       */
/* (freshly unpacked from sk), compute                                  */
/*                                                                      */
/*     INVNTT(cp * NTT(s))                                             */
/*                                                                      */
/* in place under arithmetic (mod q) 1st-order masking:                */
/*                                                                      */
/*   s_a  <- uniform mod q                                             */
/*   s_b  <- s - s_a                (held in s_inout)                  */
/*   NTT(s_a), NTT(s_b)                                                */
/*   cp * s_a_hat, cp * s_b_hat                                        */
/*   INVNTT(each)                                                      */
/*   s_inout = s_a + s_b             (combine)                         */
/*                                                                      */
/* Caller supplies `share_buf` (one scratch poly, +1024 B stack).      */
/* ------------------------------------------------------------------ */
void masked_cp_times_s(poly *s_inout,
                        poly *share_buf,
                        const poly *cp) {
    unsigned int i;
    int32_t a;

    /* Random share s_a into share_buf, compute s_b = s - s_a in s_inout */
    for (i = 0; i < N; i++) {
        a = (int32_t)(masked_cs2_fresh_rand() % (uint32_t)Q);
        share_buf->coeffs[i] = a;
        s_inout->coeffs[i]  -= a;
    }

    /* NTT on both shares */
    MLDSA_NAMESPACE(poly_ntt)(share_buf);
    MLDSA_NAMESPACE(poly_ntt)(s_inout);

    /* cp * share_hat on both shares (cp public) */
    MLDSA_NAMESPACE(poly_pointwise_montgomery)(share_buf, cp, share_buf);
    MLDSA_NAMESPACE(poly_pointwise_montgomery)(s_inout,   cp, s_inout);

    /* INVNTT on both shares */
    MLDSA_NAMESPACE(poly_invntt_tomont)(share_buf);
    MLDSA_NAMESPACE(poly_invntt_tomont)(s_inout);

    /* Combine: s_inout <- share_a + share_b (= INVNTT(cp * NTT(s))) */
    for (i = 0; i < N; i++) {
        s_inout->coeffs[i] += share_buf->coeffs[i];
    }
}

#endif /* MLDSA_MASK_CS2_CT0 */
