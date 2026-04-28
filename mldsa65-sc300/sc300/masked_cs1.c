/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/sc300/masked_cs1.c —
 *
 * Step 2 of SCA masking PoC: arithmetic (mod q) masking of the
 * cs1 chain in sign Phase 2a.  For each loop iteration l:
 *
 *   s1[l]  unpacked ------->  held as (s1_a, s1_b) with s1_a+s1_b = s1
 *   NTT(s1_a), NTT(s1_b)                          (linear, each share)
 *   cp * s1hat_a, cp * s1hat_b                     (cp is public)
 *   INVNTT(each)                                   (linear, each share)
 *   y = poly_uniform_gamma1(rhoprime, nonce)       (unmasked in Step 2)
 *   z = cs1_a + cs1_b + y                          (combine)
 *
 * Correctness:
 *   NTT is Z_q-linear, pmul is Z_q-linear in one operand (cp public),
 *   INVNTT is Z_q-linear -> cs1_a + cs1_b = INVNTT(cp * NTT(s1)) = cs1.
 *   Output z matches the unmasked computation byte-exact; KAT preserved.
 *
 * PoC scope:
 *   Arithmetic masking is genuine (not cost emulation). First-order DPA
 *   resistance for the cs1 chain holds under the standard threshold model
 *   when shares are drawn from a uniform random source. Fresh masks come
 *   from an xorshift64 seeded at load -- replace with TRNG/DRBG for
 *   production-grade leakage resistance.
 *
 * File is compiled only when MLDSA_MASK_CS1 is defined.
 */

#ifdef MLDSA_MASK_CS1

#include <stdint.h>
#include <stddef.h>

#include "params.h"
#include "poly.h"
#include "masked.h"
#include "masked_random.h"

/* Fresh randomness now comes from the shared masked_random.c */
#define masked_cs1_fresh_rand masked_fresh_rand32

/* ------------------------------------------------------------------ */
/* Masked Phase 2a kernel  (stack-optimised: no extra share buffer)    */
/*                                                                      */
/* Uses only two polys the caller already holds: z_out and y_buf.      */
/*  - During the NTT/pmul/INVNTT pipeline y_buf holds the random       */
/*    share s1_a (its value as "y_l" is not needed yet).               */
/*  - After combining shares into z_out we overwrite y_buf with the    */
/*    actual y_l sample and fold it into z_out.                        */
/*                                                                      */
/* Arithmetic-share invariants still hold throughout the chain:         */
/*   (NTT, pmul-by-public-cp, INVNTT) are all Z_q-linear, so           */
/*   y_buf + z_out  ==  INVNTT(cp * NTT(s1))  at every stage.          */
/* ------------------------------------------------------------------ */
void masked_cs1_compute_z_l(poly *z_out,
                             poly *y_buf,
                             const poly *cp,
                             const uint8_t *sk_s1_pkd,
                             const uint8_t rhoprime[CRHBYTES],
                             uint16_t nonce) {
    unsigned int i;
    int32_t a;

    /* Unpack s1[l] into z_out (unmasked at this B<->A boundary; Step 6
     * will move this boundary under masking via B->A conversion). */
    POLYETA_UNPACK(z_out, sk_s1_pkd);

    /* Random share s1_a stored in y_buf; s1_b in z_out. */
    for (i = 0; i < N; i++) {
        a = (int32_t)(masked_cs1_fresh_rand() % (uint32_t)Q);
        y_buf->coeffs[i] = a;
        z_out->coeffs[i] -= a;
    }

    /* NTT both shares */
    MLDSA_NAMESPACE(poly_ntt)(y_buf);
    MLDSA_NAMESPACE(poly_ntt)(z_out);

    /* cp * <share>_hat on both shares (cp public, linear in share) */
    MLDSA_NAMESPACE(poly_pointwise_montgomery)(y_buf, cp, y_buf);
    MLDSA_NAMESPACE(poly_pointwise_montgomery)(z_out, cp, z_out);

    /* INVNTT both shares (each now holds one arithmetic share of cs1) */
    MLDSA_NAMESPACE(poly_invntt_tomont)(y_buf);
    MLDSA_NAMESPACE(poly_invntt_tomont)(z_out);

    /* Combine cs1 shares into z_out: z_out = cs1_a + cs1_b = cs1. */
    for (i = 0; i < N; i++) {
        z_out->coeffs[i] += y_buf->coeffs[i];
    }

    /* y_buf is now free - overwrite with the real y_l sample. */
    SAMPLE_Y(y_buf, rhoprime, nonce);

    /* Fold y into z_out to get z = cs1 + y (mod q unreduced). */
    for (i = 0; i < N; i++) {
        z_out->coeffs[i] += y_buf->coeffs[i];
    }
}

#endif /* MLDSA_MASK_CS1 */
