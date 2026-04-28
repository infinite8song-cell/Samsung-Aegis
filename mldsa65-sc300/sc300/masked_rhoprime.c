/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/sc300/masked_rhoprime.c —
 *
 * Step 1 of SCA masking PoC: 1st-order Boolean-masked Keccak-f[1600]
 * used only for the rhoprime computation
 *
 *     rho'' = SHAKE256(K || rnd || mu, 64)
 *
 * where K is the secret key seed.  All other SHAKE calls in sign/verify
 * operate on publicly-derivable inputs and remain unmasked.
 *
 * Masking model:
 *   - 1st-order Boolean masking: each state lane held as two XOR shares
 *   - linear steps (theta, rho, pi, iota) applied to each share independently
 *   - non-linear chi step uses an ISW-1 SecAnd gadget with fresh randomness
 *   - K is split (K0 random, K1 = K XOR K0) before absorption
 *   - rnd and mu are public (mu = H(tr||M), tr = H(pk), pk public); absorbed
 *     into share 0 only, share 1 untouched for those bytes
 *   - output rho'' = share0 XOR share1 at squeeze time
 *
 * NOTE — randomness source:
 *   This PoC uses an xorshift64 seeded at load.  For any production-grade
 *   DPA-resistant deployment, replace `masked_fresh_rand64` with a TRNG
 *   or a properly seeded DRBG.  The PoC is adequate for measuring the
 *   performance cost of the masking structure.
 *
 * Compiled into the build only when MLDSA_MASK_RHOPRIME is defined; the
 * file is otherwise an empty translation unit.
 */

#ifdef MLDSA_MASK_RHOPRIME

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "masked.h"           /* shared masked_keccakf1600 */
#include "masked_random.h"    /* shared masked_fresh_rand64  */

/* ------------------------------------------------------------------ */
/* Public entry: compute rhoprime = SHAKE256(K || rnd || mu, 64) with  */
/* K in Boolean shares; rnd and mu treated as public.                   */
/* ------------------------------------------------------------------ */
#define SHAKE256_RATE 136

void masked_compute_rhoprime(uint8_t rhoprime[64],
                              const uint8_t Kseed[32],
                              const uint8_t rnd[32],
                              const uint8_t mu[64]) {
    uint64_t s0[25] = {0};
    uint64_t s1[25] = {0};
    uint8_t Ks0[32], Ks1[32];
    unsigned int i;

    /* Split Kseed into two Boolean shares */
    for (i = 0; i < 32; i++) {
        uint64_t r = masked_fresh_rand64();
        Ks0[i] = (uint8_t)r;
        Ks1[i] = Kseed[i] ^ Ks0[i];
    }

    /* Absorb Kseed into both shares (offset 0..31) */
    for (i = 0; i < 32; i++) {
        s0[i >> 3] ^= (uint64_t)Ks0[i] << (8 * (i & 7));
        s1[i >> 3] ^= (uint64_t)Ks1[i] << (8 * (i & 7));
    }
    /* Absorb rnd (public) into share 0 only (offset 32..63) */
    for (i = 0; i < 32; i++) {
        s0[(32 + i) >> 3] ^= (uint64_t)rnd[i] << (8 * ((32 + i) & 7));
    }
    /* Absorb mu (public) into share 0 only (offset 64..127) */
    for (i = 0; i < 64; i++) {
        s0[(64 + i) >> 3] ^= (uint64_t)mu[i] << (8 * ((64 + i) & 7));
    }
    /* SHAKE256 domain separator + pad10*1 at end of rate */
    s0[128 >> 3] ^= (uint64_t)0x1f << (8 * (128 & 7));
    s0[(SHAKE256_RATE - 1) >> 3] ^= (uint64_t)0x80 << (8 * ((SHAKE256_RATE - 1) & 7));

    /* Masked permutation */
    masked_keccakf1600(s0, s1);

    /* Squeeze 64 bytes: rhoprime = (s0 XOR s1) byte-by-byte */
    for (i = 0; i < 64; i++) {
        uint8_t b0 = (uint8_t)(s0[i >> 3] >> (8 * (i & 7)));
        uint8_t b1 = (uint8_t)(s1[i >> 3] >> (8 * (i & 7)));
        rhoprime[i] = b0 ^ b1;
    }
}

#endif /* MLDSA_MASK_RHOPRIME */
