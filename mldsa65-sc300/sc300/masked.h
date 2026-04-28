/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/sc300/masked.h — shared prototypes for SCA masking PoC.
 *
 * Each step is gated by its own MLDSA_MASK_* compile-time define and
 * can be independently toggled. Baseline behaviour (no defines) is
 * byte-identical to the non-masked implementation.
 *
 *   MLDSA_MASK_RHOPRIME   Step 1 — Boolean-masked Keccak for rho''
 *   MLDSA_MASK_CS1        Step 2 — Arithmetic masked Phase 2a (cs1)
 *   MLDSA_MASK_CS2_CT0    Step 3 — Arithmetic masked Phase 2b (cs2, ct0)
 *   MLDSA_MASK_Y_SAMPLE   Step 4 — Masked SHAKE for y (uniform_gamma1)
 *   MLDSA_MASK_CHKNORM    Step 5 — Masked chknorm + make_hint
 *   MLDSA_MASK_BA         Step 6 — B<->A conversion at unpack/sample
 */

#ifndef IMPL_SC300_MASKED_H
#define IMPL_SC300_MASKED_H

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Masking quality levels (informational):                              */
/*   REAL 1st-order masking:  Step 1, Step 2, Step 3                   */
/*   PoC cost emulation:      Step 4, Step 5, Step 6                   */
/*                                                                      */
/* The emulation steps capture the performance envelope of a future    */
/* fully masked implementation (e.g. bit-interleaved masked Keccak    */
/* in ASM for Step 4) but do NOT provide DPA resistance by themselves. */
/* Builds that enable any emulation step get a compile-time warning    */
/* unless MLDSA_MASK_ACCEPT_EMULATION is also defined.                 */
/* ------------------------------------------------------------------ */
#if (defined(MLDSA_MASK_Y_SAMPLE) || \
     defined(MLDSA_MASK_CHKNORM)  || \
     defined(MLDSA_MASK_BA))       && \
    !defined(MLDSA_MASK_ACCEPT_EMULATION)
#warning "This build enables cost-emulation masking step(s) 4/5/6 (no DPA resistance). Define MLDSA_MASK_ACCEPT_EMULATION to silence."
#endif

#if defined(MLDSA_MASK_RHOPRIME) || defined(MLDSA_MASK_Y_SAMPLE)
/* Real 1st-order Boolean-masked Keccak-f[1600] permutation.
 * state_a XOR state_b = plaintext state, preserved across calls. */
void masked_keccakf1600(uint64_t state_a[25], uint64_t state_b[25]);
#endif

#ifdef MLDSA_MASK_RHOPRIME
/* Masked SHAKE256(Kseed || rnd || mu, 64). Kseed is secret (the "K" field
 * of sk at offset SEEDBYTES); rnd and mu treated as public. */
void masked_compute_rhoprime(uint8_t rhoprime[64],
                              const uint8_t Kseed[32],
                              const uint8_t rnd[32],
                              const uint8_t mu[64]);
#endif

#ifdef MLDSA_MASK_CS1
#include "poly.h"
#include "params.h"
/* Step 2: Phase 2a kernel with s1 held in arithmetic shares.
 * Computes z_l = INVNTT(cp * NTT(s1[l])) + y_l using two shares,
 * returns combined z in z_out.  y_buf is scratch poly that also
 * holds the y_l sample at the end (caller already owns it). */
void masked_cs1_compute_z_l(poly *z_out,
                             poly *y_buf,
                             const poly *cp,
                             const uint8_t *sk_s1_pkd,
                             const uint8_t rhoprime[CRHBYTES],
                             uint16_t nonce);
#endif

#ifdef MLDSA_MASK_CS2_CT0
#include "poly.h"
#include "params.h"
/* Step 3: Phase 2b helper.  Given s in s_inout (unmasked, just unpacked),
 * replaces it in place with INVNTT(cp * NTT(s)) under arithmetic shares.
 * share_buf is caller-owned scratch (+1024 B stack). */
void masked_cp_times_s(poly *s_inout, poly *share_buf, const poly *cp);
#endif

#ifdef MLDSA_MASK_Y_SAMPLE
#include "poly.h"
#include "params.h"
/* Step 4: Boolean-masked SHAKE256-driven poly_uniform_gamma1.
 * Byte-identical output to the plain MLDSA_NAMESPACE(poly_uniform_gamma1)
 * (same seed and nonce produce same y); only the Keccak state is protected. */
void masked_poly_uniform_gamma1(poly *a,
                                  const uint8_t seed[CRHBYTES],
                                  uint16_t nonce);

#define SAMPLE_Y(out, seed, nonce) masked_poly_uniform_gamma1((out), (seed), (nonce))
#else
#define SAMPLE_Y(out, seed, nonce) \
    MLDSA_NAMESPACE(poly_uniform_gamma1)((out), (seed), (nonce))
#endif

#ifdef MLDSA_MASK_CHKNORM
#include "poly.h"
/* Step 5: constant-time chknorm + dummy-refresh make_hint for cost
 * emulation of a fully masked implementation.  Boolean / count output
 * matches the unmasked reference; KAT preserved. */
int          masked_poly_chknorm (const poly *a, int32_t B);
unsigned int masked_poly_make_hint(poly *h, const poly *a0, const poly *a1);

#define CHKNORM(a, B)          masked_poly_chknorm((a), (B))
#define MAKE_HINT(h, a0, a1)   masked_poly_make_hint((h), (a0), (a1))
#else
#define CHKNORM(a, B)          MLDSA_NAMESPACE(poly_chknorm)((a), (B))
#define MAKE_HINT(h, a0, a1)   MLDSA_NAMESPACE(poly_make_hint)((h), (a0), (a1))
#endif

#ifdef MLDSA_MASK_BA
#include "poly.h"
/* Step 6: cost emulation of Goubin-style B->A conversion at every
 * sk unpack site (polyeta for s1/s2 and polyt0 for t0).  Reference
 * coefficient output is preserved; KAT unchanged. */
void masked_polyeta_unpack_ba(poly *r, const uint8_t *a);
void masked_polyt0_unpack_ba (poly *r, const uint8_t *a);

#define POLYETA_UNPACK(r, a)   masked_polyeta_unpack_ba((r), (a))
#define POLYT0_UNPACK(r, a)    masked_polyt0_unpack_ba((r), (a))
#else
#define POLYETA_UNPACK(r, a)   MLDSA_NAMESPACE(polyeta_unpack)((r), (a))
#define POLYT0_UNPACK(r, a)    MLDSA_NAMESPACE(polyt0_unpack)((r), (a))
#endif

#endif /* IMPL_SC300_MASKED_H */
