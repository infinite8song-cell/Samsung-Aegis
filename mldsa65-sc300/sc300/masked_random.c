/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/sc300/masked_random.c —
 *
 * Shared fresh-randomness implementation for every masked_*.c
 * compilation unit.  Replaces the seven per-file xorshift64 states
 * that used to live in each masked source.  PoC only — replace
 * with a TRNG or seeded CSPRNG in production.
 */

#if defined(MLDSA_MASK_RHOPRIME) || \
    defined(MLDSA_MASK_CS1)       || \
    defined(MLDSA_MASK_CS2_CT0)   || \
    defined(MLDSA_MASK_Y_SAMPLE)  || \
    defined(MLDSA_MASK_CHKNORM)   || \
    defined(MLDSA_MASK_BA)

#include <stdint.h>
#include "masked_random.h"

/* Single PRNG state for the whole masked compilation unit set. */
static uint64_t g_masked_prng = 0xbebafeca5a5a5a5aULL;

uint64_t masked_fresh_rand64(void) {
    uint64_t x = g_masked_prng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    g_masked_prng = x;
    return x;
}

uint32_t masked_fresh_rand32(void) {
    return (uint32_t)masked_fresh_rand64();
}

#endif /* any MLDSA_MASK_* */
