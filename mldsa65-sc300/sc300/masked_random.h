/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/sc300/masked_random.h —
 *
 * Single fresh-randomness source shared by every masked_*.c file.
 *
 * PoC: backed by an xorshift64 generator whose state is private to
 * masked_random.c.  For production deployment replace the xorshift
 * body with a TRNG (or a DPA-resistant seeded CSPRNG) in one place.
 *
 * THREAD SAFETY: not re-entrant.  Library callers must serialise any
 * code path that consumes fresh randomness through this interface.
 */

#ifndef IMPL_SC300_MASKED_RANDOM_H
#define IMPL_SC300_MASKED_RANDOM_H

#include <stdint.h>

uint64_t masked_fresh_rand64(void);
uint32_t masked_fresh_rand32(void);

#endif /* IMPL_SC300_MASKED_RANDOM_H */
