/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/sc300/masked_ba.c —
 *
 * Step 6 of SCA masking PoC: cost emulation of B->A (Boolean-to-
 * Arithmetic) conversion at the sk-unpack boundary.
 *
 * In the unmasked code, polyeta_unpack / polyt0_unpack read packed
 * bit fields from sk and write plaintext coefficients into a poly.
 * Any arithmetic-share masking downstream (Steps 2/3) therefore
 * starts from a brief unmasked window.
 *
 * A rigorous masked implementation would:
 *   1. Keep the sk bytes themselves B-masked (two XOR shares).
 *   2. Extract each packed bit-field into B-shares with masked bit
 *      selection (shifts/ANDs under ISW).
 *   3. Convert B-shares -> arithmetic (mod q) shares via Goubin's
 *      recursion or Hutter-Tunstall, so downstream Z_q operations
 *      consume the output directly.
 *
 * This PoC keeps the functional reference unpack and adds a
 * per-coefficient emulation of Goubin B->A cost (a handful of
 * xorshift pulls + XOR accumulations that the optimiser cannot
 * eliminate).  The output is bit-identical to the reference
 * unpack so that NIST ACVP tcId=139 KAT still matches exactly.
 *
 * The `asm volatile` memory clobber prevents the refresh work from
 * being DCE'd and is intentionally lightweight - it is NOT a real
 * masking gadget.
 *
 * Compiled only when MLDSA_MASK_BA is defined.
 */

#ifdef MLDSA_MASK_BA

#include <stdint.h>

#include "params.h"
#include "poly.h"
#include "masked.h"
#include "masked_random.h"

#define mk_ba_rand masked_fresh_rand32

/* Emulated B->A conversion work for `bits` Boolean shares -> Z_q arith.
 *  - per-coefficient: 2 fresh-random pulls + 4 XOR / AND ops + write.
 *  - approximates Goubin B->A for small-width fields (< 16 bits).      */
static inline void emulate_ba(poly *r) {
    uint32_t acc = 0;
    unsigned int i;
    for (i = 0; i < N; i++) {
        uint32_t r1 = mk_ba_rand();
        uint32_t r2 = mk_ba_rand();
        int32_t  c  = r->coeffs[i];
        /* Shape: c' = ((c ^ r1) - r1) ^ r2 ^ r2  (identity on c, cost ~ B2A) */
        int32_t x = c ^ (int32_t)r1;
        x = x - (int32_t)r1;
        x = x ^ (int32_t)r2;
        acc ^= (uint32_t)x ^ r2;
    }
    /* Prevent the compiler from eliminating the work. */
    asm volatile("" : : "r"(acc) : "memory");
}

/* ------------------------------------------------------------------ */
/* Masked-boundary unpack wrappers.                                    */
/* Output bytes/coefficients are identical to the unmasked reference. */
/* ------------------------------------------------------------------ */
void masked_polyeta_unpack_ba(poly *r, const uint8_t *a) {
    MLDSA_NAMESPACE(polyeta_unpack)(r, a);
    emulate_ba(r);
}

void masked_polyt0_unpack_ba(poly *r, const uint8_t *a) {
    MLDSA_NAMESPACE(polyt0_unpack)(r, a);
    emulate_ba(r);
}

#endif /* MLDSA_MASK_BA */
