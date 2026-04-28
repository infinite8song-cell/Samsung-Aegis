/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/sc300/masked_y_sample.c —
 *
 * Step 4 (current policy): Boolean-mask COST EMULATION for y sampling
 * via the hand-tuned ARMv7-M Keccak primitives from common/keccakf1600.S.
 *
 * BACKGROUND — why emulation instead of real masking here:
 *   poly_uniform_gamma1 is called 10 times per sign (5 in Phase 1 +
 *   5 in Phase 2a), each call performs 5 Keccak permutations; that
 *   means ~50 masked permutations per sign.  A real C-level masked
 *   Keccak permutation costs ~10x the unmasked ARMv7-M ASM, so
 *   naively switching to the real masked_keccakf1600 used by Step 1
 *   pushes sign overhead to +500% (measured).  Step 1 is safe at
 *   +1% because rhoprime is one call.
 *
 *   The only way to keep real masking here AND keep sign cost low is
 *   a fully bit-interleaved masked Keccak-f[1600].S that mirrors
 *   common/keccakf1600.S's 32-bit lane scheduling - ~1000 LOC of
 *   dedicated ARMv7-M assembly plus TVLA verification.  That
 *   follow-up is tracked but not in this commit.
 *
 * UNTIL the masked .S lands, this file uses COST EMULATION:
 *   - the real state is absorbed + permuted + extracted using the
 *     reference ASM primitives and produces the correct SHAKE256
 *     output (KAT byte-exact),
 *   - an emulation state seeded with fresh randomness is permuted
 *     in lockstep so the cycle count reflects what a future masked
 *     ASM kernel would occupy (~2x unmasked ASM on CM3).
 *
 * This variant is deliberately labelled "cost emulation, not DPA
 * resistance" in the PoC overall report.
 *
 * Stack: two 25-lane states + a 680 B squeeze buffer + tiny
 * bookkeeping.  No large C-level scratch arrays.
 *
 * Compiled only when MLDSA_MASK_Y_SAMPLE is defined.
 */

#ifdef MLDSA_MASK_Y_SAMPLE

#include <stdint.h>
#include <stddef.h>

#include "params.h"
#include "poly.h"
#include "keccakf1600.h"   /* hand-tuned ARMv7-M Keccak primitives */
#include "masked.h"
#include "masked_random.h"

#define mk_y_rand64 masked_fresh_rand64

#define SHAKE256_RATE                136
#define POLY_UNIFORM_GAMMA1_NBLOCKS   5   /* ceil(640 / 136) for ML-DSA-65 */

void masked_poly_uniform_gamma1(poly *a,
                                  const uint8_t seed[CRHBYTES],
                                  uint16_t nonce) {
    uint64_t state[25];
    uint64_t state_emu[25];
    uint8_t  buf[POLY_UNIFORM_GAMMA1_NBLOCKS * SHAKE256_RATE];
    uint8_t  nonce_bytes[2];
    uint8_t  dom_pad;
    unsigned int i, blk;

    /* ---- Real state: absorb seed || nonce via ASM primitives ---- */
    for (i = 0; i < 25; i++) state[i] = 0;

    KeccakF1600_StateXORBytes(state, seed, 0, CRHBYTES);

    nonce_bytes[0] = (uint8_t)(nonce & 0xff);
    nonce_bytes[1] = (uint8_t)((nonce >> 8) & 0xff);
    KeccakF1600_StateXORBytes(state, nonce_bytes, CRHBYTES, 2);

    dom_pad = 0x1f;
    KeccakF1600_StateXORBytes(state, &dom_pad, CRHBYTES + 2, 1);
    dom_pad = 0x80;
    KeccakF1600_StateXORBytes(state, &dom_pad, SHAKE256_RATE - 1, 1);

    /* ---- Emulation state: fresh randomness so the second ASM call
     * does real work (keeps it from being dead-code-eliminated). ---- */
    for (i = 0; i < 25; i++) {
        state_emu[i] = mk_y_rand64();
    }

    /* ---- Squeeze NBLOCKS blocks, 2 ASM permutations per block. ---- */
    for (blk = 0; blk < POLY_UNIFORM_GAMMA1_NBLOCKS; blk++) {
        KeccakF1600_StatePermute(state);       /* correct output */
        KeccakF1600_StatePermute(state_emu);   /* dual-share cost emu */

        KeccakF1600_StateExtractBytes(state,
                                       buf + blk * SHAKE256_RATE,
                                       0, SHAKE256_RATE);

        /* Optimiser barrier: consume state_emu so the permute is not
         * dead-code-eliminated, but don't let it reach the output. */
        {
            volatile uint64_t sink;
            sink = state_emu[0] ^ state_emu[12] ^ state_emu[24];
            (void)sink;
        }
    }

    MLDSA_NAMESPACE(polyz_unpack)(a, buf);
}

#endif /* MLDSA_MASK_Y_SAMPLE */
