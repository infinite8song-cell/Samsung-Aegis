/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/sc300/masked_keccak_core.c —
 *
 * REAL 1st-order Boolean-masked Keccak-f[1600] (no cost emulation).
 *
 * Shared between Step 1 (rhoprime) and Step 4 (y sampling).  The
 * permutation processes two Boolean shares of the 1600-bit state
 * through 24 rounds:
 *
 *   theta, rho, pi, iota   : linear, applied to each share
 *   chi                    : non-linear, 25 x 64-bit SecAnd gadgets
 *                            per round with fresh randomness between
 *                            every AND pair
 *
 * The SecAnd gadget is an ISW-1 construction implemented in an
 * ARMv7-M inline assembly block so that every intermediate value
 * of the cross term (a & b) lives in a register and is never stored
 * to memory in plaintext form.  The full 64-bit gadget runs as:
 *
 *    SecAnd64(a_a,a_b, b_a,b_b)  ->  (o_a, o_b)   with o_a^o_b = a&b
 *      r = fresh_rand64()
 *      o_a = (a_a & b_a) ^ ((a_a & b_b) ^ r)
 *      o_b = (a_b & b_b) ^ ((a_b & b_a) ^ r)
 *
 * and is decomposed into two 32-bit halves because CM3 is 32-bit.
 *
 * FRESH RANDOMNESS:
 *   This PoC pulls from an xorshift64 PRNG.  A production build must
 *   replace `mk_rand64` with a TRNG or a seeded CSPRNG whose own
 *   side-channel posture matches the target threat model.
 *
 * CORRECTNESS:
 *   share_a[i] XOR share_b[i] == plaintext_state[i] for every lane i
 *   at every round boundary.  At squeeze time the user XORs the two
 *   shares byte-wise to recover the unmasked SHAKE output, which
 *   matches the reference keccakf1600 output byte-exact.
 *
 * STACK:
 *   Scratch arrays C/D (80 B) + B (400 B) + per-row r (80 B) live on
 *   the permutation's frame.  Total permutation frame ~600 B.  When
 *   called inside sign the caller also keeps two state arrays
 *   (2 * 200 B) and the absorb/squeeze buffer.
 *
 * PERFORMANCE (measured on QEMU mps2-an385, Cortex-M3):
 *   Unmasked reference ASM keccakf1600.S       : ~   1 unit
 *   This masked core (C body, inline-asm SecAnd): ~ 35 units   (see Step 4)
 *
 *   The gap vs the ~2x-optimal masked ASM bound is the cost of the
 *   non-bit-interleaved C permutation body.  Closing the gap needs
 *   a hand-tuned masked .S that mirrors common/keccakf1600.S's
 *   lane-interleaving scheduling; see discussion in the Step 4
 *   revision commit log.
 */

#if defined(MLDSA_MASK_RHOPRIME) || defined(MLDSA_MASK_Y_SAMPLE)

#include <stdint.h>
#include <stddef.h>

#include "masked.h"
#include "masked_random.h"

#define NROUNDS 24
#define ROL64(a, n) (((a) << (n)) ^ ((a) >> (64 - (n))))

static const uint64_t KeccakF_RC[NROUNDS] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static const uint8_t rho_offsets[25] = {
    0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

/* Fresh randomness now comes from the shared masked_random.c. */
#define mk_rand64 masked_fresh_rand64

/* ------------------------------------------------------------------ */
/* 64-bit ISW-1 SecAnd                                                 */
/*   (o_a, o_b) <- (a & b) under Boolean shares (a_a,a_b) and (b_a,b_b)*/
/*                                                                      */
/* Implemented as two 32-bit halves with an ARMv7-M Thumb-2 inline-asm */
/* kernel.  Every cross term (a_a & b_b) and (a_b & b_a) is refreshed  */
/* by XOR with a fresh 32-bit random before being combined with the   */
/* diagonal term; intermediate values stay in registers.               */
/* ------------------------------------------------------------------ */
static __attribute__((always_inline)) inline
void secand64(uint64_t *o_a, uint64_t *o_b,
              uint64_t a_a, uint64_t a_b,
              uint64_t b_a, uint64_t b_b) {
    uint32_t aa_lo = (uint32_t)a_a, aa_hi = (uint32_t)(a_a >> 32);
    uint32_t ab_lo = (uint32_t)a_b, ab_hi = (uint32_t)(a_b >> 32);
    uint32_t ba_lo = (uint32_t)b_a, ba_hi = (uint32_t)(b_a >> 32);
    uint32_t bb_lo = (uint32_t)b_b, bb_hi = (uint32_t)(b_b >> 32);
    uint64_t r  = mk_rand64();
    uint32_t r_lo = (uint32_t)r,    r_hi = (uint32_t)(r >> 32);
    uint32_t oa_lo, ob_lo, oa_hi, ob_hi, t1, t2;

    /* Low half: 8-instruction SecAnd kernel, all intermediates live
     * in registers the compiler picks from scratch here. */
    __asm__ volatile (
        "and    %[t1], %[aa], %[bb]    \n\t"
        "eor    %[t1], %[t1], %[rn]    \n\t"
        "and    %[t2], %[aa], %[ba]    \n\t"
        "eor    %[oa], %[t2], %[t1]    \n\t"
        "and    %[t1], %[ab], %[ba]    \n\t"
        "eor    %[t1], %[t1], %[rn]    \n\t"
        "and    %[t2], %[ab], %[bb]    \n\t"
        "eor    %[ob], %[t2], %[t1]    \n\t"
        : [oa] "=&r" (oa_lo), [ob] "=&r" (ob_lo),
          [t1] "=&r" (t1),    [t2] "=&r" (t2)
        : [aa] "r" (aa_lo), [ab] "r" (ab_lo),
          [ba] "r" (ba_lo), [bb] "r" (bb_lo),
          [rn] "r" (r_lo)
    );

    /* High half: same kernel with the hi-halves. */
    __asm__ volatile (
        "and    %[t1], %[aa], %[bb]    \n\t"
        "eor    %[t1], %[t1], %[rn]    \n\t"
        "and    %[t2], %[aa], %[ba]    \n\t"
        "eor    %[oa], %[t2], %[t1]    \n\t"
        "and    %[t1], %[ab], %[ba]    \n\t"
        "eor    %[t1], %[t1], %[rn]    \n\t"
        "and    %[t2], %[ab], %[bb]    \n\t"
        "eor    %[ob], %[t2], %[t1]    \n\t"
        : [oa] "=&r" (oa_hi), [ob] "=&r" (ob_hi),
          [t1] "=&r" (t1),    [t2] "=&r" (t2)
        : [aa] "r" (aa_hi), [ab] "r" (ab_hi),
          [ba] "r" (ba_hi), [bb] "r" (bb_hi),
          [rn] "r" (r_hi)
    );

    *o_a = (uint64_t)oa_lo | ((uint64_t)oa_hi << 32);
    *o_b = (uint64_t)ob_lo | ((uint64_t)ob_hi << 32);
}

/* ------------------------------------------------------------------ */
/* Masked Keccak-f[1600] permutation                                    */
/* ------------------------------------------------------------------ */
void masked_keccakf1600(uint64_t state_a[25], uint64_t state_b[25]) {
    uint64_t C_a[5], C_b[5], D_a[5], D_b[5];
    uint64_t B_a[25], B_b[25];
    uint64_t out_a, out_b;
    int round, x, y;

    for (round = 0; round < NROUNDS; round++) {
        /* --- theta (linear, each share independently) --- */
        for (x = 0; x < 5; x++) {
            C_a[x] = state_a[x] ^ state_a[x+5] ^ state_a[x+10] ^ state_a[x+15] ^ state_a[x+20];
            C_b[x] = state_b[x] ^ state_b[x+5] ^ state_b[x+10] ^ state_b[x+15] ^ state_b[x+20];
        }
        for (x = 0; x < 5; x++) {
            D_a[x] = C_a[(x+4) % 5] ^ ROL64(C_a[(x+1) % 5], 1);
            D_b[x] = C_b[(x+4) % 5] ^ ROL64(C_b[(x+1) % 5], 1);
        }
        for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++) {
                state_a[x + 5*y] ^= D_a[x];
                state_b[x + 5*y] ^= D_b[x];
            }
        }

        /* --- rho + pi (linear) --- */
        for (y = 0; y < 5; y++) {
            for (x = 0; x < 5; x++) {
                int src = x + 5*y;
                int dst = y + 5 * ((2*x + 3*y) % 5);
                B_a[dst] = ROL64(state_a[src], rho_offsets[src]);
                B_b[dst] = ROL64(state_b[src], rho_offsets[src]);
            }
        }

        /* --- chi (masked with ISW-1 SecAnd in inline asm) --- */
        for (y = 0; y < 5; y++) {
            uint64_t r_a[5], r_b[5];
            for (x = 0; x < 5; x++) {
                int ix1 = (x + 1) % 5;
                int ix2 = (x + 2) % 5;
                /* NOT applied to share A only (share B unchanged).  */
                secand64(&out_a, &out_b,
                         ~B_a[ix1 + 5*y],  B_b[ix1 + 5*y],
                          B_a[ix2 + 5*y],  B_b[ix2 + 5*y]);
                r_a[x] = B_a[x + 5*y] ^ out_a;
                r_b[x] = B_b[x + 5*y] ^ out_b;
            }
            for (x = 0; x < 5; x++) {
                state_a[x + 5*y] = r_a[x];
                state_b[x + 5*y] = r_b[x];
            }
        }

        /* --- iota (XOR RC into share A only) --- */
        state_a[0] ^= KeccakF_RC[round];
    }
}

#endif /* MLDSA_MASK_RHOPRIME || MLDSA_MASK_Y_SAMPLE */
