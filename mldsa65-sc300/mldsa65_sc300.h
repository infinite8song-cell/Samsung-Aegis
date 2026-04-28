/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * impl_sc300/mldsa65_sc300.h —
 *
 * Single public header for library consumers of the ML-DSA-65 (FIPS
 * 204) Cortex-M3 implementation.  Pulls in the canonical sizes and
 * the function prototypes without exposing internal structs.
 *
 * A caller who just wants to sign / verify / generate keys should
 * only need this one include.
 *
 * Caller responsibilities:
 *   - link against the library archive (libmldsa65_sc300_*.a)
 *   - provide a `randombytes(uint8_t *out, size_t n)` implementation
 *     at link time
 *
 * THREAD SAFETY:
 *   The library functions below and all masked_* internals keep
 *   mutable state in static storage (non-reentrant).  Callers must
 *   serialise concurrent use.
 */

#ifndef MLDSA65_SC300_H
#define MLDSA65_SC300_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Canonical sizes (FIPS 204, parameter set ML-DSA-65)                 */
/* ------------------------------------------------------------------ */
#define MLDSA65_PUBLIC_KEY_BYTES  1952u
#define MLDSA65_SECRET_KEY_BYTES  4032u
#define MLDSA65_SIGNATURE_BYTES   3309u
#define MLDSA65_RND_BYTES           32u    /* per-signature rnd input */
#define MLDSA65_TR_BYTES            64u    /* H(pk), embedded in sk    */

/* ------------------------------------------------------------------ */
/* PQClean-style API  (detached signature, NIST ACVP compatible)       */
/* ------------------------------------------------------------------ */

/* Key generation. randombytes(...) is called internally. */
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

/* Seeded key generation: xi[32] is the FIPS 204 seed (ACVP keyGen "seed"). */
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(
        uint8_t *pk, uint8_t *sk, const uint8_t xi[MLDSA65_RND_BYTES]);

/* External Sign (FIPS 204 Alg 2).  Pre-hashes (tr || 0x00 || |ctx|
 * || ctx || m) before driving Sign_internal.                         */
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(
        uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

/* External Sign with explicit rnd.  Pass 32 zero bytes for deterministic
 * mode (ACVP sigGen deterministic=true).                              */
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx_rnd(
        uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t rnd[MLDSA65_RND_BYTES],
        const uint8_t *sk);

/* Internal Sign (FIPS 204 Alg 7).  Caller supplies rnd[32]; pass 32
 * zero bytes for deterministic mode (matches ACVP KAT).              */
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_internal(
        uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t rnd[MLDSA65_RND_BYTES],
        const uint8_t *sk);

/* External / Internal Verify.  Return 0 on valid, non-zero on invalid.*/
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
        const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_internal(
        const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

/* ------------------------------------------------------------------ */
/* 10-arg wrapper API (matches the caller-provided signature form).    */
/*   - crypto_sign: writes the DETACHED signature (3309 B) into sm,   */
/*     sets *sm_size = MLDSA65_SIGNATURE_BYTES.                       */
/*   - crypto_sign_open: takes pk (not sk).                           */
/*   - rnd parameter (if non-NULL) goes straight to Sign_internal;   */
/*     NULL draws fresh bytes via randombytes().                      */
/*   - inv_* / security_level / secret_parity are ignored.            */
/* ------------------------------------------------------------------ */

unsigned int crypto_sign_keypair(
    unsigned char       *pk,
    unsigned char       *sk,
    unsigned char       *rnd,
    unsigned int         inv_add_rnd,
    unsigned char        security_level,
    unsigned int        *secret_parity);

unsigned int crypto_sign(
    unsigned char       *sm,
    unsigned long long  *sm_size,
    unsigned char       *m,
    unsigned long long   m_size,
    unsigned char       *sk,
    unsigned char        security_level,
    unsigned int         secret_parity,
    const unsigned char *rnd,
    unsigned int         inv_add,
    unsigned int         inv_add_rnd);

unsigned int crypto_sign_open(
    const unsigned char *m,
    unsigned long long   m_size,
    const unsigned char *sm,
    unsigned long long   sm_size,
    const unsigned char *pk,
    unsigned char        security_level,
    unsigned int         inv_add);

#ifdef __cplusplus
}
#endif

#endif /* MLDSA65_SC300_H */
