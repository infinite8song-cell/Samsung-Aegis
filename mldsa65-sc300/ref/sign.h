#ifndef MLDSA_SIGN_H
#define MLDSA_SIGN_H
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include <stddef.h>
#include <stdint.h>

int MLDSA_NAMESPACE(crypto_sign_keypair)(uint8_t *pk, uint8_t *sk);

/* Seeded keypair: xi[32] is the FIPS 204 xi seed (ACVP keyGen "seed" field). */
int MLDSA_NAMESPACE(crypto_sign_keypair_from_seed)(
        uint8_t *pk, uint8_t *sk, const uint8_t xi[32]);

/* External sign with explicit rnd: zeros → deterministic (ACVP det=true). */
int MLDSA_NAMESPACE(crypto_sign_signature_ctx_rnd)(
        uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t rnd[32],
        const uint8_t *sk);

int MLDSA_NAMESPACE(crypto_sign_signature_ctx)(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

/* FIPS 204 Algorithm 7: ML-DSA.Sign_internal(sk, M', rnd)
 *   mu    = H(tr || M', 64)
 *   rho'' = H(K  || rnd || mu, 64)
 * Caller supplies rnd (32 bytes). For ACVP deterministic=true tests,
 * pass rnd = 32 zero bytes.  Output: detached signature only. */
int MLDSA_NAMESPACE(crypto_sign_signature_internal)(
        uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t rnd[32],
        const uint8_t *sk);

int MLDSA_NAMESPACE(crypto_sign_ctx)(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

int MLDSA_NAMESPACE(crypto_sign_verify_ctx)(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

/* FIPS 204 Algorithm 8: ML-DSA.Verify_internal — matches signature_internal. */
int MLDSA_NAMESPACE(crypto_sign_verify_internal)(
        const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

int MLDSA_NAMESPACE(crypto_sign_open_ctx)(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

#endif
