#ifndef MLDSA_API_H
#define MLDSA_API_H

#include "params.h"
#include <stddef.h>
#include <stdint.h>

/* Expose namespaced size constants for callers using the long form. */
#if MLDSA_MODE == 44
#  define PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES  CRYPTO_PUBLICKEYBYTES
#  define PQCLEAN_MLDSA44_CLEAN_CRYPTO_SECRETKEYBYTES  CRYPTO_SECRETKEYBYTES
#  define PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES           CRYPTO_BYTES
#  define PQCLEAN_MLDSA44_CLEAN_CRYPTO_ALGNAME         "ML-DSA-44"
#else
#  define PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES  CRYPTO_PUBLICKEYBYTES
#  define PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES  CRYPTO_SECRETKEYBYTES
#  define PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES           CRYPTO_BYTES
#  define PQCLEAN_MLDSA65_CLEAN_CRYPTO_ALGNAME         "ML-DSA-65"
#endif

int MLDSA_NAMESPACE(crypto_sign_keypair)(uint8_t *pk, uint8_t *sk);

int MLDSA_NAMESPACE(crypto_sign_signature_ctx)(uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

int MLDSA_NAMESPACE(crypto_sign_ctx)(uint8_t *sm, size_t *smlen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *sk);

int MLDSA_NAMESPACE(crypto_sign_verify_ctx)(const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

int MLDSA_NAMESPACE(crypto_sign_open_ctx)(uint8_t *m, size_t *mlen,
        const uint8_t *sm, size_t smlen,
        const uint8_t *ctx, size_t ctxlen,
        const uint8_t *pk);

#endif /* MLDSA_API_H */
