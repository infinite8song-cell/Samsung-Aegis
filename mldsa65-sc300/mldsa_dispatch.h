/* mldsa_dispatch.h — explicit declarations for both ML-DSA-44 and ML-DSA-65.
 * Used only by api_wrapper.c; do not include in mode-specific build units. */
#ifndef MLDSA_DISPATCH_H
#define MLDSA_DISPATCH_H

#include <stddef.h>
#include <stdint.h>

/* Canonical sizes (FIPS 204) */
#define MLDSA44_PUBLICKEYBYTES   1312u
#define MLDSA44_SECRETKEYBYTES   2560u
#define MLDSA44_BYTES            2420u

#define MLDSA65_PUBLICKEYBYTES   1952u
#define MLDSA65_SECRETKEYBYTES   4032u
#define MLDSA65_BYTES            3309u

/* ML-DSA-44 entry points (internal API only; caller-provided randomness) */
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_from_seed(
        uint8_t *pk, uint8_t *sk, const uint8_t xi[32]);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_internal(
        uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t rnd[32],
        const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_internal(
        const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

/* ML-DSA-65 entry points (internal API only; caller-provided randomness) */
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(
        uint8_t *pk, uint8_t *sk, const uint8_t xi[32]);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_internal(
        uint8_t *sig, size_t *siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t rnd[32],
        const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_internal(
        const uint8_t *sig, size_t siglen,
        const uint8_t *m, size_t mlen,
        const uint8_t *pk);

#endif /* MLDSA_DISPATCH_H */
