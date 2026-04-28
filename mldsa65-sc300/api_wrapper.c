/*
 * api_wrapper.c — runtime dispatch between ML-DSA-44 and ML-DSA-65.
 *
 * INTERNAL-ONLY API:
 *   All randomness must be caller-provided (seed for keypair, rnd for sign).
 *   No randombytes() dependency.
 *
 * security_level == 44  → ML-DSA-44 (pk=1312, sk=2560, sig=2420)
 * security_level == 65  → ML-DSA-65 (pk=1952, sk=4032, sig=3309) [default]
 *
 * sk buffer convention: caller passes pk || sk concatenated.
 * crypto_sign writes a DETACHED signature (not prepended to message).
 *
 * Return convention (caller-side):
 *   success (underlying rc == 0) -> WRAPPER_SUCCESS (0x1234)
 *   failure (underlying rc != 0) -> (unsigned int)rc  (pass through)
 */

#include <stdint.h>
#include <string.h>

#include "api_wrapper.h"
#include "mldsa_dispatch.h"

#define WRAPPER_SUCCESS 0x1234u

/* ------------------------------------------------------------------ */

unsigned int crypto_sign_keypair(
    unsigned char       *pk,
    unsigned char       *sk,
    unsigned char       *rnd,              /* 32-byte seed (xi) */
    unsigned int         inv_add_rnd,
    unsigned char        security_level,
    unsigned int        *secret_parity)
{
    int rc;

    (void)inv_add_rnd;

    if (rnd == (unsigned char *)0) {
        return (unsigned int)-1;           /* caller must supply seed */
    }

    if (security_level == 44) {
        rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_from_seed(
                 pk, sk, (const uint8_t *)rnd);
    } else {
        rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(
                 pk, sk, (const uint8_t *)rnd);
    }

    if (rc != 0) {
        return (unsigned int)rc;
    }

    if (secret_parity != (void *)0) {
        *secret_parity = 0;
    }

    return WRAPPER_SUCCESS;
}

/* ------------------------------------------------------------------ */

unsigned int crypto_sign(
    unsigned char       *sm,
    unsigned long long  *sm_size,
    unsigned char       *m,
    unsigned long long   m_size,
    unsigned char       *sk,
    unsigned char        security_level,
    unsigned int         secret_parity,
    const unsigned char *rnd,              /* 32-byte signing randomness */
    unsigned int         inv_add,
    unsigned int         inv_add_rnd)
{
    size_t siglen = 0;
    int rc;

    (void)secret_parity;
    (void)inv_add;
    (void)inv_add_rnd;

    if (rnd == (const unsigned char *)0) {
        return (unsigned int)-1;           /* caller must supply rnd */
    }

    if (security_level == 44) {
        rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature_internal(
                 sm, &siglen,
                 (const uint8_t *)m, (size_t)m_size,
                 (const uint8_t *)rnd,
                 (const uint8_t *)sk);
    } else {
        rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_internal(
                 sm, &siglen,
                 (const uint8_t *)m, (size_t)m_size,
                 (const uint8_t *)rnd,
                 (const uint8_t *)sk);
    }

    if (sm_size != (void *)0) {
        *sm_size = (unsigned long long)siglen;
    }

    return (rc == 0) ? WRAPPER_SUCCESS : (unsigned int)rc;
}

/* ------------------------------------------------------------------ */

unsigned int crypto_sign_open(
    const unsigned char *m,
    unsigned long long   m_size,
    const unsigned char *sm,
    unsigned long long   sm_size,
    const unsigned char *pk,
    unsigned char        security_level,
    unsigned int         inv_add)
{
    int rc;

    (void)inv_add;

    if (security_level == 44) {
        rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify_internal(
                 (const uint8_t *)sm, (size_t)sm_size,
                 (const uint8_t *)m,  (size_t)m_size,
                 (const uint8_t *)pk);
    } else {
        rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_internal(
                 (const uint8_t *)sm, (size_t)sm_size,
                 (const uint8_t *)m,  (size_t)m_size,
                 (const uint8_t *)pk);
    }

    return (rc == 0) ? WRAPPER_SUCCESS : (unsigned int)rc;
}
