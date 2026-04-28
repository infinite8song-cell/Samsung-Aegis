/*
 * api_wrapper_kem.h — ML-KEM-768 caller-facing wrapper.
 *
 * INTERNAL-ONLY API: all randomness is caller-provided.
 *   kem_keypair : `coins` is 64 bytes (d || z); must be non-NULL.
 *   kem_encaps  : `coins` is 32 bytes (m);       must be non-NULL.
 *   kem_decaps  : no caller randomness needed.
 *
 * Return convention (matches api_wrapper.h / ML-DSA wrapper):
 *   success -> 0x1234u      (NOT 0; caller-side sentinel)
 *   failure -> non-zero rc  (passed through)
 */

#ifndef API_WRAPPER_KEM_H
#define API_WRAPPER_KEM_H

#include <stdint.h>

#define KEM_PUBLICKEYBYTES   1184u
#define KEM_SECRETKEYBYTES   2400u
#define KEM_CIPHERTEXTBYTES  1088u
#define KEM_SHAREDSECRETBYTES 32u

/* 64 random bytes = d (32) || z (32) */
unsigned int kem_keypair(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *coins);       /* 64 bytes */

/* 32 random bytes = m (the ephemeral secret to encapsulate) */
unsigned int kem_encaps(
    unsigned char       *ct,
    unsigned char       *ss,
    const unsigned char *pk,
    const unsigned char *coins);       /* 32 bytes */

unsigned int kem_decaps(
    unsigned char       *ss,
    const unsigned char *ct,
    const unsigned char *sk);

#endif /* API_WRAPPER_KEM_H */
