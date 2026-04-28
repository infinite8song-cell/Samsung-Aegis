#ifndef API_WRAPPER_H
#define API_WRAPPER_H

/*
 * api_wrapper.h — ML-DSA-44/65 wrapper matching caller-side API.
 *
 * INTERNAL-ONLY API: all randomness is caller-provided.
 *   crypto_sign_keypair: `rnd` is the 32-byte seed (xi); must be non-NULL.
 *   crypto_sign        : `rnd` is the 32-byte signing randomness; must be non-NULL.
 *                        Both functions return (unsigned int)-1 if rnd == NULL.
 *
 * crypto_sign_open receives pk directly (not sk).
 * inv_* / security_level / secret_parity parameters are ignored (no-op).
 * secret_parity output is always set to 0.
 *
 * Return convention:
 *   success -> 0x1234u      (NOT 0; caller-side sentinel)
 *   failure -> underlying rc (non-zero) is passed through unchanged
 */

#include <stdint.h>

#define WRAPPER_PUBLICKEYBYTES  1952
#define WRAPPER_SECRETKEYBYTES  (1952 + 4032)   /* pk || sk */
#define WRAPPER_BYTES           3309

unsigned int crypto_sign_keypair(
    unsigned char       *pk,
    unsigned char       *sk,           /* caller buffer: pk(1952) || sk(4032) */
    unsigned char       *rnd,
    unsigned int         inv_add_rnd,
    unsigned char        security_level,
    unsigned int        *secret_parity);

unsigned int crypto_sign(
    unsigned char       *sm,
    unsigned long long  *sm_size,
    unsigned char       *m,
    unsigned long long   m_size,
    unsigned char       *sk,           /* caller buffer: pk(1952) || sk(4032) */
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

#endif /* API_WRAPPER_H */
