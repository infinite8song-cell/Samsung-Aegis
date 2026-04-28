/*
 * api_wrapper_kem.c — ML-KEM-768 caller-facing wrapper (internal-only API).
 *
 * No randombytes dependency; caller provides all coins.
 * Success return = 0x1234 (matches api_wrapper.c convention).
 */

#include <stdint.h>
#include <stddef.h>

#include "api_wrapper_kem.h"

/* Forward declarations — avoid including ref_kem headers (they collide
 * with the ref/ ML-DSA headers when both modules are linked together). */
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(uint8_t *pk,
                                                      uint8_t *sk,
                                                      const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(uint8_t *ct,
                                                  uint8_t *ss,
                                                  const uint8_t *pk,
                                                  const uint8_t *coins);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss,
                                          const uint8_t *ct,
                                          const uint8_t *sk);

/* CM-augmented entry points (sc300_kem/kem_cm.c).  Only referenced when
 * any CM_* flag is set at build time; kem_decaps() routes to it.       */
#if defined(CM_SHUFFLING) || defined(CM_MASKING) || defined(CM_PARITY) || \
    defined(CM_INTEGRITY) || defined(CM_RICE_CHECKSUM)
#define IMPL_SC300_USE_KEM_CM 1
#include "cm_integrity.h"      /* -I$(HERE)/sc300 */
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec_cm(
        uint8_t *ss, const uint8_t *ct, const uint8_t *sk,
        uint32_t *parity_or_null,
        cm_integrity_state *intg_or_null);
#endif

#define KEM_SUCCESS 0x1234u

unsigned int kem_keypair(
    unsigned char       *pk,
    unsigned char       *sk,
    const unsigned char *coins)
{
    int rc;
    if (coins == (const unsigned char *)0) {
        return (unsigned int)-1;
    }
    rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(
            (uint8_t *)pk, (uint8_t *)sk, (const uint8_t *)coins);
    return (rc == 0) ? KEM_SUCCESS : (unsigned int)rc;
}

unsigned int kem_encaps(
    unsigned char       *ct,
    unsigned char       *ss,
    const unsigned char *pk,
    const unsigned char *coins)
{
    int rc;
    if (coins == (const unsigned char *)0) {
        return (unsigned int)-1;
    }
    rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(
            (uint8_t *)ct, (uint8_t *)ss,
            (const uint8_t *)pk, (const uint8_t *)coins);
    return (rc == 0) ? KEM_SUCCESS : (unsigned int)rc;
}

unsigned int kem_decaps(
    unsigned char       *ss,
    const unsigned char *ct,
    const unsigned char *sk)
{
    int rc;
#if defined(IMPL_SC300_USE_KEM_CM)
    /* Issue #5 의 5 가지 CM 적용 경로 */
    rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec_cm(
            (uint8_t *)ss, (const uint8_t *)ct, (const uint8_t *)sk,
            (uint32_t *)0, (cm_integrity_state *)0);
#else
    rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(
            (uint8_t *)ss, (const uint8_t *)ct, (const uint8_t *)sk);
#endif
    return (rc == 0) ? KEM_SUCCESS : (unsigned int)rc;
}
