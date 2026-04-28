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
#include "cm_parity.h"          /* -I$(HERE)/sc300 */
#include "cm_integrity.h"
#include "cm_rice_checksum.h"
#include "cm_shuffling.h"

#define WRAPPER_SUCCESS 0x1234u

#ifndef MLDSA_CM_TOTAL_ITER
#define MLDSA_CM_TOTAL_ITER 1u   /* Issue #5 명시 — KeyGen/Sign 반복 횟수 */
#endif

/* ------------------------------------------------------------------ */

unsigned int crypto_sign_keypair(
    unsigned char       *pk,
    unsigned char       *sk,
    unsigned char       *rnd,              /* 32-byte seed (xi) */
    unsigned int         inv_add_rnd,
    unsigned char        security_level,
    unsigned int        *secret_parity)
{
    int rc = 0;
    cm_parity_state    par;  cm_parity_init(&par);
    cm_integrity_state intg; cm_integrity_init(&intg);
    /* inv_add_rnd: caller supplies cm_inverse_addr(&intg) of caller's
     * own struct.  Embedded build이 0 을 넘기면 자체 관리. */
    uintptr_t inv = (inv_add_rnd != 0u)
                  ? (uintptr_t)inv_add_rnd
                  : cm_inverse_addr(&intg);

    if (rnd == (unsigned char *)0) {
        return (unsigned int)-1;
    }

    /* Issue #5 작업2-3: total_iter 만큼 반복하며 parity 누적
     * (단순 결정론적 KeyGen 이라 매 iter 동일 결과; iter>1 은 fault
     *  주입 검출용).  baseline 빌드는 iter=1 단발. */
    for (unsigned it = 0; it < MLDSA_CM_TOTAL_ITER; it++) {
        if (security_level == 44) {
            rc = PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair_from_seed(
                     pk, sk, (const uint8_t *)rnd);
        } else {
            rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(
                     pk, sk, (const uint8_t *)rnd);
        }
        cm_integrity_record(inv, (uint32_t)(rc + 1));
        if (rc != 0) return (unsigned int)rc;

        /* parity over public-key bytes (s1, s2 are inside sk; pk is the
         * derived public artefact whose parity rotates with secret KG) */
        size_t pklen = (security_level == 44) ? MLDSA44_PUBLICKEYBYTES
                                              : MLDSA65_PUBLICKEYBYTES;
        cm_parity_update(&par, cm_parity_buf(pk, pklen));
    }

    if (secret_parity != (void *)0) {
        *secret_parity = (unsigned int)par.accum;
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
    (void)inv_add_rnd;

    if (rnd == (const unsigned char *)0) {
        return (unsigned int)-1;
    }

    /* CM 4 — Integrity 누적 (호출 측 inv_add 가 0 이면 내부 관리) */
    cm_integrity_state intg; cm_integrity_init(&intg);
    uintptr_t inv = (inv_add != 0u) ? (uintptr_t)inv_add
                                     : cm_inverse_addr(&intg);

    /* CM 1 — Shuffling (sign 은 단발이라 의미 없으나, 시연용으로
     * 무작위 dummy index pass 를 한 번 수행해 cost-emulation). */
    uint16_t dummy_idx[8];
    cm_shuffle_indices(dummy_idx, 8);

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
    cm_integrity_record(inv, (uint32_t)(rc + 1));

    /* CM 5 — Rice checksum 비교는 KEM Dec 전용; 서명은 secret_parity 만 검증.
     * CM 3 — secret_parity 가 caller 가 KeyGen 에서 받은 값과 일치해야 함. */
    if (secret_parity != 0u) {
        /* sk의 'K' 필드(masking key) parity 를 동일 방식으로 재계산.
         * KeyGen 시 출력한 parity 값과 일치하면 fault 없음. */
        uint32_t p = cm_parity_buf((const uint8_t *)sk,
                                    (security_level == 44)
                                      ? MLDSA44_PUBLICKEYBYTES
                                      : MLDSA65_PUBLICKEYBYTES);
        if (p != (uint32_t)secret_parity) {
            /* parity 불일치 — fault 가능성, 그러나 하드 abort 대신 rc 변경 */
            rc = (rc == 0) ? 0xCAFEu : rc;
        }
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

    /* CM 4 — Integrity (verify 는 1회 호출이라 단발 누적) */
    cm_integrity_state intg; cm_integrity_init(&intg);
    uintptr_t inv = (inv_add != 0u) ? (uintptr_t)inv_add
                                     : cm_inverse_addr(&intg);

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
    cm_integrity_record(inv, (uint32_t)(rc + 1));

    return (rc == 0) ? WRAPPER_SUCCESS : (unsigned int)rc;
}
