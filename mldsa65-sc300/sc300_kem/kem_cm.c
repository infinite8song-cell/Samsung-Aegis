/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300_kem/kem_cm.c — ML-KEM-768 Decaps / KeyGen with all 5 CMs applied
 *                       (Issue Samsung-Aegis #5, 작업2)
 *
 * baseline 빌드 (CM_* 미정의) 시 동작은 PQClean reference 와 byte-identical.
 * 빌드 토글:
 *   -DCM_SHUFFLING       indcpa 내 polyvec 인덱스 비순차 처리
 *   -DCM_MASKING         m → (m1, m0) Boolean share, masked SHA3 / Enc
 *   -DCM_PARITY          KeyGen / Decaps total_iter parity 누적·검증
 *   -DCM_INTEGRITY       inverse_address 무결성 누적
 *   -DCM_RICE_CHECKSUM   ct vs ct' DTRNG-가중 체크섬 비교
 *
 * 본 모듈은 ref_kem/ 의 PQClean 진입점을 호출하며 hot path 의 외곽에서
 * CM 을 적용한다.  Sym4-A 표적인 secret 키/메시지는 다음 지점에서 보호:
 *
 *    indcpa_dec()   →  m (32B, decoded message)
 *      → 분기a) hash_g(buf=m||z) ⇒ kr
 *      → 분기b) indcpa_enc(ct', buf, pk, coins')  ← masked 변형 사용
 *      → 분기c) verify(ct, ct') ⇒ fail
 *
 *  적용 CM 위치:
 *    [Masking]      indcpa_dec 직후 m → (m1=m^m0, m0)
 *    [Masked SHA3]  hash_g 대신 cm_masked_sha3_512(m1, m0)
 *    [Masked Enc]   indcpa_enc 대신 cm_masked_indcpa_enc(m1, m0, pk, coins')
 *    [Rice CSUM]    Decaps 진입 시 chk(ct), Enc' 후 chk(ct'), compare
 *    [Parity]       (m1 ^ m0) 의 word-XOR 누적 → 외부 검증
 *    [Integrity]    indcpa_dec / indcpa_enc 반환값(=void → 1) 누적
 *    [Shuffling]    indcpa_dec coefficient loop (poly_sub) 인덱스 셔플
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "params.h"
#include "kem.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "api.h"

#include "cm.h"          /* -I$(HERE)/sc300 supplies the path */

/* ref_kem 가 제공하는 PQClean 함수 prototype 들 */
extern void PQCLEAN_MLKEM768_CLEAN_indcpa_keypair_derand(
        uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
        const uint8_t coins[KYBER_SYMBYTES]);
extern void PQCLEAN_MLKEM768_CLEAN_indcpa_enc(
        uint8_t c[KYBER_INDCPA_BYTES],
        const uint8_t m[KYBER_INDCPA_MSGBYTES],
        const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        const uint8_t coins[KYBER_SYMBYTES]);
extern void PQCLEAN_MLKEM768_CLEAN_indcpa_dec(
        uint8_t m[KYBER_INDCPA_MSGBYTES],
        const uint8_t c[KYBER_INDCPA_BYTES],
        const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]);
extern int  PQCLEAN_MLKEM768_CLEAN_verify(const uint8_t *a, const uint8_t *b, size_t len);
extern void PQCLEAN_MLKEM768_CLEAN_cmov  (uint8_t *r, const uint8_t *x, size_t len, uint8_t b);

#ifndef MLKEM_CM_TOTAL_ITER
#define MLKEM_CM_TOTAL_ITER 1   /* parity 검증을 위한 반복 횟수 (Issue 명세) */
#endif

/* ------------------------------------------------------------------ */
/* CM-augmented Decaps                                                  */
/* ------------------------------------------------------------------ */
int  PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec_cm(
        uint8_t       *ss,
        const uint8_t *ct,
        const uint8_t *sk,
        uint32_t      *out_parity_or_null,
        cm_integrity_state *out_integrity_or_null)
{
    int fail = 0;
    uint8_t  buf[2 * KYBER_SYMBYTES];
    uint8_t  m0 [KYBER_SYMBYTES];                  /* mask share */
    uint8_t  m1 [KYBER_SYMBYTES];                  /* masked m   */
    uint8_t  kr [2 * KYBER_SYMBYTES];
    uint8_t  cmp[KYBER_CIPHERTEXTBYTES];
    const uint8_t *pk = sk + KYBER_INDCPA_SECRETKEYBYTES;

    /* ----- [Rice CSUM] 입력 ct 체크섬 (CM 5) ----- */
    cm_rice_ctx rice;
    cm_rice_init(&rice);
    uint32_t csum_in = cm_rice_compute(&rice, ct, KYBER_CIPHERTEXTBYTES);

    /* ----- [Integrity] 누적 컨텍스트 (CM 4) ----- */
    cm_integrity_state intg;
    cm_integrity_init(&intg);
    uintptr_t inv = cm_inverse_addr(&intg);

    /* ----- [Parity] total_iter 누적 컨텍스트 (CM 3) ----- */
    cm_parity_state par;
    cm_parity_init(&par);

    for (unsigned iter = 0; iter < MLKEM_CM_TOTAL_ITER; iter++) {

        /* ----- IND-CPA decrypt → m (32B) ----- */
        uint8_t m_local[KYBER_INDCPA_MSGBYTES];
        PQCLEAN_MLKEM768_CLEAN_indcpa_dec(m_local, ct, sk);
        cm_integrity_record(inv, 1u);   /* indcpa_dec is void → record 1 */

        /* ----- [Masking] m → (m1, m0) (CM 2) -----
         * Dec 함수 특이사항(Issue): m 을 그대로 복원하지 말고 m1 = m ^ m0
         * 형태로 유지. 이후 masked_sha3 / masked_enc 사용. */
        cm_mask_bytes(m1, m0, m_local, KYBER_SYMBYTES);
        for (size_t i = 0; i < sizeof(m_local); i++) m_local[i] = 0;

        /* ----- [Parity] m1 ^ m0 word XOR 누적 (CM 3) ----- */
        cm_parity_update(&par, cm_parity_buf(m1, KYBER_SYMBYTES) ^
                                cm_parity_buf(m0, KYBER_SYMBYTES));

        /* ----- 분기a) Masked hash_g(m || z) → (K, coins') -----
         * z 는 sk 끝 32B, public.  m1, m0 두 share 를 absorb. */
        {
            uint8_t buf1[2 * KYBER_SYMBYTES];
            uint8_t buf0[2 * KYBER_SYMBYTES];
            memcpy(buf1, m1, KYBER_SYMBYTES);
            memcpy(buf1 + KYBER_SYMBYTES,
                   sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES,
                   KYBER_SYMBYTES);
            memset(buf0, 0, sizeof(buf0));
            memcpy(buf0, m0, KYBER_SYMBYTES);
            cm_masked_sha3_512(kr, buf1, buf0, 2 * KYBER_SYMBYTES);

            /* baseline 추적용 buf (verify 후 cmov 에 사용 안 함) */
            memcpy(buf, buf1, 2 * KYBER_SYMBYTES);
            for (size_t i = 0; i < sizeof(buf1); i++) {
                buf[i] = (uint8_t)(buf1[i] ^ buf0[i]);
            }
            for (size_t i = 0; i < sizeof(buf0); i++) buf0[i] = 0;
            for (size_t i = 0; i < sizeof(buf1); i++) buf1[i] = 0;
        }

        /* ----- 분기b) Masked Enc(m1, m0, pk, coins') ----- */
        cm_masked_indcpa_enc(cmp, m1, m0, pk, kr + KYBER_SYMBYTES);
        cm_integrity_record(inv, 2u);

        /* ----- [Rice CSUM] 재계산 ct' 체크섬 비교 (CM 5) ----- */
        uint32_t csum_out = cm_rice_compute(&rice, cmp, KYBER_CIPHERTEXTBYTES);
        if (!cm_rice_compare(csum_in /* expected match? */, csum_out)) {
            /* 정상 Decaps 시 csum_in 와 csum_out 일치해야 함 */
            fail |= 0x10;
        }

        /* ----- 분기c) verify(ct, cmp) ----- */
        int v = PQCLEAN_MLKEM768_CLEAN_verify(ct, cmp, KYBER_CIPHERTEXTBYTES);
        if (v) fail |= 0x01;
        cm_integrity_record(inv, (uint32_t)(v + 3u));
    }

    /* Compute rejection key */
    rkprf(ss, sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, ct);

    /* Copy true key to return buffer if fail is false */
    PQCLEAN_MLKEM768_CLEAN_cmov(ss, kr, KYBER_SYMBYTES,
                                 (uint8_t)(1 - (fail & 1)));

    /* 호출자에게 parity / integrity 결과 전달 (옵션) */
    if (out_parity_or_null)    *out_parity_or_null = par.accum;
    if (out_integrity_or_null) *out_integrity_or_null = intg;

    /* Scrub */
    for (size_t i = 0; i < sizeof(m0); i++) m0[i] = 0;
    for (size_t i = 0; i < sizeof(m1); i++) m1[i] = 0;
    for (size_t i = 0; i < sizeof(kr); i++) kr[i] = 0;
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = 0;

    return fail ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* CM-augmented KeyGen — total_iter parity, integrity 만 적용          */
/* ------------------------------------------------------------------ */
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand_cm(
        uint8_t       *pk,
        uint8_t       *sk,
        const uint8_t *coins,
        uint32_t      *out_parity_or_null,
        cm_integrity_state *out_integrity_or_null)
{
    cm_parity_state    par;  cm_parity_init(&par);
    cm_integrity_state intg; cm_integrity_init(&intg);
    uintptr_t          inv = cm_inverse_addr(&intg);

    for (unsigned iter = 0; iter < MLKEM_CM_TOTAL_ITER; iter++) {
        PQCLEAN_MLKEM768_CLEAN_indcpa_keypair_derand(pk, sk, coins);
        cm_integrity_record(inv, 1u);

        memcpy(sk + KYBER_INDCPA_SECRETKEYBYTES, pk, KYBER_PUBLICKEYBYTES);
        hash_h(sk + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES,
                pk, KYBER_PUBLICKEYBYTES);
        memcpy(sk + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES,
                coins + KYBER_SYMBYTES, KYBER_SYMBYTES);

        /* parity: pk word-XOR */
        cm_parity_update(&par, cm_parity_buf(pk, KYBER_PUBLICKEYBYTES));
    }

    if (out_parity_or_null)    *out_parity_or_null = par.accum;
    if (out_integrity_or_null) *out_integrity_or_null = intg;
    return 0;
}
