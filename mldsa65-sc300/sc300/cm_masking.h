/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/cm_masking.h — Arithmetic masking helpers (Issue #5, 작업2-2)
 *
 *   "랜덤 마스크 변수를 생성하여 덧셈/뺄셈/곱셈 후 마스크를 제거하여
 *    원본 값을 복원."
 *
 *   "Dec 함수 특이사항: 메시지 m을 그대로 복원하지 말고, 마스크 값 m0
 *    를 생성해 m과 연산한 m1을 출력. 이후 m1, m0를 사용해야 하므로
 *    Masked_Enc, Masked_Sha3 함수를 별도 구현하라."
 *
 * 전역 도메인:
 *   ML-KEM   : modulus q = 3329 (KYBER_Q),  16-bit
 *   ML-DSA   : modulus q = 8380417,         32-bit (FIPS 204)
 *
 * baseline (define 없음) 시 모든 헬퍼는 identity / no-op 으로 inline 된다.
 */
#ifndef IMPL_SC300_CM_MASKING_H
#define IMPL_SC300_CM_MASKING_H

#include <stdint.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* 16-bit (ML-KEM-768)                                                */
/* ------------------------------------------------------------------ */

/* x  → (x + r) mod q ;   x_share = (x + r) mod q ;   *r_out = r */
int16_t cm_mask_add16 (int16_t x, int16_t q, int16_t *r_out);
/* x_share, r → x = (x_share - r) mod q */
int16_t cm_unmask16   (int16_t x_share, int16_t r, int16_t q);
/* (a*x + r) mod q ;    중간 값 노출 방지 */
int16_t cm_mask_mul16 (int16_t a, int16_t x, int16_t q, int16_t *r_out);

/* ------------------------------------------------------------------ */
/* 32-bit (ML-DSA-65)                                                 */
/* ------------------------------------------------------------------ */
int32_t cm_mask_add32 (int32_t x, int32_t q, int32_t *r_out);
int32_t cm_unmask32   (int32_t x_share, int32_t r, int32_t q);
int32_t cm_mask_mul32 (int32_t a, int32_t x, int32_t q, int32_t *r_out);

/* ------------------------------------------------------------------ */
/* Boolean masking for K bytes (used by Masked_SHA3).                  */
/* mask_out is filled with random; m_xor_mask = m ^ mask_out.          */
/* CM_MASKING off ⇒ mask=0, m_xor_mask = m.                            */
/* ------------------------------------------------------------------ */
void cm_mask_bytes  (uint8_t *m_xor_mask, uint8_t *mask_out,
                     const uint8_t *m, size_t mlen);
void cm_unmask_bytes(uint8_t *m, const uint8_t *m_xor_mask,
                     const uint8_t *mask, size_t mlen);

/* ------------------------------------------------------------------ */
/* Masked_SHA3-512 / SHAKE — m, m0 두 share 를 받아 H(m1=m^m0, m0) 를
 * 단일 absorb 후 unmask 시점을 출력 단계로 미룸.  baseline 빌드에서는
 * 일반 sha3_512 / shake256 호출과 등가.                                */
/* ------------------------------------------------------------------ */
void cm_masked_sha3_512(uint8_t out[64],
                          const uint8_t *m1, const uint8_t *m0, size_t mlen);

void cm_masked_shake256(uint8_t *out, size_t outlen,
                         const uint8_t *m1, const uint8_t *m0, size_t mlen);

/* ------------------------------------------------------------------ */
/* Masked_Enc — ML-KEM IND-CPA Enc 를 두 share (msg1, msg0) 로 수행.   */
/* baseline 빌드 시 한 번의 일반 Enc 와 동일 출력.  CM_MASKING 시       */
/*   ct = Enc(msg1 ^ msg0, pk, coins)  와 동일하지만 내부적으로 m 을   */
/*   복원하지 않고 두 share 상태를 유지한다 (PoC 수준).                */
/* ------------------------------------------------------------------ */
void cm_masked_indcpa_enc(uint8_t ct[/*1088*/],
                            const uint8_t *msg1,
                            const uint8_t *msg0,
                            const uint8_t *pk,
                            const uint8_t coins[32]);

#endif /* IMPL_SC300_CM_MASKING_H */
