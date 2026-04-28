/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/cm_rice_checksum.h — Rice-style ciphertext checksum CM
 *                             (Issue #5, 작업2-5)
 *
 *   "ML-KEM Dec 에 적용. 초기 CipherText c 의 Checksum 계산 후, 최종
 *    계산된 c' 의 Checksum 과 비교.  Checksum 충돌 방지를 위해 DTRNG
 *    로 생성한 랜덤 값을 각 항에 곱셈 연산하여 진행하라."
 *
 * 동작:
 *   cm_rice_ctx ctx;
 *   cm_rice_init(&ctx);                  // DTRNG 로 랜덤 가중치 r[] 생성
 *   uint32_t s_in  = cm_rice_compute(&ctx, c,  CT_LEN);
 *   ... Decaps 내부에서 c' 재계산 ...
 *   uint32_t s_out = cm_rice_compute(&ctx, cp, CT_LEN);
 *   if (cm_rice_compare(s_in, s_out)) ok; else fault();
 *
 * baseline 빌드(CM_RICE_CHECKSUM 미정의) 시:
 *   cm_rice_compute 는 단순 XOR-checksum,
 *   cm_rice_compare 는 항상 1 반환.
 */
#ifndef IMPL_SC300_CM_RICE_CHECKSUM_H
#define IMPL_SC300_CM_RICE_CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

#define CM_RICE_NWEIGHTS 32u   /* 32 byte 윈도우, ct 1088B = 34 windows */

typedef struct {
    uint32_t weights[CM_RICE_NWEIGHTS];   /* DTRNG 생성, 0 회피 */
    uint32_t seed;
} cm_rice_ctx;

void     cm_rice_init   (cm_rice_ctx *ctx);
uint32_t cm_rice_compute(const cm_rice_ctx *ctx,
                         const uint8_t *buf, size_t len);
int      cm_rice_compare(uint32_t s1, uint32_t s2);

#endif /* IMPL_SC300_CM_RICE_CHECKSUM_H */
