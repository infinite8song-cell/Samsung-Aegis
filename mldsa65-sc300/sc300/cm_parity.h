/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/cm_parity.h — Parity check CM (Issue #5, 작업2-3)
 *
 *   "알고리즘 수행 중 특정 값에 대한 Parity를 계산. ML-KEM KeyGen,
 *    Decaps에서는 total_iter 만큼 수행 후 각 Parity 값을 검증하라."
 *
 * 사용 패턴:
 *   cm_parity_state st;
 *   cm_parity_init(&st);
 *   for (i=0;i<total_iter;i++) {
 *      ... do op ...
 *      cm_parity_update(&st, value);
 *   }
 *   if (!cm_parity_check(&st, expected)) { fault(); }
 *
 * baseline (CM_PARITY 미정의) 시 모든 함수는 inline 된 no-op 이고
 * cm_parity_check() 는 항상 1 (pass) 을 반환한다.
 */
#ifndef IMPL_SC300_CM_PARITY_H
#define IMPL_SC300_CM_PARITY_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t accum;       /* XOR of low-32 of each value */
    uint32_t count;
} cm_parity_state;

void     cm_parity_init  (cm_parity_state *st);
void     cm_parity_update(cm_parity_state *st, uint32_t value);
/* expected_parity: 호출 측이 별도 경로로 계산해 비교. 빌드 옵션 OFF
 * 일 때 항상 1. */
int      cm_parity_check (const cm_parity_state *st, uint32_t expected_parity);

/* convenience: parity over a contiguous byte buffer */
uint32_t cm_parity_buf   (const uint8_t *p, size_t n);

#endif /* IMPL_SC300_CM_PARITY_H */
