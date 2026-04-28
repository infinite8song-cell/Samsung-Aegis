/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/cm_shuffling.h — Index shuffling CM (Issue #5, 작업2-1)
 *
 *   "배열 {0,1,...,n}을 선언 후 Shuffle. 해당 배열의 인덱스 순서대로
 *    비순차적으로 연산을 수행하라."
 *
 * Fisher–Yates shuffle on uint16_t[n]. n ≤ 4096.  랜덤 소스는 DTRNG
 * 시뮬레이션(randombytes()).  CM_SHUFFLING 미정의 시 idx[i]=i 로 채움
 * (zero-overhead identity, 호출부 코드 변경 없음).
 */
#ifndef IMPL_SC300_CM_SHUFFLING_H
#define IMPL_SC300_CM_SHUFFLING_H

#include <stdint.h>
#include <stddef.h>

/* idx[0..n-1] 를 0..n-1 로 채운 후 shuffle (CM_SHUFFLING) 또는
 * identity (no-CM build).  반환값: n. */
unsigned int cm_shuffle_indices(uint16_t *idx, unsigned int n);

/* 단일 16-bit 무작위(0..max_excl-1) — Fisher–Yates 내부 사용. */
uint16_t cm_rand_u16(uint16_t max_excl);

#endif /* IMPL_SC300_CM_SHUFFLING_H */
