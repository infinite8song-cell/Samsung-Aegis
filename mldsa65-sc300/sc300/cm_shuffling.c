/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/cm_shuffling.c — Fisher–Yates index shuffle (Issue #5, 작업2-1) */

#include "cm_shuffling.h"
#include <string.h>

#if defined(CM_SHUFFLING)
#include "randombytes.h"
#endif

uint16_t cm_rand_u16(uint16_t max_excl)
{
#if defined(CM_SHUFFLING)
    /* rejection sampling — DTRNG 모사용 randombytes 사용 */
    if (max_excl == 0) {
        return 0;
    }
    uint32_t lim = (uint32_t)0x10000u - ((uint32_t)0x10000u % (uint32_t)max_excl);
    while (1) {
        uint8_t r[2];
        randombytes(r, 2);
        uint16_t v = (uint16_t)((uint16_t)r[0] | ((uint16_t)r[1] << 8));
        if ((uint32_t)v < lim) {
            return (uint16_t)((uint32_t)v % (uint32_t)max_excl);
        }
    }
#else
    (void)max_excl;
    return 0;
#endif
}

unsigned int cm_shuffle_indices(uint16_t *idx, unsigned int n)
{
    if (n == 0) return 0;
    /* identity 채우기는 모든 빌드에서 동일 — 호출부가 idx[] 를
     * 그대로 사용해도 동작이 깨지지 않는다. */
    for (unsigned int i = 0; i < n; i++) {
        idx[i] = (uint16_t)i;
    }

#if defined(CM_SHUFFLING)
    /* in-place Fisher–Yates */
    for (unsigned int i = n - 1; i > 0; i--) {
        uint16_t j   = cm_rand_u16((uint16_t)(i + 1));
        uint16_t tmp = idx[i];
        idx[i]       = idx[j];
        idx[j]       = tmp;
    }
#endif
    return n;
}
