/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/cm_parity.c — Parity check CM (Issue #5, 작업2-3) */

#include "cm_parity.h"

void cm_parity_init(cm_parity_state *st)
{
    st->accum = 0u;
    st->count = 0u;
}

void cm_parity_update(cm_parity_state *st, uint32_t value)
{
#if defined(CM_PARITY)
    st->accum ^= value;
    st->count += 1u;
#else
    (void)st; (void)value;
#endif
}

int cm_parity_check(const cm_parity_state *st, uint32_t expected_parity)
{
#if defined(CM_PARITY)
    return (st->accum == expected_parity) ? 1 : 0;
#else
    (void)st; (void)expected_parity;
    return 1;
#endif
}

uint32_t cm_parity_buf(const uint8_t *p, size_t n)
{
    uint32_t acc = 0u;
    size_t i;
    for (i = 0; i + 4 <= n; i += 4) {
        uint32_t w = (uint32_t)p[i]
                   | ((uint32_t)p[i+1] << 8)
                   | ((uint32_t)p[i+2] << 16)
                   | ((uint32_t)p[i+3] << 24);
        acc ^= w;
    }
    for (; i < n; i++) {
        acc ^= (uint32_t)p[i];
    }
    return acc;
}
