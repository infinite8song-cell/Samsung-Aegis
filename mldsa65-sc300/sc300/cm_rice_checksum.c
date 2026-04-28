/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/cm_rice_checksum.c — Rice-weighted ciphertext checksum
 *                             (Issue #5, 작업2-5) */

#include "cm_rice_checksum.h"
#include <string.h>

#if defined(CM_RICE_CHECKSUM)
#include "randombytes.h"
#endif

void cm_rice_init(cm_rice_ctx *ctx)
{
#if defined(CM_RICE_CHECKSUM)
    randombytes((uint8_t *)ctx->weights, sizeof(ctx->weights));
    /* 0 가중치 회피 (충돌 위험) */
    for (unsigned i = 0; i < CM_RICE_NWEIGHTS; i++) {
        if (ctx->weights[i] == 0u) ctx->weights[i] = 0x9E3779B9u;
    }
    uint8_t s[4];
    randombytes(s, 4);
    ctx->seed = (uint32_t)s[0]
              | ((uint32_t)s[1] << 8)
              | ((uint32_t)s[2] << 16)
              | ((uint32_t)s[3] << 24);
#else
    memset(ctx, 0, sizeof(*ctx));
    ctx->seed = 0xDEADBEEFu;
    for (unsigned i = 0; i < CM_RICE_NWEIGHTS; i++) {
        ctx->weights[i] = 1u + i;   /* deterministic identity weights */
    }
#endif
}

uint32_t cm_rice_compute(const cm_rice_ctx *ctx,
                          const uint8_t *buf, size_t len)
{
    uint32_t acc = ctx->seed;
    size_t i = 0;
    unsigned widx = 0;
    while (i < len) {
        size_t take = len - i;
        if (take > 4) take = 4;
        uint32_t w = 0;
        for (size_t k = 0; k < take; k++) {
            w |= (uint32_t)buf[i + k] << (8u * k);
        }
        /* 곱셈 가중 — 충돌 회피 */
        acc ^= (uint32_t)(w * ctx->weights[widx]);
        widx = (widx + 1u) % CM_RICE_NWEIGHTS;
        i += take;
    }
    return acc;
}

int cm_rice_compare(uint32_t s1, uint32_t s2)
{
#if defined(CM_RICE_CHECKSUM)
    /* constant-time compare */
    uint32_t d = s1 ^ s2;
    d |= d >> 16;
    d |= d >>  8;
    d |= d >>  4;
    d |= d >>  2;
    d |= d >>  1;
    return (int)(1u - (d & 1u));
#else
    (void)s1; (void)s2;
    return 1;
#endif
}
