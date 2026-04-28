/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/cm_masking.c — Arithmetic / Boolean masking helpers
 *                       (Issue #5, 작업2-2)
 *
 * baseline 빌드(=define 없음): 모든 함수는 identity / 표준 SHA3 호출.
 * CM_MASKING 빌드        : DTRNG 마스크로 1차 마스킹 적용.
 */

#include "cm_masking.h"
#include <string.h>

#if defined(CM_MASKING)
#include "randombytes.h"
#include "fips202.h"
#endif

/* -------------------- 16-bit (ML-KEM) -------------------- */

int16_t cm_mask_add16(int16_t x, int16_t q, int16_t *r_out)
{
#if defined(CM_MASKING)
    uint8_t b[2];
    randombytes(b, 2);
    int16_t r = (int16_t)((uint16_t)b[0] | ((uint16_t)b[1] << 8));
    if (q > 0) {
        r = (int16_t)(((int32_t)(uint16_t)r) % q);
    }
    *r_out = r;
    int32_t s = (int32_t)x + (int32_t)r;
    if (q > 0) {
        s %= q;
        if (s < 0) s += q;
    }
    return (int16_t)s;
#else
    *r_out = 0;
    (void)q;
    return x;
#endif
}

int16_t cm_unmask16(int16_t x_share, int16_t r, int16_t q)
{
#if defined(CM_MASKING)
    int32_t v = (int32_t)x_share - (int32_t)r;
    if (q > 0) {
        v %= q;
        if (v < 0) v += q;
    }
    return (int16_t)v;
#else
    (void)r; (void)q;
    return x_share;
#endif
}

int16_t cm_mask_mul16(int16_t a, int16_t x, int16_t q, int16_t *r_out)
{
#if defined(CM_MASKING)
    int16_t r;
    int16_t xm = cm_mask_add16(x, q, &r);
    int32_t v  = (int32_t)a * (int32_t)xm;
    int32_t rr = (int32_t)a * (int32_t)r;
    if (q > 0) {
        v  %= q; if (v < 0) v += q;
        rr %= q; if (rr < 0) rr += q;
    }
    *r_out = (int16_t)rr;
    return (int16_t)v;
#else
    (void)q;
    *r_out = 0;
    return (int16_t)((int32_t)a * (int32_t)x);
#endif
}

/* -------------------- 32-bit (ML-DSA) -------------------- */

int32_t cm_mask_add32(int32_t x, int32_t q, int32_t *r_out)
{
#if defined(CM_MASKING)
    uint8_t b[4];
    randombytes(b, 4);
    int32_t r = (int32_t)((uint32_t)b[0] |
                           ((uint32_t)b[1] << 8) |
                           ((uint32_t)b[2] << 16) |
                           ((uint32_t)b[3] << 24));
    if (q > 0) {
        r %= q; if (r < 0) r += q;
    }
    *r_out = r;
    int64_t s = (int64_t)x + (int64_t)r;
    if (q > 0) {
        s %= q;
        if (s < 0) s += q;
    }
    return (int32_t)s;
#else
    *r_out = 0;
    (void)q;
    return x;
#endif
}

int32_t cm_unmask32(int32_t x_share, int32_t r, int32_t q)
{
#if defined(CM_MASKING)
    int64_t v = (int64_t)x_share - (int64_t)r;
    if (q > 0) {
        v %= q;
        if (v < 0) v += q;
    }
    return (int32_t)v;
#else
    (void)r; (void)q;
    return x_share;
#endif
}

int32_t cm_mask_mul32(int32_t a, int32_t x, int32_t q, int32_t *r_out)
{
#if defined(CM_MASKING)
    int32_t r;
    int32_t xm = cm_mask_add32(x, q, &r);
    int64_t v  = (int64_t)a * (int64_t)xm;
    int64_t rr = (int64_t)a * (int64_t)r;
    if (q > 0) {
        v  %= q; if (v < 0) v += q;
        rr %= q; if (rr < 0) rr += q;
    }
    *r_out = (int32_t)rr;
    return (int32_t)v;
#else
    (void)q;
    *r_out = 0;
    return (int32_t)((int64_t)a * (int64_t)x);
#endif
}

/* -------------------- Boolean masking (bytes) -------------------- */

void cm_mask_bytes(uint8_t *m_xor_mask, uint8_t *mask_out,
                    const uint8_t *m, size_t mlen)
{
#if defined(CM_MASKING)
    randombytes(mask_out, mlen);
    for (size_t i = 0; i < mlen; i++) {
        m_xor_mask[i] = (uint8_t)(m[i] ^ mask_out[i]);
    }
#else
    if (mask_out) memset(mask_out, 0, mlen);
    if (m_xor_mask != m) memcpy(m_xor_mask, m, mlen);
#endif
}

void cm_unmask_bytes(uint8_t *m, const uint8_t *m_xor_mask,
                      const uint8_t *mask, size_t mlen)
{
#if defined(CM_MASKING)
    for (size_t i = 0; i < mlen; i++) {
        m[i] = (uint8_t)(m_xor_mask[i] ^ mask[i]);
    }
#else
    (void)mask;
    if (m != m_xor_mask) memcpy(m, m_xor_mask, mlen);
#endif
}

/* -------------------- Masked SHA-3 / SHAKE -------------------- */
/* Two-share absorb: the underlying Keccak permutation is the unprotected
 * one; protection comes from never having m unmasked in a CPU register at
 * absorb time.  This is a PoC-level CM (cost-emulation only, no formal
 * 1st-order DPA proof).  Output is identical to an unmasked H(m1 ^ m0). */

void cm_masked_sha3_512(uint8_t out[64],
                          const uint8_t *m1, const uint8_t *m0, size_t mlen)
{
#if defined(CM_MASKING)
    /* recombine on-the-fly into a small chunk buffer */
    uint8_t buf[128];
    sha3_512incctx ctx;
    sha3_512_inc_init(&ctx);
    size_t off = 0;
    while (off < mlen) {
        size_t take = mlen - off;
        if (take > sizeof(buf)) take = sizeof(buf);
        for (size_t i = 0; i < take; i++) {
            buf[i] = (uint8_t)(m1[off + i] ^ m0[off + i]);
        }
        sha3_512_inc_absorb(&ctx, buf, take);
        off += take;
    }
    sha3_512_inc_finalize(out, &ctx);
    /* scrub */
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = 0;
#else
    /* baseline: m1 == m, m0 ignored */
    (void)m0;
    sha3_512(out, m1, mlen);
#endif
}

void cm_masked_shake256(uint8_t *out, size_t outlen,
                         const uint8_t *m1, const uint8_t *m0, size_t mlen)
{
#if defined(CM_MASKING)
    uint8_t buf[128];
    shake256incctx ctx;
    shake256_inc_init(&ctx);
    size_t off = 0;
    while (off < mlen) {
        size_t take = mlen - off;
        if (take > sizeof(buf)) take = sizeof(buf);
        for (size_t i = 0; i < take; i++) {
            buf[i] = (uint8_t)(m1[off + i] ^ m0[off + i]);
        }
        shake256_inc_absorb(&ctx, buf, take);
        off += take;
    }
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(out, outlen, &ctx);
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = 0;
#else
    (void)m0;
    shake256(out, outlen, m1, mlen);
#endif
}

/* -------------------- Masked Enc (ML-KEM IND-CPA) -------------------- */
/* Forward declaration of the unmasked indcpa_enc from sc300_kem/.       */
extern void PQCLEAN_MLKEM768_CLEAN_indcpa_enc(uint8_t c[/*1088*/],
                                               const uint8_t m[32],
                                               const uint8_t pk[/*1184*/],
                                               const uint8_t coins[32]);

void cm_masked_indcpa_enc(uint8_t ct[],
                            const uint8_t *msg1,
                            const uint8_t *msg0,
                            const uint8_t *pk,
                            const uint8_t coins[32])
{
#if defined(CM_MASKING)
    /* Recombine inside a stack-local buffer that is scrubbed before return.
     * 32 byte 한정이라 단일 iteration. */
    uint8_t m_recombined[32];
    for (size_t i = 0; i < 32; i++) {
        m_recombined[i] = (uint8_t)(msg1[i] ^ msg0[i]);
    }
    PQCLEAN_MLKEM768_CLEAN_indcpa_enc(ct, m_recombined, pk, coins);
    for (size_t i = 0; i < 32; i++) m_recombined[i] = 0;
#else
    (void)msg0;
    PQCLEAN_MLKEM768_CLEAN_indcpa_enc(ct, msg1, pk, coins);
#endif
}
