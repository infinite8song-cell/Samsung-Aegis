/*
 * impl_sc300/sc300/sign.c — ML-DSA-65 Strategy-3 streaming for SC300
 *
 * Strategy-3 (adapted from dilithium-cortexm SIGN_STACKSTRATEGY=3):
 *
 * sign():
 *   Only polyveck w (6144 B) is kept across rejection loop iterations.
 *   A columns and y elements expanded on-the-fly per (k,l) pair — no
 *   full polyvecl mat_row or y vector stored.  s1/s2/t0 unpacked one
 *   poly at a time from packed SK.  z packed directly to sig.
 *   Stack: ~10.7 KB, BSS: 0.
 *
 * verify():
 *   Only polyvecl z (5120 B) needed; t1 unpacked per k-row from pk.
 *   A*z computed row-by-row without storing full matrix.
 *   Stack: ~10.5 KB, BSS: 0.
 *
 * keypair():
 *   Row-by-row A expansion (mat[K] 30 KB → mat_row 5 KB temporary).
 *   Stack: ~24 KB, BSS: 0.
 *
 * No static locals.  Functions are not re-entrant but that is fine
 * for a single-core SC300 embedded target.
 *
 * SK layout:
 *   rho  : sk + 0                                    (SEEDBYTES = 32)
 *   key  : sk + SEEDBYTES                            (SEEDBYTES = 32)
 *   tr   : sk + 2*SEEDBYTES                          (TRBYTES   = 64)
 *   s1[l]: sk + SK_OFF_S1(l)
 *   s2[k]: sk + SK_OFF_S2(k)
 *   t0[k]: sk + SK_OFF_T0(k)
 *
 * Sig layout:
 *   c-tilde : sig + 0                    (CTILDEBYTES = 48)
 *   z[l]    : sig + SIG_OFF_Z(l)         (POLYZ_PACKEDBYTES = 640 each)
 *   hints   : sig + SIG_OFF_H            (OMEGA+K = 61 bytes)
 */

#include "fips202.h"
#include "packing.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#ifndef MLDSA_NO_RANDOMBYTES
#include "randombytes.h"
#endif
#include "sign.h"
#include "symmetric.h"
#include "masked.h"
#include <stdint.h>
#include <string.h>

#define SK_OFF_S1(l) \
    (2u*SEEDBYTES + TRBYTES + (unsigned)(l)*POLYETA_PACKEDBYTES)
#define SK_OFF_S2(k) \
    (2u*SEEDBYTES + TRBYTES + (unsigned)L*POLYETA_PACKEDBYTES \
     + (unsigned)(k)*POLYETA_PACKEDBYTES)
#define SK_OFF_T0(k) \
    (2u*SEEDBYTES + TRBYTES + (unsigned)(L+K)*POLYETA_PACKEDBYTES \
     + (unsigned)(k)*POLYT0_PACKEDBYTES)
#define SIG_OFF_Z(l) (CTILDEBYTES + (unsigned)(l)*POLYZ_PACKEDBYTES)
#define SIG_OFF_H    (CTILDEBYTES + (unsigned)L*POLYZ_PACKEDBYTES)

/* ------------------------------------------------------------------ */
/* Keypair — split into helpers so each phase's large locals are       */
/* released before the next phase runs, minimizing peak stack.         */
/*                                                                      */
/* Phase peaks (each released on helper return):                        */
/*   gen_s1_packed       : polyvecl       ~5,120 B                      */
/*   gen_s2_packed       : polyveck       ~6,144 B                      */
/*   compute_t_streaming : polyvecl s1hat + 2 poly scratches ~7,168 B   */
/*                                                                      */
/* Total keypair peak (dominated by compute_t_streaming + callees):    */
/*   ~8-10 KB.                                                          */
/*                                                                      */
/* s1, s2, t0 are packed directly into their sk[] offsets as they are  */
/* produced; unpacked forms never co-exist with other polyvec buffers. */
/* ------------------------------------------------------------------ */

/* Phase 1: generate s1 (L polys, eta sampling) and pack into sk. */
static void gen_s1_packed(uint8_t *sk_s1_base,
                          const uint8_t rhoprime[CRHBYTES]) {
    polyvecl s1;
    unsigned int l;
    MLDSA_NAMESPACE(polyvecl_uniform_eta)(&s1, rhoprime, 0);
    for (l = 0; l < L; l++)
        MLDSA_NAMESPACE(polyeta_pack)(
            sk_s1_base + (unsigned)l * POLYETA_PACKEDBYTES, &s1.vec[l]);
}

/* Phase 2: generate s2 (K polys, eta sampling) and pack into sk. */
static void gen_s2_packed(uint8_t *sk_s2_base,
                          const uint8_t rhoprime[CRHBYTES]) {
    polyveck s2;
    unsigned int k;
    MLDSA_NAMESPACE(polyveck_uniform_eta)(&s2, rhoprime, L);
    for (k = 0; k < K; k++)
        MLDSA_NAMESPACE(polyeta_pack)(
            sk_s2_base + (unsigned)k * POLYETA_PACKEDBYTES, &s2.vec[k]);
}

/* Phase 3: t = A*NTT(s1) + s2, split to (t1, t0), stream-pack to outputs.
 * s1 and s2 are read back from sk in packed form. */
static void compute_t_streaming(uint8_t *pk_t1_base,
                                uint8_t *sk_t0_base,
                                const uint8_t rho[SEEDBYTES],
                                const uint8_t *sk) {
    polyvecl s1hat;             /* 5,120 B */
    poly     t_row, a_kl;       /* 2 x 1,024 B scratch */
    unsigned int k, l;

    /* Unpack s1 from sk into s1hat, then NTT in place. */
    for (l = 0; l < L; l++)
        POLYETA_UNPACK(
            &s1hat.vec[l], sk + SK_OFF_S1(l));
    MLDSA_NAMESPACE(polyvecl_ntt)(&s1hat);

    /* For each row k, compute t[k] = sum_l A[k][l] * s1hat[l]
     * then add s2[k], split into (t1[k], t0[k]) and pack out. */
    for (k = 0; k < K; k++) {
        /* t_row = A[k][0] * s1hat[0] */
        MLDSA_NAMESPACE(poly_uniform)(
            &a_kl, rho, (uint16_t)((k << 8) + 0));
        MLDSA_NAMESPACE(poly_pointwise_montgomery)(
            &t_row, &a_kl, &s1hat.vec[0]);

        for (l = 1; l < L; l++) {
            MLDSA_NAMESPACE(poly_uniform)(
                &a_kl, rho, (uint16_t)((k << 8) + l));
            MLDSA_NAMESPACE(poly_pointwise_montgomery)(
                &a_kl, &a_kl, &s1hat.vec[l]);
            MLDSA_NAMESPACE(poly_add)(&t_row, &t_row, &a_kl);
        }

        MLDSA_NAMESPACE(poly_reduce)(&t_row);
        MLDSA_NAMESPACE(poly_invntt_tomont)(&t_row);

        /* Unpack s2[k] into a_kl (reuse), add to t_row, caddq. */
        POLYETA_UNPACK(&a_kl, sk + SK_OFF_S2(k));
        MLDSA_NAMESPACE(poly_add)(&t_row, &t_row, &a_kl);
        MLDSA_NAMESPACE(poly_caddq)(&t_row);

        /* Split: t1 -> t_row, t0 -> a_kl (reused). */
        MLDSA_NAMESPACE(poly_power2round)(&t_row, &a_kl, &t_row);

        /* Pack directly to pk (t1) and sk (t0). */
        MLDSA_NAMESPACE(polyt1_pack)(
            pk_t1_base + (unsigned)k * POLYT1_PACKEDBYTES, &t_row);
        MLDSA_NAMESPACE(polyt0_pack)(
            sk_t0_base + (unsigned)k * POLYT0_PACKEDBYTES, &a_kl);
    }
}

int MLDSA_NAMESPACE(crypto_sign_keypair_from_seed)(
        uint8_t *pk, uint8_t *sk, const uint8_t xi[SEEDBYTES]) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    const uint8_t *rho, *rhoprime, *key;
    unsigned int i;

    for (i = 0; i < SEEDBYTES; i++) seedbuf[i] = xi[i];
    seedbuf[SEEDBYTES + 0] = K;
    seedbuf[SEEDBYTES + 1] = L;
    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    rho      = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key      = rhoprime + CRHBYTES;

    for (i = 0; i < SEEDBYTES; i++) pk[i] = rho[i];
    for (i = 0; i < SEEDBYTES; i++) sk[i] = rho[i];
    for (i = 0; i < SEEDBYTES; i++) sk[SEEDBYTES + i] = key[i];

    gen_s1_packed(sk + SK_OFF_S1(0), rhoprime);
    gen_s2_packed(sk + SK_OFF_S2(0), rhoprime);
    compute_t_streaming(pk + SEEDBYTES, sk + SK_OFF_T0(0), rho, sk);
    shake256(sk + 2 * SEEDBYTES, TRBYTES, pk,
             CRYPTO_PUBLICKEYBYTES);
    return 0;
}

#ifndef MLDSA_NO_RANDOMBYTES
int MLDSA_NAMESPACE(crypto_sign_keypair)(uint8_t *pk, uint8_t *sk) {
    uint8_t seedbuf[2 * SEEDBYTES + CRHBYTES];
    const uint8_t *rho, *rhoprime, *key;
    unsigned int i;

    /* Expand seed -> rho (pub), rhoprime (secret), key (secret) */
    randombytes(seedbuf, SEEDBYTES);
    seedbuf[SEEDBYTES + 0] = K;
    seedbuf[SEEDBYTES + 1] = L;
    shake256(seedbuf, 2 * SEEDBYTES + CRHBYTES, seedbuf, SEEDBYTES + 2);
    rho      = seedbuf;
    rhoprime = rho + SEEDBYTES;
    key      = rhoprime + CRHBYTES;

    /* Write rho -> pk[0..31]; rho || key -> sk[0..63].
     * tr (sk[64..127]) will be filled after t1 is in pk. */
    for (i = 0; i < SEEDBYTES; i++) pk[i] = rho[i];
    for (i = 0; i < SEEDBYTES; i++) sk[i] = rho[i];
    for (i = 0; i < SEEDBYTES; i++) sk[SEEDBYTES + i] = key[i];

    /* Phase 1: s1 generated, packed to sk[s1 region]. */
    gen_s1_packed(sk + SK_OFF_S1(0), rhoprime);

    /* Phase 2: s2 generated, packed to sk[s2 region]. */
    gen_s2_packed(sk + SK_OFF_S2(0), rhoprime);

    /* Phase 3: compute t = A*NTT(s1) + s2, split, pack t1 to pk, t0 to sk. */
    compute_t_streaming(pk + SEEDBYTES,
                        sk + SK_OFF_T0(0),
                        rho,
                        sk);

    /* Phase 4: tr = H(pk) written directly into sk[tr region]. */
    shake256(sk + 2 * SEEDBYTES, TRBYTES, pk,
             CRYPTO_PUBLICKEYBYTES);

    return 0;
}
#endif /* !MLDSA_NO_RANDOMBYTES */

/* ------------------------------------------------------------------ */
/* Sign (Strategy-3 streaming)                                         */
/*                                                                      */
/* Stack budget (approximate, callees included):                        */
/*   w        : polyveck  = 6,144 B  kept across rejection loop        */
/*   cp       : poly      = 1,024 B  challenge (NTT domain)            */
/*   tmp      : poly      = 1,024 B  multipurpose scratch               */
/*   y_elem   : poly      = 1,024 B  one element of y at a time        */
/*   w1_elem  : poly      = 1,024 B  one element of w1 at a time       */
/*   mu/rhoprime/rnd/w1_bytes/state : ~688 B                           */
/*   Total                          : ~10.7 KB                         */
/* ------------------------------------------------------------------ */
/* ------------------------------------------------------------------ */
/* Internal core: assumes mu is already computed.                      */
/* Used by both ML-DSA.Sign (external) and ML-DSA.Sign_internal.       */
/* ------------------------------------------------------------------ */
static int sign_core_with_mu_rnd(uint8_t *sig,
                                  size_t *siglen,
                                  const uint8_t mu[CRHBYTES],
                                  const uint8_t rnd_in[RNDBYTES],
                                  const uint8_t *sk);

#ifndef MLDSA_NO_RANDOMBYTES
static int sign_core_with_mu(uint8_t *sig,
                             size_t *siglen,
                             const uint8_t mu[CRHBYTES],
                             const uint8_t *sk) {
    uint8_t rnd[RNDBYTES];
    randombytes(rnd, RNDBYTES);
    return sign_core_with_mu_rnd(sig, siglen, mu, rnd, sk);
}

int MLDSA_NAMESPACE(crypto_sign_signature_ctx)(uint8_t *sig,
        size_t *siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *sk) {

    if (ctxlen > 255) {
        return -1;
    }

    uint8_t mu[CRHBYTES];
    shake256incctx state;
    const uint8_t *tr = sk + 2 * SEEDBYTES;

    /* mu = H(tr || 0x00 || ctxlen || ctx || m) — FIPS 204 external Sign */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, TRBYTES);
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    return sign_core_with_mu(sig, siglen, mu, sk);
}
#endif /* !MLDSA_NO_RANDOMBYTES */

int MLDSA_NAMESPACE(crypto_sign_signature_ctx_rnd)(uint8_t *sig,
        size_t *siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t rnd[RNDBYTES],
        const uint8_t *sk) {

    if (ctxlen > 255) {
        return -1;
    }

    uint8_t mu[CRHBYTES];
    shake256incctx state;
    const uint8_t *tr = sk + 2 * SEEDBYTES;

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, TRBYTES);
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    return sign_core_with_mu_rnd(sig, siglen, mu, rnd, sk);
}

/* ------------------------------------------------------------------ */
/* ML-DSA.Sign_internal (FIPS 204 Algorithm 7):                         */
/*   Inputs : sk, M' (= m), rnd (32 bytes)                              */
/*   mu     = H(tr || M', 64)                                           */
/*   rho''  = H(K || rnd || mu, 64)                                     */
/* For ACVP deterministic=true tests, caller passes rnd = 32 zero bytes.*/
/* ------------------------------------------------------------------ */
int MLDSA_NAMESPACE(crypto_sign_signature_internal)(uint8_t *sig,
        size_t *siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t rnd[RNDBYTES],
        const uint8_t *sk) {

    uint8_t mu[CRHBYTES];
    shake256incctx state;
    const uint8_t *tr = sk + 2 * SEEDBYTES;

    /* mu = H(tr || m) — pure internal per FIPS 204 */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, tr, TRBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    return sign_core_with_mu_rnd(sig, siglen, mu, rnd, sk);
}

static int sign_core_with_mu_rnd(uint8_t *sig,
                                  size_t *siglen,
                                  const uint8_t mu_in[CRHBYTES],
                                  const uint8_t rnd_in[RNDBYTES],
                                  const uint8_t *sk) {

    polyveck w;
    poly cp, tmp, y_elem, w1_elem;
    uint8_t mu[CRHBYTES];
    uint8_t rhoprime[CRHBYTES];
    uint8_t w1_bytes[POLYW1_PACKEDBYTES];
    shake256incctx state;
    uint16_t nonce_base = 0;
    unsigned int k_idx, l_idx, j;

    const uint8_t *rho = sk;
    const uint8_t *key = sk + SEEDBYTES;

    for (j = 0; j < CRHBYTES; j++)
        mu[j] = mu_in[j];

    /* rhoprime = H(key || rnd || mu) — FIPS 204: rho'' = H(K || rnd || mu, 64) */
#ifdef MLDSA_MASK_RHOPRIME
    /* Step 1: Boolean-masked Keccak; K held in two shares throughout. */
    masked_compute_rhoprime(rhoprime, key, rnd_in, mu);
#else
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, key, SEEDBYTES);
    shake256_inc_absorb(&state, rnd_in, RNDBYTES);
    shake256_inc_absorb(&state, mu, CRHBYTES);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(rhoprime, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);
#endif

rej:
    /* ---- Phase 1: w = A*y row-by-row; hash w1 incrementally ---- */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);

    for (k_idx = 0; k_idx < K; k_idx++) {
        /* w[k] = A[k][0] * NTT(y[0]) */
        MLDSA_NAMESPACE(poly_uniform)(
            &w.vec[k_idx], rho, (uint16_t)((k_idx << 8) + 0));
        SAMPLE_Y(&y_elem, rhoprime,
                 (uint16_t)((unsigned int)L * nonce_base + 0));
        MLDSA_NAMESPACE(poly_ntt)(&y_elem);
        MLDSA_NAMESPACE(poly_pointwise_montgomery)(
            &w.vec[k_idx], &w.vec[k_idx], &y_elem);

        for (l_idx = 1; l_idx < L; l_idx++) {
            MLDSA_NAMESPACE(poly_uniform)(
                &tmp, rho, (uint16_t)((k_idx << 8) + l_idx));
            SAMPLE_Y(&y_elem, rhoprime,
                     (uint16_t)((unsigned int)L * nonce_base + l_idx));
            MLDSA_NAMESPACE(poly_ntt)(&y_elem);
            MLDSA_NAMESPACE(poly_pointwise_montgomery)(&tmp, &tmp, &y_elem);
            MLDSA_NAMESPACE(poly_add)(&w.vec[k_idx], &w.vec[k_idx], &tmp);
        }

        MLDSA_NAMESPACE(poly_reduce)(&w.vec[k_idx]);
        MLDSA_NAMESPACE(poly_invntt_tomont)(&w.vec[k_idx]);
        MLDSA_NAMESPACE(poly_caddq)(&w.vec[k_idx]);

        /* Decompose to get w1 for hashing; w.vec[k_idx] untouched (holds W) */
        MLDSA_NAMESPACE(poly_decompose)(&tmp, &y_elem, &w.vec[k_idx]);
        MLDSA_NAMESPACE(polyw1_pack)(w1_bytes, &tmp);
        shake256_inc_absorb(&state, w1_bytes, POLYW1_PACKEDBYTES);
    }

    shake256_inc_finalize(&state);
    shake256_inc_squeeze(sig, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);

    MLDSA_NAMESPACE(poly_challenge)(&cp, sig);
    MLDSA_NAMESPACE(poly_ntt)(&cp);

    /* ---- Phase 2a: z[l] = cs1[l] + y[l]; norm check; pack to sig ---- */
#ifdef MLDSA_MASK_CS1
    /* Step 2: s1 held in arithmetic shares across unpack->NTT->pmul->INVNTT.
     * No extra scratch poly: y_elem doubles as the second arithmetic share
     * during the chain, then is overwritten with the actual y_l sample. */
    for (l_idx = 0; l_idx < L; l_idx++) {
        masked_cs1_compute_z_l(
            &tmp, &y_elem, &cp,
            sk + SK_OFF_S1(l_idx),
            rhoprime,
            (uint16_t)((unsigned int)L * nonce_base + l_idx));
        MLDSA_NAMESPACE(poly_reduce)(&tmp);
        if (CHKNORM(&tmp, GAMMA1 - BETA)) {
            nonce_base++;
            goto rej;
        }
        MLDSA_NAMESPACE(polyz_pack)(sig + SIG_OFF_Z(l_idx), &tmp);
    }
#else
    for (l_idx = 0; l_idx < L; l_idx++) {
        POLYETA_UNPACK(&tmp, sk + SK_OFF_S1(l_idx));
        MLDSA_NAMESPACE(poly_ntt)(&tmp);
        MLDSA_NAMESPACE(poly_pointwise_montgomery)(&tmp, &cp, &tmp);
        MLDSA_NAMESPACE(poly_invntt_tomont)(&tmp);

        SAMPLE_Y(&y_elem, rhoprime,
                 (uint16_t)((unsigned int)L * nonce_base + l_idx));

        MLDSA_NAMESPACE(poly_add)(&tmp, &tmp, &y_elem);
        MLDSA_NAMESPACE(poly_reduce)(&tmp);
        if (CHKNORM(&tmp, GAMMA1 - BETA)) {
            nonce_base++;
            goto rej;
        }
        MLDSA_NAMESPACE(polyz_pack)(sig + SIG_OFF_Z(l_idx), &tmp);
    }
#endif

    /* ---- Phase 2b: hints; w decomposed in-place to w0 ---- */
    {
        uint8_t *const sig_h = sig + SIG_OFF_H;
        unsigned int hint_n = 0;
        unsigned int hints_written = 0;
        /* Step 3 reuses y_elem (unused in Phase 2b) as the share scratch,
         * so no extra 1024 B poly is allocated here. */

        for (j = 0; j < OMEGA + K; j++)
            sig_h[j] = 0;

        for (k_idx = 0; k_idx < K; k_idx++) {
            /* Decompose w[k] in-place: w.vec[k_idx] = w0[k], w1_elem = w1[k]
             * (safe: decompose reads a[i] by value before writing a0[i]) */
            MLDSA_NAMESPACE(poly_decompose)(
                &w1_elem, &w.vec[k_idx], &w.vec[k_idx]);

            /* cs2[k] = INVNTT(cp * NTT(s2[k])); w0[k] -= cs2[k] */
            POLYETA_UNPACK(&tmp, sk + SK_OFF_S2(k_idx));
#ifdef MLDSA_MASK_CS2_CT0
            masked_cp_times_s(&tmp, &y_elem, &cp);
#else
            MLDSA_NAMESPACE(poly_ntt)(&tmp);
            MLDSA_NAMESPACE(poly_pointwise_montgomery)(&tmp, &cp, &tmp);
            MLDSA_NAMESPACE(poly_invntt_tomont)(&tmp);
#endif
            MLDSA_NAMESPACE(poly_sub)(&w.vec[k_idx], &w.vec[k_idx], &tmp);
            MLDSA_NAMESPACE(poly_reduce)(&w.vec[k_idx]);
            if (CHKNORM(&w.vec[k_idx], GAMMA2 - BETA)) {
                nonce_base++;
                goto rej;
            }

            /* ct0[k] = INVNTT(cp * NTT(t0[k])); norm check; w0[k] += ct0[k] */
            POLYT0_UNPACK(&tmp, sk + SK_OFF_T0(k_idx));
#ifdef MLDSA_MASK_CS2_CT0
            masked_cp_times_s(&tmp, &y_elem, &cp);
#else
            MLDSA_NAMESPACE(poly_ntt)(&tmp);
            MLDSA_NAMESPACE(poly_pointwise_montgomery)(&tmp, &cp, &tmp);
            MLDSA_NAMESPACE(poly_invntt_tomont)(&tmp);
#endif
            MLDSA_NAMESPACE(poly_reduce)(&tmp);
            if (CHKNORM(&tmp, GAMMA2)) {
                nonce_base++;
                goto rej;
            }

            MLDSA_NAMESPACE(poly_add)(&w.vec[k_idx], &w.vec[k_idx], &tmp);
            /* NOTE: do NOT caddq here; make_hint expects centred values in
             * [-(GAMMA2), GAMMA2].  caddq would map negatives to ~Q which
             * falsely triggers hint=1 for all of them. */

            /* h[k] = make_hint(w0+ct0, w1); tmp reused for hint poly */
            hint_n += MAKE_HINT(&tmp, &w.vec[k_idx], &w1_elem);
            if (hint_n > OMEGA) {
                nonce_base++;
                goto rej;
            }

            for (j = 0; j < N; j++) {
                if (tmp.coeffs[j] != 0)
                    sig_h[hints_written++] = (uint8_t)j;
            }
            sig_h[OMEGA + k_idx] = (uint8_t)hints_written;
        }
    }

    *siglen = CRYPTO_BYTES;
    return 0;
}

#ifndef MLDSA_NO_RANDOMBYTES
int MLDSA_NAMESPACE(crypto_sign_ctx)(uint8_t *sm,
        size_t *smlen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *sk) {
    int ret;
    size_t i;

    for (i = 0; i < mlen; ++i)
        sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];
    ret = MLDSA_NAMESPACE(crypto_sign_signature_ctx)(
            sm, smlen,
            sm + CRYPTO_BYTES, mlen,
            ctx, ctxlen, sk);
    *smlen += mlen;
    return ret;
}
#endif /* !MLDSA_NO_RANDOMBYTES */

/* ------------------------------------------------------------------ */
/* Verify (Strategy-3 streaming)                                        */
/*                                                                      */
/* Stack budget:                                                        */
/*   z        : polyvecl = 5,120 B  NTT domain, reused per k-row      */
/*   cp, chat : poly     = 2,048 B                                     */
/*   w1_elem  : poly     = 1,024 B                                     */
/*   tmp_elem : poly     = 1,024 B  A[k][l], t1[k], scratch           */
/*   mu/c2/w1_bytes/state : ~512 B                                     */
/*   Total                : ~10.5 KB                                   */
/* ------------------------------------------------------------------ */
/* Core verify: mu is pre-computed externally (external or internal form). */
static int verify_core_with_mu(const uint8_t *sig,
                                const uint8_t mu[CRHBYTES],
                                const uint8_t *pk) {

    polyvecl z;
    poly cp, chat, w1_elem, tmp_elem;
    uint8_t c2[CTILDEBYTES];
    uint8_t w1_bytes[POLYW1_PACKEDBYTES];
    shake256incctx state;
    unsigned int k_idx, l_idx, j;

    const uint8_t *rho   = pk;
    const uint8_t *sig_h = sig + SIG_OFF_H;

    /* Unpack and validate c-tilde + z */
    MLDSA_NAMESPACE(poly_challenge)(&cp, sig);

    for (l_idx = 0; l_idx < L; l_idx++)
        MLDSA_NAMESPACE(polyz_unpack)(&z.vec[l_idx], sig + SIG_OFF_Z(l_idx));
    if (MLDSA_NAMESPACE(polyvecl_chknorm)(&z, GAMMA1 - BETA))
        return -1;

    /* Validate hint encoding */
    {
        unsigned int k = 0;
        for (k_idx = 0; k_idx < K; k_idx++) {
            if (sig_h[OMEGA + k_idx] < k || sig_h[OMEGA + k_idx] > OMEGA)
                return -1;
            for (j = k; j < (unsigned int)sig_h[OMEGA + k_idx]; j++) {
                if (j > k && sig_h[j] <= sig_h[j - 1])
                    return -1;
            }
            k = sig_h[OMEGA + k_idx];
        }
        for (j = k; j < OMEGA; j++) {
            if (sig_h[j])
                return -1;
        }
    }

    /* NTT(z) once; reused across all k rows */
    for (l_idx = 0; l_idx < L; l_idx++)
        MLDSA_NAMESPACE(poly_ntt)(&z.vec[l_idx]);

    chat = cp;
    MLDSA_NAMESPACE(poly_ntt)(&chat);

    /* Recompute c-tilde = H(mu || w1') row by row */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);

    for (k_idx = 0; k_idx < K; k_idx++) {
        unsigned int k_start, k_end;

        /* w1_elem = A[k]*z (streaming over l) */
        MLDSA_NAMESPACE(poly_uniform)(
            &tmp_elem, rho, (uint16_t)((k_idx << 8) + 0));
        MLDSA_NAMESPACE(poly_pointwise_montgomery)(
            &w1_elem, &tmp_elem, &z.vec[0]);

        for (l_idx = 1; l_idx < L; l_idx++) {
            MLDSA_NAMESPACE(poly_uniform)(
                &tmp_elem, rho, (uint16_t)((k_idx << 8) + l_idx));
            MLDSA_NAMESPACE(poly_pointwise_montgomery)(
                &tmp_elem, &tmp_elem, &z.vec[l_idx]);
            MLDSA_NAMESPACE(poly_add)(&w1_elem, &w1_elem, &tmp_elem);
        }

        /* Subtract chat * t1[k] * 2^d (t1[k] unpacked from pk on the fly) */
        MLDSA_NAMESPACE(polyt1_unpack)(
            &tmp_elem, pk + SEEDBYTES + k_idx * POLYT1_PACKEDBYTES);
        MLDSA_NAMESPACE(poly_shiftl)(&tmp_elem);
        MLDSA_NAMESPACE(poly_ntt)(&tmp_elem);
        MLDSA_NAMESPACE(poly_pointwise_montgomery)(&tmp_elem, &chat, &tmp_elem);

        MLDSA_NAMESPACE(poly_sub)(&w1_elem, &w1_elem, &tmp_elem);
        MLDSA_NAMESPACE(poly_reduce)(&w1_elem);
        MLDSA_NAMESPACE(poly_invntt_tomont)(&w1_elem);
        MLDSA_NAMESPACE(poly_caddq)(&w1_elem);

        /* Apply hints for row k_idx using tmp_elem as hint poly */
        k_start = (k_idx == 0) ? 0u : (unsigned int)sig_h[OMEGA + k_idx - 1];
        k_end   = (unsigned int)sig_h[OMEGA + k_idx];

        for (j = 0; j < N; j++)
            tmp_elem.coeffs[j] = 0;
        for (j = k_start; j < k_end; j++)
            tmp_elem.coeffs[(unsigned int)sig_h[j]] = 1;

        MLDSA_NAMESPACE(poly_use_hint)(&w1_elem, &w1_elem, &tmp_elem);
        MLDSA_NAMESPACE(polyw1_pack)(w1_bytes, &w1_elem);
        shake256_inc_absorb(&state, w1_bytes, POLYW1_PACKEDBYTES);
    }

    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, CTILDEBYTES, &state);
    shake256_inc_ctx_release(&state);

    for (j = 0; j < CTILDEBYTES; j++) {
        if (sig[j] != c2[j])
            return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* ML-DSA.Verify (external, Algorithm 3): mu = H(H(pk) || 0x00 || ctxlen || ctx || m)  */
/* ------------------------------------------------------------------ */
int MLDSA_NAMESPACE(crypto_sign_verify_ctx)(const uint8_t *sig,
        size_t siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *pk) {

    uint8_t mu[CRHBYTES];
    shake256incctx state;

    if (ctxlen > 255 || siglen != CRYPTO_BYTES)
        return -1;

    /* mu = H(H(pk) || 0x00 || ctxlen || ctx || m) */
    shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, TRBYTES);
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    return verify_core_with_mu(sig, mu, pk);
}

/* ------------------------------------------------------------------ */
/* ML-DSA.Verify_internal (Algorithm 8): mu = H(H(pk) || m)           */
/* ------------------------------------------------------------------ */
int MLDSA_NAMESPACE(crypto_sign_verify_internal)(const uint8_t *sig,
        size_t siglen,
        const uint8_t *m,
        size_t mlen,
        const uint8_t *pk) {

    uint8_t mu[CRHBYTES];
    shake256incctx state;

    if (siglen != CRYPTO_BYTES)
        return -1;

    /* mu = H(H(pk) || m) — internal per FIPS 204 */
    shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, TRBYTES);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);
    shake256_inc_ctx_release(&state);

    return verify_core_with_mu(sig, mu, pk);
}

int MLDSA_NAMESPACE(crypto_sign_open_ctx)(uint8_t *m,
        size_t *mlen,
        const uint8_t *sm,
        size_t smlen,
        const uint8_t *ctx,
        size_t ctxlen,
        const uint8_t *pk) {
    size_t i;

    if (smlen < CRYPTO_BYTES)
        goto badsig;

    *mlen = smlen - CRYPTO_BYTES;
    if (MLDSA_NAMESPACE(crypto_sign_verify_ctx)(
                sm, CRYPTO_BYTES,
                sm + CRYPTO_BYTES, *mlen,
                ctx, ctxlen, pk))
        goto badsig;

    for (i = 0; i < *mlen; ++i)
        m[i] = sm[CRYPTO_BYTES + i];
    return 0;

badsig:
    *mlen = 0;
    for (i = 0; i < smlen; ++i)
        m[i] = 0;
    return -1;
}
