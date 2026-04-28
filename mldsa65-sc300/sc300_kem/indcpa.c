/* sc300_kem/indcpa.c — ML-KEM-768 indcpa, streaming A-matrix variant.
 *
 * Replaces ref_kem/indcpa.c.  Key change: generate the A / A^T matrix one
 * row at a time instead of holding the full k×k matrix (4,608 B) on the
 * stack at once.  indcpa_enc also compresses each b[i] row directly into the
 * ciphertext buffer, eliminating polyvec b (another 1,536 B).
 *
 * Stack savings vs reference:
 *   indcpa_keypair_derand : a[KYBER_K] → a_row           −3,072 B
 *   indcpa_enc            : at[KYBER_K] → at_row         −3,072 B
 *                           polyvec b eliminated          −1,536 B
 *                           polyvec pkpv → poly scratch     −512 B (net)
 *   indcpa_dec            : unchanged
 */
#include "indcpa.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "symmetric.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Pack / unpack helpers (identical to ref_kem/indcpa.c)              */
/* ------------------------------------------------------------------ */

static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES]) {
    PQCLEAN_MLKEM768_CLEAN_polyvec_tobytes(r, pk);
    memcpy(r + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk) {
    PQCLEAN_MLKEM768_CLEAN_polyvec_tobytes(r, sk);
}

static void unpack_sk(polyvec *sk,
                      const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES]) {
    PQCLEAN_MLKEM768_CLEAN_polyvec_frombytes(sk, packedsk);
}

static void unpack_ciphertext(polyvec *b, poly *v,
                              const uint8_t c[KYBER_INDCPA_BYTES]) {
    PQCLEAN_MLKEM768_CLEAN_polyvec_decompress(b, c);
    PQCLEAN_MLKEM768_CLEAN_poly_decompress(v, c + KYBER_POLYVECCOMPRESSEDBYTES);
}

/* ------------------------------------------------------------------ */
/* Rejection sampler (identical to ref_kem/indcpa.c)                  */
/* ------------------------------------------------------------------ */

static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen) {
    unsigned int ctr, pos;
    uint16_t val0, val1;

    ctr = pos = 0;
    while (ctr < len && pos + 3 <= buflen) {
        val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
        val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
        pos += 3;
        if (val0 < KYBER_Q) { r[ctr++] = val0; }
        if (ctr < len && val1 < KYBER_Q) { r[ctr++] = val1; }
    }
    return ctr;
}

/* ------------------------------------------------------------------ */
/* Streaming row generator                                             */
/* ------------------------------------------------------------------ */

#define GEN_MATRIX_NBLOCKS \
    ((12 * KYBER_N / 8 * (1 << 12) / KYBER_Q + XOF_BLOCKBYTES) / XOF_BLOCKBYTES)

/* Generate one row of A (transposed=0) or A^T (transposed=1).
 * buf and xof_state live only inside this frame — not on the caller's frame. */
static void gen_matrix_row(polyvec *row,
                            const uint8_t seed[KYBER_SYMBYTES],
                            unsigned int row_idx, int transposed) {
    unsigned int ctr, j;
    unsigned int buflen;
    uint8_t buf[GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES];
    xof_state state;

    for (j = 0; j < KYBER_K; j++) {
        if (transposed) {
            xof_absorb(&state, seed, (uint8_t)row_idx, (uint8_t)j);
        } else {
            xof_absorb(&state, seed, (uint8_t)j, (uint8_t)row_idx);
        }
        xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
        buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
        ctr = rej_uniform(row->vec[j].coeffs, KYBER_N, buf, buflen);
        while (ctr < KYBER_N) {
            xof_squeezeblocks(buf, 1, &state);
            buflen = XOF_BLOCKBYTES;
            ctr += rej_uniform(row->vec[j].coeffs + ctr,
                               KYBER_N - ctr, buf, buflen);
        }
        xof_ctx_release(&state);
    }
}

/* Public gen_matrix (declared in indcpa.h): wraps gen_matrix_row for all rows. */
void PQCLEAN_MLKEM768_CLEAN_gen_matrix(polyvec *a,
                                       const uint8_t seed[KYBER_SYMBYTES],
                                       int transposed) {
    unsigned int i;
    for (i = 0; i < KYBER_K; i++) {
        gen_matrix_row(&a[i], seed, i, transposed);
    }
}

/* ------------------------------------------------------------------ */
/* Single-poly du=10 compress for b[i] rows                           */
/* (polyvec_compress iterates outer=poly, inner=coeff, so each        */
/*  polynomial's 320 compressed bytes are contiguous.)                */
/* ------------------------------------------------------------------ */
#define POLY_COMPRESS_DU10_BYTES (KYBER_POLYVECCOMPRESSEDBYTES / KYBER_K)  /* 320 */

static void poly_compress_du10(uint8_t *r, const poly *a) {
    unsigned int j, k;
    uint64_t d0;
    uint16_t t[4];

    for (j = 0; j < KYBER_N / 4; j++) {
        for (k = 0; k < 4; k++) {
            t[k]  = (uint16_t)a->coeffs[4 * j + k];
            t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
            d0  = t[k];
            d0 <<= 10;
            d0 += 1665;
            d0 *= 1290167;
            d0 >>= 32;
            t[k] = (uint16_t)(d0 & 0x3ff);
        }
        r[0] = (uint8_t)(t[0] >> 0);
        r[1] = (uint8_t)((t[0] >> 8) | (t[1] << 2));
        r[2] = (uint8_t)((t[1] >> 6) | (t[2] << 4));
        r[3] = (uint8_t)((t[2] >> 4) | (t[3] << 6));
        r[4] = (uint8_t)(t[3] >> 2);
        r += 5;
    }
}

/* ------------------------------------------------------------------ */
/* indcpa_keypair_derand — stream A one row at a time                 */
/* ------------------------------------------------------------------ */

void PQCLEAN_MLKEM768_CLEAN_indcpa_keypair_derand(
        uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
        const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i;
    uint8_t buf[2 * KYBER_SYMBYTES];
    const uint8_t *publicseed = buf;
    const uint8_t *noiseseed  = buf + KYBER_SYMBYTES;
    uint8_t nonce = 0;
    polyvec a_row, e, pkpv, skpv;  /* a_row replaces a[KYBER_K]: saves 3,072 B */

    memcpy(buf, coins, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = KYBER_K;
    hash_g(buf, buf, KYBER_SYMBYTES + 1);

    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM768_CLEAN_poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
    }
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM768_CLEAN_poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);
    }
    PQCLEAN_MLKEM768_CLEAN_polyvec_ntt(&skpv);
    PQCLEAN_MLKEM768_CLEAN_polyvec_ntt(&e);

    /* A * skpv: generate one row of A at a time, compute product immediately. */
    for (i = 0; i < KYBER_K; i++) {
        gen_matrix_row(&a_row, publicseed, i, 0 /* A, not A^T */);
        PQCLEAN_MLKEM768_CLEAN_polyvec_basemul_acc_montgomery(
                &pkpv.vec[i], &a_row, &skpv);
        PQCLEAN_MLKEM768_CLEAN_poly_tomont(&pkpv.vec[i]);
    }

    PQCLEAN_MLKEM768_CLEAN_polyvec_add(&pkpv, &pkpv, &e);
    PQCLEAN_MLKEM768_CLEAN_polyvec_reduce(&pkpv);

    pack_sk(sk, &skpv);
    pack_pk(pk, &pkpv, publicseed);
}

/* ------------------------------------------------------------------ */
/* indcpa_enc — stream A^T, compress b[i] directly into ciphertext   */
/* ------------------------------------------------------------------ */

void PQCLEAN_MLKEM768_CLEAN_indcpa_enc(
        uint8_t c[KYBER_INDCPA_BYTES],
        const uint8_t m[KYBER_INDCPA_MSGBYTES],
        const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
        const uint8_t coins[KYBER_SYMBYTES]) {
    unsigned int i, j;
    uint8_t seed[KYBER_SYMBYTES];
    uint8_t nonce = 0;
    /* sp  : r in NTT domain; needed for all inner products.
     * at_row : one row of A^T; replaces at[KYBER_K], saves 3,072 B.
     * v      : accumulated dot(pkpv, sp).
     * k      : decoded message polynomial.
     * b_i    : one row of b; also used as scratch for v accumulation.
     * scratch: ep[i]/epp noise; also used for streaming pk[j] loading. */
    polyvec sp, at_row;
    poly v, k, b_i, scratch;

    /* Public seed is the last KYBER_SYMBYTES bytes of packed pk. */
    memcpy(seed, pk + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
    PQCLEAN_MLKEM768_CLEAN_poly_frommsg(&k, m);

    /* Sample r (sp) and NTT it. */
    for (i = 0; i < KYBER_K; i++) {
        PQCLEAN_MLKEM768_CLEAN_poly_getnoise_eta1(&sp.vec[i], coins, nonce++);
    }
    PQCLEAN_MLKEM768_CLEAN_polyvec_ntt(&sp);

    /* v = pkpv . sp — stream pk one polynomial at a time.
     * Equivalent to unpack_pk(&pkpv,...) + polyvec_basemul_acc_montgomery(&v,&pkpv,&sp). */
    PQCLEAN_MLKEM768_CLEAN_poly_frombytes(&scratch, pk + 0 * KYBER_POLYBYTES);
    PQCLEAN_MLKEM768_CLEAN_poly_basemul_montgomery(&v, &scratch, &sp.vec[0]);
    for (j = 1; j < KYBER_K; j++) {
        PQCLEAN_MLKEM768_CLEAN_poly_frombytes(&scratch, pk + j * KYBER_POLYBYTES);
        PQCLEAN_MLKEM768_CLEAN_poly_basemul_montgomery(&b_i, &scratch, &sp.vec[j]);
        PQCLEAN_MLKEM768_CLEAN_poly_add(&v, &v, &b_i);
    }
    PQCLEAN_MLKEM768_CLEAN_poly_reduce(&v);   /* mirrors polyvec_basemul_acc_montgomery */

    /* Stream A^T rows: compute b[i] = A^T[i]·sp, add ep[i], compress to c. */
    for (i = 0; i < KYBER_K; i++) {
        gen_matrix_row(&at_row, seed, i, 1 /* A^T */);
        PQCLEAN_MLKEM768_CLEAN_polyvec_basemul_acc_montgomery(&b_i, &at_row, &sp);
        PQCLEAN_MLKEM768_CLEAN_poly_invntt_tomont(&b_i);
        /* ep[i]: nonces 3, 4, 5 (nonce starts at KYBER_K=3 after sp loop). */
        PQCLEAN_MLKEM768_CLEAN_poly_getnoise_eta2(&scratch, coins, nonce++);
        PQCLEAN_MLKEM768_CLEAN_poly_add(&b_i, &b_i, &scratch);
        PQCLEAN_MLKEM768_CLEAN_poly_reduce(&b_i);
        poly_compress_du10(c + i * POLY_COMPRESS_DU10_BYTES, &b_i);
    }
    /* After loop: nonce == KYBER_K + KYBER_K = 6 */

    /* Finalize v: INTT + epp (nonce=6) + k. */
    PQCLEAN_MLKEM768_CLEAN_poly_invntt_tomont(&v);
    PQCLEAN_MLKEM768_CLEAN_poly_getnoise_eta2(&scratch, coins, nonce); /* epp */
    PQCLEAN_MLKEM768_CLEAN_poly_add(&v, &v, &scratch);
    PQCLEAN_MLKEM768_CLEAN_poly_add(&v, &v, &k);
    PQCLEAN_MLKEM768_CLEAN_poly_reduce(&v);
    PQCLEAN_MLKEM768_CLEAN_poly_compress(c + KYBER_POLYVECCOMPRESSEDBYTES, &v);
}

/* ------------------------------------------------------------------ */
/* indcpa_dec — unchanged from reference                              */
/* ------------------------------------------------------------------ */

void PQCLEAN_MLKEM768_CLEAN_indcpa_dec(
        uint8_t m[KYBER_INDCPA_MSGBYTES],
        const uint8_t c[KYBER_INDCPA_BYTES],
        const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES]) {
    polyvec b, skpv;
    poly v, mp;

    unpack_ciphertext(&b, &v, c);
    unpack_sk(&skpv, sk);

    PQCLEAN_MLKEM768_CLEAN_polyvec_ntt(&b);
    PQCLEAN_MLKEM768_CLEAN_polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
    PQCLEAN_MLKEM768_CLEAN_poly_invntt_tomont(&mp);

    PQCLEAN_MLKEM768_CLEAN_poly_sub(&mp, &v, &mp);
    PQCLEAN_MLKEM768_CLEAN_poly_reduce(&mp);

    PQCLEAN_MLKEM768_CLEAN_poly_tomsg(m, &mp);
}
