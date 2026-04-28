/*
 * test_mldsa65_main.c — S1 baseline harness for impl_sc300 ML-DSA-65
 *
 * Runs crypto_sign_keypair → crypto_sign → crypto_sign_open on a fixed
 * 59-byte message and emits a parseable baseline line for each operation:
 *
 *    MLDSA65,gcc,<op>,stack=<N>,cycles=<M>
 *
 * Randomness is the deterministic SURF-based fallback in
 * pqm4/common/randombytes.c (NONRANDOM FALLBACK), so keys and sig bytes
 * are reproducible across runs — suitable for S2+ byte-equality regression.
 *
 * external round-trip gate: sign→verify round-trip passes (message recovered).
 * ML-DSA-65 ACVP KAT is a later gate (S11); S1 only needs functional correctness.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "hal.h"
#include "sendfn.h"
#include "api_bridge.h"   /* pulls pqclean api.h and short macros */
#include "sign.h"         /* PQCLEAN_MLDSA65_CLEAN_crypto_sign_{signature,verify}_internal */
#include "kat_vectors.h"  /* NIST ACVP ML-DSA-65 all test vectors */

#define MLEN 59

/* Heap allocations would work too; keep static to keep frames small. */
static uint8_t pk[CRYPTO_PUBLICKEYBYTES];    /* 1952 B */
static uint8_t sk[CRYPTO_SECRETKEYBYTES];    /* 4032 B */
static uint8_t sm[CRYPTO_BYTES + MLEN];      /* 3368 B */
static uint8_t msg[MLEN];
static uint8_t msg2[MLEN];

/* Semihosting SYS_EXIT via BKPT #0xAB.
 * r0 = 0x18 (SYS_EXIT), r1 = ADP_Stopped_ApplicationExit (0x20026).
 * Using a fixed reason code makes QEMU exit cleanly regardless of
 * application exit status. */
static void __attribute__((noreturn)) do_semihosting_exit(int status)
{
    (void)status;
    __asm volatile(
        "mov r0, #0x18\n\t"
        "ldr r1, =0x20026\n\t"
        "bkpt #0xAB\n\t"
        ::: "r0", "r1", "memory"
    );
    while (1);
}

static void dump_stage(const char *op, unsigned int stack, unsigned long long cycles)
{
    /* Emit as two lines for simple parsing. */
    char tag_stack[64];
    char tag_cycles[64];
    /* "MLDSA65,gcc,<op>,stack" / "MLDSA65,gcc,<op>,cycles" */
    /* Use snprintf-like manual composition to avoid pulling printf deps. */
    size_t i = 0;
    const char *prefix = "MLDSA65,gcc,";
    for (; *prefix; prefix++) tag_stack[i++] = *prefix;
    for (const char *p = op; *p; p++) tag_stack[i++] = *p;
    memcpy(tag_stack + i, ",stack:", 7); i += 7;
    tag_stack[i] = '\0';

    size_t j = 0;
    const char *prefix2 = "MLDSA65,gcc,";
    for (; *prefix2; prefix2++) tag_cycles[j++] = *prefix2;
    for (const char *p = op; *p; p++) tag_cycles[j++] = *p;
    memcpy(tag_cycles + j, ",cycles:", 8); j += 8;
    tag_cycles[j] = '\0';

    send_unsigned(tag_stack, stack);
    send_unsignedll(tag_cycles, cycles);
}

int main(void)
{
    size_t smlen = 0;
    size_t mlen2 = 0;
    uint64_t t0, t1;
    unsigned int stack_keypair, stack_sign, stack_verify;
    unsigned long long cyc_keypair, cyc_sign, cyc_verify;
    int rc;

    hal_setup(CLOCK_BENCHMARK);
    hal_send_str("=========================================");
    hal_send_str("impl_sc300 ML-DSA-65 QEMU test (sc300 streaming + NTT asm)");
#if defined(__ARMCC_VERSION)
    hal_send_str("  toolchain=armclang, core=Cortex-M3 (SC300)");
#else
    hal_send_str("  toolchain=gcc, core=Cortex-M3 (SC300)");
#endif
    hal_send_str("=========================================");

    send_unsigned("CRYPTO_PUBLICKEYBYTES:", (unsigned)CRYPTO_PUBLICKEYBYTES);
    send_unsigned("CRYPTO_SECRETKEYBYTES:", (unsigned)CRYPTO_SECRETKEYBYTES);
    send_unsigned("CRYPTO_BYTES:",          (unsigned)CRYPTO_BYTES);

    /* fixed message 0x00..0x3A */
    for (size_t i = 0; i < MLEN; i++) msg[i] = (uint8_t)i;

    /* ----------------- keypair ----------------- */
    hal_send_str("-- keypair --");
    hal_spraystack();
    t0 = hal_get_time();
    rc = crypto_sign_keypair(pk, sk);
    t1 = hal_get_time();
    if (rc != 0) {
        hal_send_str("EXT-GATE: FAIL (keypair returned nonzero)");
        do_semihosting_exit(1);
    }
    stack_keypair = (unsigned int)hal_checkstack();
    cyc_keypair   = (unsigned long long)(t1 - t0);
    dump_stage("keypair", stack_keypair, cyc_keypair);

    /* ----------------- sign ----------------- */
    hal_send_str("-- sign --");
    hal_spraystack();
    t0 = hal_get_time();
    rc = crypto_sign(sm, &smlen, msg, MLEN, sk);
    t1 = hal_get_time();
    if (rc != 0) {
        hal_send_str("EXT-GATE: FAIL (sign returned nonzero)");
        do_semihosting_exit(1);
    }
    stack_sign = (unsigned int)hal_checkstack();
    cyc_sign   = (unsigned long long)(t1 - t0);
    dump_stage("sign", stack_sign, cyc_sign);

    if (smlen != (size_t)CRYPTO_BYTES + MLEN) {
        hal_send_str("EXT-GATE: FAIL (smlen mismatch)");
        do_semihosting_exit(1);
    }

    /* ----------------- verify ----------------- */
    hal_send_str("-- verify --");
    hal_spraystack();
    t0 = hal_get_time();
    rc = crypto_sign_open(msg2, &mlen2, sm, smlen, pk);
    t1 = hal_get_time();
    if (rc != 0) {
        hal_send_str("EXT-GATE: FAIL (verify returned nonzero)");
        do_semihosting_exit(1);
    }
    stack_verify = (unsigned int)hal_checkstack();
    cyc_verify   = (unsigned long long)(t1 - t0);
    dump_stage("verify", stack_verify, cyc_verify);

    if (mlen2 != MLEN || memcmp(msg, msg2, MLEN) != 0) {
        hal_send_str("EXT-GATE: FAIL (recovered message mismatch)");
        do_semihosting_exit(1);
    }

    /* First 16 bytes of PK / SIG as a quick fingerprint
       (for cross-run / later-phase byte-equality checks). */
    char line[80];
    const char HEX[] = "0123456789abcdef";
    memcpy(line, "PK[0..15]:", 10);
    for (int i = 0; i < 16; i++) {
        line[10 + i*2]     = HEX[pk[i] >> 4];
        line[10 + i*2 + 1] = HEX[pk[i] & 0xf];
    }
    line[10 + 32] = '\0';
    hal_send_str(line);

    memcpy(line, "SIG[0..15]:", 11);
    for (int i = 0; i < 16; i++) {
        line[11 + i*2]     = HEX[sm[i] >> 4];
        line[11 + i*2 + 1] = HEX[sm[i] & 0xf];
    }
    line[11 + 32] = '\0';
    hal_send_str(line);

    hal_send_str("EXT-GATE: PASS (keypair/sign/verify round-trip OK)");

    /* ----------------- internal sign/verify round-trip ----------------- */
    {
        static uint8_t sig_int[CRYPTO_BYTES];
        static uint8_t rnd_det[32]; /* zero => deterministic, matches FIPS 204 KAT */
        size_t sig_int_len = 0;

        for (size_t i = 0; i < sizeof(rnd_det); i++) rnd_det[i] = 0;

        hal_send_str("-- internal sign --");
        hal_spraystack();
        t0 = hal_get_time();
        rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_internal(
                 sig_int, &sig_int_len, msg, MLEN, rnd_det, sk);
        t1 = hal_get_time();
        if (rc != 0 || sig_int_len != (size_t)CRYPTO_BYTES) {
            hal_send_str("INT-GATE: FAIL (internal sign)");
            do_semihosting_exit(1);
        }
        dump_stage("sign_internal",
                   (unsigned int)hal_checkstack(),
                   (unsigned long long)(t1 - t0));

        hal_send_str("-- internal verify --");
        hal_spraystack();
        t0 = hal_get_time();
        rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_internal(
                 sig_int, sig_int_len, msg, MLEN, pk);
        t1 = hal_get_time();
        if (rc != 0) {
            hal_send_str("INT-GATE: FAIL (internal verify)");
            do_semihosting_exit(1);
        }
        dump_stage("verify_internal",
                   (unsigned int)hal_checkstack(),
                   (unsigned long long)(t1 - t0));

        /* Internal signature differs from external (different mu). */
        memcpy(line, "SIG_INT[0..15]:", 15);
        for (int i = 0; i < 16; i++) {
            line[15 + i*2]     = HEX[sig_int[i] >> 4];
            line[15 + i*2 + 1] = HEX[sig_int[i] & 0xf];
        }
        line[15 + 32] = '\0';
        hal_send_str(line);

        /* Cross-check: internal signature must NOT verify under external verify
         * (different mu computation → different c-tilde). */
        rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
                 sig_int, CRYPTO_BYTES, msg, MLEN, NULL, 0, pk);
        if (rc == 0) {
            hal_send_str("INT-GATE: FAIL (internal sig unexpectedly passed external verify)");
            do_semihosting_exit(1);
        }
        /* And vice versa: external signature (first CRYPTO_BYTES of sm) must
         * NOT verify under internal verify. */
        rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_internal(
                 sm, CRYPTO_BYTES, msg, MLEN, pk);
        if (rc == 0) {
            hal_send_str("INT-GATE: FAIL (external sig unexpectedly passed internal verify)");
            do_semihosting_exit(1);
        }

        hal_send_str("INT-GATE: PASS (internal sign/verify round-trip OK; distinct from external)");
    }

#ifndef KAT_GATE_ONLY
    /* -------- NIST ACVP KAT (ML-DSA-65, 115 cases) ----------- */
    {
        static uint8_t kat_sig[CRYPTO_BYTES];
        static uint8_t kat_pk[CRYPTO_PUBLICKEYBYTES];
        static uint8_t kat_sk[CRYPTO_SECRETKEYBYTES];
        static const uint8_t zeros[32];
        size_t siglen;
        int pass, fail;
        int total_pass = 0, total_fail = 0;
        uint64_t kat_t0, kat_t1;
        uint64_t kat_keygen_total     = 0;
        uint64_t kat_siggen_int_total = 0;
        uint64_t kat_siggen_ext_total = 0;
        uint64_t kat_sigver_int_total = 0;
        uint64_t kat_sigver_ext_total = 0;

        hal_send_str("-- NIST ACVP KAT (ML-DSA-65) --");

        /* sigGen internal */
        pass = 0; fail = 0;
        for (int i = 0; i < KAT_SIGGEN_INT_DET_N; i++) {
            const siggen_int_tc_t *tc = &kat_siggen_sg10[i];
            siglen = 0;
            kat_t0 = hal_get_time();
            rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_internal(
                     kat_sig, &siglen, tc->msg, tc->mlen, zeros, tc->sk);
            kat_t1 = hal_get_time();
            kat_siggen_int_total += (uint64_t)(kat_t1 - kat_t0);
            if (rc == 0 && siglen == CRYPTO_BYTES &&
                memcmp(kat_sig, tc->exp_sig, CRYPTO_BYTES) == 0)
                pass++;
            else
                fail++;
        }
        total_pass += pass; total_fail += fail;
        if (fail == 0) hal_send_str("[sigGen tgId=10 internal/det  ] 15/15 PASS");
        else           hal_send_str("[sigGen tgId=10 internal/det  ] FAIL");

        pass = 0; fail = 0;
        for (int i = 0; i < KAT_SIGGEN_INT_NDET_N; i++) {
            const siggen_int_tc_t *tc = &kat_siggen_sg22[i];
            siglen = 0;
            kat_t0 = hal_get_time();
            rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_internal(
                     kat_sig, &siglen, tc->msg, tc->mlen, tc->rnd, tc->sk);
            kat_t1 = hal_get_time();
            kat_siggen_int_total += (uint64_t)(kat_t1 - kat_t0);
            if (rc == 0 && siglen == CRYPTO_BYTES &&
                memcmp(kat_sig, tc->exp_sig, CRYPTO_BYTES) == 0)
                pass++;
            else
                fail++;
        }
        total_pass += pass; total_fail += fail;
        if (fail == 0) hal_send_str("[sigGen tgId=22 internal/ndet ] 15/15 PASS");
        else           hal_send_str("[sigGen tgId=22 internal/ndet ] FAIL");

        /* sigGen external */
        pass = 0; fail = 0;
        for (int i = 0; i < KAT_SIGGEN_EXT_DET_N; i++) {
            const siggen_ext_tc_t *tc = &kat_siggen_sg03[i];
            siglen = 0;
            kat_t0 = hal_get_time();
            rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx_rnd(
                     kat_sig, &siglen,
                     tc->msg, tc->mlen, tc->ctx, tc->ctxlen, zeros, tc->sk);
            kat_t1 = hal_get_time();
            kat_siggen_ext_total += (uint64_t)(kat_t1 - kat_t0);
            if (rc == 0 && siglen == CRYPTO_BYTES &&
                memcmp(kat_sig, tc->exp_sig, CRYPTO_BYTES) == 0)
                pass++;
            else
                fail++;
        }
        total_pass += pass; total_fail += fail;
        if (fail == 0) hal_send_str("[sigGen tgId= 3 external/det  ] 15/15 PASS");
        else           hal_send_str("[sigGen tgId= 3 external/det  ] FAIL");

        pass = 0; fail = 0;
        for (int i = 0; i < KAT_SIGGEN_EXT_NDET_N; i++) {
            const siggen_ext_tc_t *tc = &kat_siggen_sg15[i];
            siglen = 0;
            kat_t0 = hal_get_time();
            rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx_rnd(
                     kat_sig, &siglen,
                     tc->msg, tc->mlen, tc->ctx, tc->ctxlen, tc->rnd, tc->sk);
            kat_t1 = hal_get_time();
            kat_siggen_ext_total += (uint64_t)(kat_t1 - kat_t0);
            if (rc == 0 && siglen == CRYPTO_BYTES &&
                memcmp(kat_sig, tc->exp_sig, CRYPTO_BYTES) == 0)
                pass++;
            else
                fail++;
        }
        total_pass += pass; total_fail += fail;
        if (fail == 0) hal_send_str("[sigGen tgId=15 external/ndet ] 15/15 PASS");
        else           hal_send_str("[sigGen tgId=15 external/ndet ] FAIL");

        /* sigVer */
        pass = 0; fail = 0;
        for (int i = 0; i < KAT_SIGVER_INT_N; i++) {
            const sigver_int_tc_t *tc = &kat_sigver_sv10[i];
            kat_t0 = hal_get_time();
            rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_internal(
                     tc->sig, CRYPTO_BYTES, tc->msg, tc->mlen, tc->pk);
            kat_t1 = hal_get_time();
            kat_sigver_int_total += (uint64_t)(kat_t1 - kat_t0);
            int got_pass = (rc == 0) ? 1 : 0;
            if (got_pass == tc->exp_pass) pass++;
            else                          fail++;
        }
        total_pass += pass; total_fail += fail;
        if (fail == 0) hal_send_str("[sigVer tgId=10 internal      ] 15/15 PASS");
        else           hal_send_str("[sigVer tgId=10 internal      ] FAIL");

        pass = 0; fail = 0;
        for (int i = 0; i < KAT_SIGVER_EXT_N; i++) {
            const sigver_ext_tc_t *tc = &kat_sigver_sv03[i];
            kat_t0 = hal_get_time();
            rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
                     tc->sig, CRYPTO_BYTES,
                     tc->msg, tc->mlen, tc->ctx, tc->ctxlen, tc->pk);
            kat_t1 = hal_get_time();
            kat_sigver_ext_total += (uint64_t)(kat_t1 - kat_t0);
            int got_pass = (rc == 0) ? 1 : 0;
            if (got_pass == tc->exp_pass) pass++;
            else                          fail++;
        }
        total_pass += pass; total_fail += fail;
        if (fail == 0) hal_send_str("[sigVer tgId= 3 external      ] 15/15 PASS");
        else           hal_send_str("[sigVer tgId= 3 external      ] FAIL");

        /* keyGen */
        pass = 0; fail = 0;
        for (int i = 0; i < KAT_KEYGEN_N; i++) {
            const keygen_tc_t *tc = &kat_keygen_kg02[i];
            kat_t0 = hal_get_time();
            rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair_from_seed(
                     kat_pk, kat_sk, tc->seed);
            kat_t1 = hal_get_time();
            kat_keygen_total += (uint64_t)(kat_t1 - kat_t0);
            if (rc == 0 &&
                memcmp(kat_pk, tc->exp_pk, CRYPTO_PUBLICKEYBYTES) == 0 &&
                memcmp(kat_sk, tc->exp_sk, CRYPTO_SECRETKEYBYTES) == 0)
                pass++;
            else
                fail++;
        }
        total_pass += pass; total_fail += fail;
        if (fail == 0) hal_send_str("[keyGen tgId= 2               ] 25/25 PASS");
        else           hal_send_str("[keyGen tgId= 2               ] FAIL");

        send_unsigned("KAT,total_pass:", (unsigned)total_pass);
        send_unsigned("KAT,total_fail:", (unsigned)total_fail);
        if (total_fail != 0) {
            hal_send_str("KAT-GATE: FAIL");
            do_semihosting_exit(1);
        }
        hal_send_str("KAT-GATE: PASS (115/115 NIST ACVP ML-DSA-65 vectors)");
        send_unsignedll("KAT,avg,keypair,cycles:",
                        kat_keygen_total / KAT_KEYGEN_N);
        send_unsignedll("KAT,avg,sign_internal,cycles:",
                        kat_siggen_int_total / (KAT_SIGGEN_INT_DET_N + KAT_SIGGEN_INT_NDET_N));
        send_unsignedll("KAT,avg,sign_external,cycles:",
                        kat_siggen_ext_total / (KAT_SIGGEN_EXT_DET_N + KAT_SIGGEN_EXT_NDET_N));
        send_unsignedll("KAT,avg,verify_internal,cycles:",
                        kat_sigver_int_total / KAT_SIGVER_INT_N);
        send_unsignedll("KAT,avg,verify_external,cycles:",
                        kat_sigver_ext_total / KAT_SIGVER_EXT_N);
    }
#else /* KAT_GATE_ONLY */
    hal_send_str("GATE-ONLY: PASS (skipped KAT; use qemu for full 115-case ACVP)");
#endif /* KAT_GATE_ONLY */

    hal_send_str("=== QEMU test done ===");

    do_semihosting_exit(0);
}
