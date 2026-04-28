/*
 * test_mldsa44_main.c — QEMU harness for impl_sc300 ML-DSA-44
 *
 * Compile with -DMLDSA_MODE=44; MLDSA_NAMESPACE() expands to
 * PQCLEAN_MLDSA44_CLEAN_* and CRYPTO_* sizes to ML-DSA-44 values.
 *
 * Emits parseable lines:
 *   MLDSA44,gcc,<op>,stack:<N>
 *   MLDSA44,gcc,<op>,cycles:<M>
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "hal.h"
#include "sendfn.h"
#include "api_bridge.h"    /* MLDSA_NAMESPACE-based short aliases, CRYPTO_* sizes */
#include "sign.h"          /* MLDSA_NAMESPACE(crypto_sign_signature_internal) etc. */
#include "kat_vectors44.h" /* NIST ACVP ML-DSA-44 test vectors */

#define MLEN 59

static uint8_t pk[CRYPTO_PUBLICKEYBYTES];   /* 1312 B */
static uint8_t sk[CRYPTO_SECRETKEYBYTES];   /* 2560 B */
static uint8_t sm[CRYPTO_BYTES + MLEN];     /* 2479 B */
static uint8_t msg[MLEN];
static uint8_t msg2[MLEN];

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
    char tag[72];
    const char *pfx = "MLDSA44,gcc,";
    size_t i = 0;
    for (; *pfx; pfx++) tag[i++] = *pfx;
    for (const char *p = op; *p; p++) tag[i++] = *p;
    memcpy(tag + i, ",stack:", 7); tag[i+7] = '\0';
    send_unsigned(tag, stack);

    i = 0; pfx = "MLDSA44,gcc,";
    for (; *pfx; pfx++) tag[i++] = *pfx;
    for (const char *p = op; *p; p++) tag[i++] = *p;
    memcpy(tag + i, ",cycles:", 8); tag[i+8] = '\0';
    send_unsignedll(tag, cycles);
}

int main(void)
{
    size_t smlen = 0, mlen2 = 0;
    uint64_t t0, t1;
    unsigned int stack_kp, stack_sg, stack_vf;
    unsigned long long cyc_kp, cyc_sg, cyc_vf;
    int rc;
    const char HEX[] = "0123456789abcdef";
    char line[80];

    hal_setup(CLOCK_BENCHMARK);
    hal_send_str("=========================================");
    hal_send_str("impl_sc300 ML-DSA-44 QEMU test (sc300 streaming + NTT asm)");
#if defined(__ARMCC_VERSION)
    hal_send_str("  toolchain=armclang, core=Cortex-M3 (SC300)");
#else
    hal_send_str("  toolchain=gcc, core=Cortex-M3 (SC300)");
#endif
    hal_send_str("=========================================");

    send_unsigned("CRYPTO_PUBLICKEYBYTES:", (unsigned)CRYPTO_PUBLICKEYBYTES);
    send_unsigned("CRYPTO_SECRETKEYBYTES:", (unsigned)CRYPTO_SECRETKEYBYTES);
    send_unsigned("CRYPTO_BYTES:",          (unsigned)CRYPTO_BYTES);

    for (size_t i = 0; i < MLEN; i++) msg[i] = (uint8_t)i;

    /* ----------------- keypair ----------------- */
    hal_send_str("-- keypair --");
    hal_spraystack();
    t0 = hal_get_time();
    rc = crypto_sign_keypair(pk, sk);
    t1 = hal_get_time();
    if (rc != 0) { hal_send_str("EXT-GATE: FAIL (keypair)"); do_semihosting_exit(1); }
    stack_kp = (unsigned int)hal_checkstack();
    cyc_kp   = (unsigned long long)(t1 - t0);
    dump_stage("keypair", stack_kp, cyc_kp);

    /* ----------------- sign ----------------- */
    hal_send_str("-- sign --");
    hal_spraystack();
    t0 = hal_get_time();
    rc = crypto_sign(sm, &smlen, msg, MLEN, sk);
    t1 = hal_get_time();
    if (rc != 0) { hal_send_str("EXT-GATE: FAIL (sign)"); do_semihosting_exit(1); }
    stack_sg = (unsigned int)hal_checkstack();
    cyc_sg   = (unsigned long long)(t1 - t0);
    dump_stage("sign", stack_sg, cyc_sg);

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
    if (rc != 0) { hal_send_str("EXT-GATE: FAIL (verify)"); do_semihosting_exit(1); }
    stack_vf = (unsigned int)hal_checkstack();
    cyc_vf   = (unsigned long long)(t1 - t0);
    dump_stage("verify", stack_vf, cyc_vf);

    if (mlen2 != MLEN || memcmp(msg, msg2, MLEN) != 0) {
        hal_send_str("EXT-GATE: FAIL (message mismatch)");
        do_semihosting_exit(1);
    }

    memcpy(line, "PK[0..15]:", 10);
    for (int i = 0; i < 16; i++) {
        line[10+i*2]   = HEX[pk[i]>>4];
        line[10+i*2+1] = HEX[pk[i]&0xf];
    }
    line[10+32] = '\0';
    hal_send_str(line);

    memcpy(line, "SIG[0..15]:", 11);
    for (int i = 0; i < 16; i++) {
        line[11+i*2]   = HEX[sm[i]>>4];
        line[11+i*2+1] = HEX[sm[i]&0xf];
    }
    line[11+32] = '\0';
    hal_send_str(line);

    hal_send_str("EXT-GATE: PASS (keypair/sign/verify round-trip OK)");

    /* ---- internal sign/verify round-trip ---- */
    {
        static uint8_t sig_int[CRYPTO_BYTES];
        static uint8_t rnd_det[32];
        size_t sig_int_len = 0;
        for (size_t i = 0; i < 32; i++) rnd_det[i] = 0;

        hal_send_str("-- internal sign --");
        hal_spraystack();
        t0 = hal_get_time();
        rc = MLDSA_NAMESPACE(crypto_sign_signature_internal)(
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
        rc = MLDSA_NAMESPACE(crypto_sign_verify_internal)(
                 sig_int, sig_int_len, msg, MLEN, pk);
        t1 = hal_get_time();
        if (rc != 0) {
            hal_send_str("INT-GATE: FAIL (internal verify)");
            do_semihosting_exit(1);
        }
        dump_stage("verify_internal",
                   (unsigned int)hal_checkstack(),
                   (unsigned long long)(t1 - t0));

        memcpy(line, "SIG_INT[0..15]:", 15);
        for (int i = 0; i < 16; i++) {
            line[15+i*2]   = HEX[sig_int[i]>>4];
            line[15+i*2+1] = HEX[sig_int[i]&0xf];
        }
        line[15+32] = '\0';
        hal_send_str(line);

        /* Cross-check: internal sig must NOT pass external verify */
        rc = MLDSA_NAMESPACE(crypto_sign_verify_ctx)(
                 sig_int, CRYPTO_BYTES, msg, MLEN, NULL, 0, pk);
        if (rc == 0) {
            hal_send_str("INT-GATE: FAIL (internal sig passed external verify)");
            do_semihosting_exit(1);
        }
        /* And external sig must NOT pass internal verify */
        rc = MLDSA_NAMESPACE(crypto_sign_verify_internal)(
                 sm, CRYPTO_BYTES, msg, MLEN, pk);
        if (rc == 0) {
            hal_send_str("INT-GATE: FAIL (external sig passed internal verify)");
            do_semihosting_exit(1);
        }

        hal_send_str("INT-GATE: PASS (internal sign/verify round-trip OK; distinct from external)");
    }

#ifndef KAT_GATE_ONLY
    /* -------- NIST ACVP KAT (ML-DSA-44, 115 cases) ----------- */
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

        hal_send_str("-- NIST ACVP KAT (ML-DSA-44) --");

        /* sigGen internal */
        pass = 0; fail = 0;
        for (int i = 0; i < KAT44_SIGGEN_INT_DET_N; i++) {
            const siggen_int_tc44_t *tc = &kat_siggen_sg08[i];
            siglen = 0;
            kat_t0 = hal_get_time();
            rc = MLDSA_NAMESPACE(crypto_sign_signature_internal)(
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
        if (fail == 0) hal_send_str("[sigGen tgId= 8 internal/det  ] 15/15 PASS");
        else           hal_send_str("[sigGen tgId= 8 internal/det  ] FAIL");

        pass = 0; fail = 0;
        for (int i = 0; i < KAT44_SIGGEN_INT_NDET_N; i++) {
            const siggen_int_tc44_t *tc = &kat_siggen_sg20[i];
            siglen = 0;
            kat_t0 = hal_get_time();
            rc = MLDSA_NAMESPACE(crypto_sign_signature_internal)(
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
        if (fail == 0) hal_send_str("[sigGen tgId=20 internal/ndet ] 15/15 PASS");
        else           hal_send_str("[sigGen tgId=20 internal/ndet ] FAIL");

        /* sigGen external */
        pass = 0; fail = 0;
        for (int i = 0; i < KAT44_SIGGEN_EXT_DET_N; i++) {
            const siggen_ext_tc44_t *tc = &kat_siggen_sg01[i];
            siglen = 0;
            kat_t0 = hal_get_time();
            rc = MLDSA_NAMESPACE(crypto_sign_signature_ctx_rnd)(
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
        if (fail == 0) hal_send_str("[sigGen tgId= 1 external/det  ] 15/15 PASS");
        else           hal_send_str("[sigGen tgId= 1 external/det  ] FAIL");

        pass = 0; fail = 0;
        for (int i = 0; i < KAT44_SIGGEN_EXT_NDET_N; i++) {
            const siggen_ext_tc44_t *tc = &kat_siggen_sg13[i];
            siglen = 0;
            kat_t0 = hal_get_time();
            rc = MLDSA_NAMESPACE(crypto_sign_signature_ctx_rnd)(
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
        if (fail == 0) hal_send_str("[sigGen tgId=13 external/ndet ] 15/15 PASS");
        else           hal_send_str("[sigGen tgId=13 external/ndet ] FAIL");

        /* sigVer */
        pass = 0; fail = 0;
        for (int i = 0; i < KAT44_SIGVER_INT_N; i++) {
            const sigver_int_tc44_t *tc = &kat_sigver_sv08[i];
            kat_t0 = hal_get_time();
            rc = MLDSA_NAMESPACE(crypto_sign_verify_internal)(
                     tc->sig, CRYPTO_BYTES, tc->msg, tc->mlen, tc->pk);
            kat_t1 = hal_get_time();
            kat_sigver_int_total += (uint64_t)(kat_t1 - kat_t0);
            int got = (rc == 0) ? 1 : 0;
            if (got == tc->exp_pass) pass++;
            else                     fail++;
        }
        total_pass += pass; total_fail += fail;
        if (fail == 0) hal_send_str("[sigVer tgId= 8 internal      ] 15/15 PASS");
        else           hal_send_str("[sigVer tgId= 8 internal      ] FAIL");

        pass = 0; fail = 0;
        for (int i = 0; i < KAT44_SIGVER_EXT_N; i++) {
            const sigver_ext_tc44_t *tc = &kat_sigver_sv01[i];
            kat_t0 = hal_get_time();
            rc = MLDSA_NAMESPACE(crypto_sign_verify_ctx)(
                     tc->sig, CRYPTO_BYTES,
                     tc->msg, tc->mlen, tc->ctx, tc->ctxlen, tc->pk);
            kat_t1 = hal_get_time();
            kat_sigver_ext_total += (uint64_t)(kat_t1 - kat_t0);
            int got = (rc == 0) ? 1 : 0;
            if (got == tc->exp_pass) pass++;
            else                     fail++;
        }
        total_pass += pass; total_fail += fail;
        if (fail == 0) hal_send_str("[sigVer tgId= 1 external      ] 15/15 PASS");
        else           hal_send_str("[sigVer tgId= 1 external      ] FAIL");

        /* keyGen */
        pass = 0; fail = 0;
        for (int i = 0; i < KAT44_KEYGEN_N; i++) {
            const keygen_tc44_t *tc = &kat_keygen_kg01[i];
            kat_t0 = hal_get_time();
            rc = MLDSA_NAMESPACE(crypto_sign_keypair_from_seed)(
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
        if (fail == 0) hal_send_str("[keyGen tgId= 1               ] 25/25 PASS");
        else           hal_send_str("[keyGen tgId= 1               ] FAIL");

        send_unsigned("KAT,total_pass:", (unsigned)total_pass);
        send_unsigned("KAT,total_fail:", (unsigned)total_fail);
        if (total_fail != 0) {
            hal_send_str("KAT-GATE: FAIL");
            do_semihosting_exit(1);
        }
        hal_send_str("KAT-GATE: PASS (115/115 NIST ACVP ML-DSA-44 vectors)");
        send_unsignedll("KAT,avg,keypair,cycles:",
                        kat_keygen_total / KAT44_KEYGEN_N);
        send_unsignedll("KAT,avg,sign_internal,cycles:",
                        kat_siggen_int_total / (KAT44_SIGGEN_INT_DET_N + KAT44_SIGGEN_INT_NDET_N));
        send_unsignedll("KAT,avg,sign_external,cycles:",
                        kat_siggen_ext_total / (KAT44_SIGGEN_EXT_DET_N + KAT44_SIGGEN_EXT_NDET_N));
        send_unsignedll("KAT,avg,verify_internal,cycles:",
                        kat_sigver_int_total / KAT44_SIGVER_INT_N);
        send_unsignedll("KAT,avg,verify_external,cycles:",
                        kat_sigver_ext_total / KAT44_SIGVER_EXT_N);
    }
#else /* KAT_GATE_ONLY */
    hal_send_str("GATE-ONLY: PASS (skipped KAT; use qemu44 for full 115-case ACVP)");
#endif /* KAT_GATE_ONLY */

    hal_send_str("=== QEMU test done ===");
    do_semihosting_exit(0);
}
