/*
 * test_mlkem768_main.c — Phase A baseline harness for impl_sc300 ML-KEM-768.
 *
 * Runs keypair -> encaps -> decaps round-trip and prints shared-secret
 * equality result.  No ACVP KAT yet (Phase A ships reference port only).
 *
 * Banner line is parseable:   "MLKEM768,<toolchain>,<op>,cycles|stack:<N>"
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "hal.h"
#include "sendfn.h"
#include "api.h"           /* PQCLEAN_MLKEM768_CLEAN_* prototypes */
#include "kem.h"           /* _derand variants used by KAT runner */
#include "kat_mlkem768.h"  /* deterministic test vectors */

#define PK_LEN  PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES   /* 1184 */
#define SK_LEN  PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES   /* 2400 */
#define CT_LEN  PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES  /* 1088 */
#define SS_LEN  PQCLEAN_MLKEM768_CLEAN_CRYPTO_BYTES            /* 32   */

static uint8_t pk[PK_LEN];
static uint8_t sk[SK_LEN];
static uint8_t ct[CT_LEN];
static uint8_t ss_enc[SS_LEN];
static uint8_t ss_dec[SS_LEN];

/* Semihosting SYS_EXIT (same convention as ML-DSA harness). */
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

static void emit_hex16(const char *tag, const uint8_t *buf)
{
    static const char hx[] = "0123456789abcdef";
    char line[128];
    size_t i = 0;
    while (tag[i] != 0 && i < sizeof(line) - 34) {
        line[i] = tag[i];
        i++;
    }
    for (size_t j = 0; j < 16; j++) {
        line[i++] = hx[(buf[j] >> 4) & 0xF];
        line[i++] = hx[buf[j] & 0xF];
    }
    line[i] = 0;
    hal_send_str(line);
}

int main(void)
{
    uint64_t t0, t1;
    int rc;
    int fail = 0;

    hal_setup(CLOCK_BENCHMARK);
    hal_send_str("=========================================");
    hal_send_str("impl_sc300 ML-KEM-768 QEMU test (clean ref)");
#if defined(__ARMCC_VERSION)
    hal_send_str("  toolchain=armclang, core=Cortex-M3 (SC300)");
#else
    hal_send_str("  toolchain=gcc, core=Cortex-M3 (SC300)");
#endif
    hal_send_str("=========================================");

    send_unsigned("CRYPTO_PUBLICKEYBYTES:", (unsigned)PK_LEN);
    send_unsigned("CRYPTO_SECRETKEYBYTES:", (unsigned)SK_LEN);
    send_unsigned("CRYPTO_CIPHERTEXTBYTES:", (unsigned)CT_LEN);
    send_unsigned("CRYPTO_BYTES:", (unsigned)SS_LEN);

    /* ---------- keypair ---------- */
    hal_send_str("-- keypair --");
    hal_spraystack();
    t0 = hal_get_time();
    rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
    t1 = hal_get_time();
    if (rc != 0) {
        send_unsigned("keypair rc:", (unsigned)rc);
        fail = 1;
    }
    send_unsigned("MLKEM768,stack,keypair:",  (unsigned)hal_checkstack());
    send_unsignedll("MLKEM768,cycles,keypair:", (uint64_t)(t1 - t0));

    /* ---------- encaps ---------- */
    hal_send_str("-- encaps --");
    hal_spraystack();
    t0 = hal_get_time();
    rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss_enc, pk);
    t1 = hal_get_time();
    if (rc != 0) {
        send_unsigned("encaps rc:", (unsigned)rc);
        fail = 1;
    }
    send_unsigned("MLKEM768,stack,encaps:",  (unsigned)hal_checkstack());
    send_unsignedll("MLKEM768,cycles,encaps:", (uint64_t)(t1 - t0));

    /* ---------- decaps ---------- */
    hal_send_str("-- decaps --");
    hal_spraystack();
    t0 = hal_get_time();
    rc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_dec, ct, sk);
    t1 = hal_get_time();
    if (rc != 0) {
        send_unsigned("decaps rc:", (unsigned)rc);
        fail = 1;
    }
    send_unsigned("MLKEM768,stack,decaps:",  (unsigned)hal_checkstack());
    send_unsignedll("MLKEM768,cycles,decaps:", (uint64_t)(t1 - t0));

    emit_hex16("PK[0..15]:",     pk);
    emit_hex16("CT[0..15]:",     ct);
    emit_hex16("SS_ENC[0..15]:", ss_enc);
    emit_hex16("SS_DEC[0..15]:", ss_dec);

    if (!fail && memcmp(ss_enc, ss_dec, SS_LEN) == 0) {
        hal_send_str("EXT-GATE: PASS (keygen/encaps/decaps round-trip OK)");
    } else {
        hal_send_str("EXT-GATE: FAIL");
        fail = 1;
    }

    /* --------------------------------------------------------------- *
     * ACVP-style KAT: deterministic seeds -> byte-exact expected
     * values.  Runs _derand variants to avoid any randombytes reliance.
     * --------------------------------------------------------------- */
    hal_send_str("-- KAT (deterministic _derand vectors) --");
    int kat_fail = 0;
    for (int i = 0; i < KAT_MLKEM768_NVEC; i++) {
        const kat_mlkem768_t *v = &kat_mlkem768[i];
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, v->kp_seed);
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct, ss_enc, pk, v->enc_coins);
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_dec, ct, sk);

        int ok_pk = (memcmp(pk,     v->exp_pk, PK_LEN)  == 0);
        int ok_sk = (memcmp(sk,     v->exp_sk, SK_LEN)  == 0);
        int ok_ct = (memcmp(ct,     v->exp_ct, CT_LEN)  == 0);
        int ok_ss = (memcmp(ss_enc, v->exp_ss, SS_LEN)  == 0);
        int ok_rt = (memcmp(ss_dec, v->exp_ss, SS_LEN)  == 0);

        send_unsigned("KAT,vec:", (unsigned)i);
        if (!(ok_pk && ok_sk && ok_ct && ok_ss && ok_rt)) {
            hal_send_str("KAT,FAIL");
            send_unsigned("  pk_ok:", (unsigned)ok_pk);
            send_unsigned("  sk_ok:", (unsigned)ok_sk);
            send_unsigned("  ct_ok:", (unsigned)ok_ct);
            send_unsigned("  ss_ok:", (unsigned)ok_ss);
            send_unsigned("  rt_ok:", (unsigned)ok_rt);
            kat_fail = 1;
        } else {
            hal_send_str("  ok");
        }
    }
    if (!kat_fail) {
        send_unsigned("KAT-GATE: PASS (ACVP-style vectors):", KAT_MLKEM768_NVEC);
    } else {
        hal_send_str("KAT-GATE: FAIL");
        fail = 1;
    }

    /* --------------------------------------------------------------- *
     * Issue #5 CM exercise — runs decaps via the CM-augmented wrapper
     * and checks shared-secret equality against the baseline path.    *
     * baseline 빌드 (CM_* 미정의) 시 두 경로가 byte-identical, CM 빌드
     * 시 CM 5종 (Shuffling/Masking/Parity/Integrity/Rice CSUM) 적용 후
     * 동일 결과가 나와야 한다.                                          *
     * --------------------------------------------------------------- */
    extern unsigned int kem_decaps(unsigned char *ss,
                                    const unsigned char *ct,
                                    const unsigned char *sk);
    {
        hal_send_str("-- CM-Decaps round-trip --");
        const kat_mlkem768_t *v = &kat_mlkem768[0];
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, v->kp_seed);
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct, ss_enc, pk, v->enc_coins);

        uint8_t ss_cm[SS_LEN];
        unsigned int rc = kem_decaps(ss_cm, ct, sk);
        int cm_ok = (rc == 0x1234u) && (memcmp(ss_cm, v->exp_ss, SS_LEN) == 0);
        if (cm_ok) {
            hal_send_str("CM-GATE: PASS (kem_decaps wrapper round-trip)");
        } else {
            hal_send_str("CM-GATE: FAIL");
            send_unsigned("  rc:",   (unsigned)rc);
            send_unsigned("  ok:",   (unsigned)cm_ok);
            fail = 1;
        }
    }

    hal_send_str("=== QEMU test done ===");
    do_semihosting_exit(0);
}
