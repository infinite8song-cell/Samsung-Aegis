/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * test/test_via_lib_main.c —
 *
 * Library-consumer perspective QEMU test harness.
 *
 * This file deliberately includes ONLY the public library header
 * (mldsa65_sc300.h) and platform HAL.  It does NOT reach into
 * ref/, sc300/, or any internal headers.  If this translation
 * unit compiles + links + runs to LIB-GATE PASS, the shipped
 * library's public interface is by itself sufficient for a
 * downstream caller to sign, verify, and produce KAT-byte-exact
 * output.
 *
 * Three gates checked, all using the public API only:
 *   LIB-EXT-GATE  external-ctx round-trip
 *   LIB-INT-GATE  internal sign + internal verify round-trip
 *   LIB-KAT-GATE  byte-exact match with NIST ACVP sigGen
 *                 FIPS 204 tcId=139 expected signature
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "mldsa65_sc300.h"      /* only public library header */
#include "hal.h"                /* MPS2 HAL (provided by test build) */
#include "sendfn.h"
#include "kat139.h"             /* NIST ACVP tcId=139 vector */

#define MSG_LEN  59

static uint8_t pk [MLDSA65_PUBLIC_KEY_BYTES];
static uint8_t sk [MLDSA65_SECRET_KEY_BYTES];
static uint8_t sig[MLDSA65_SIGNATURE_BYTES];
static uint8_t msg[MSG_LEN];

/* Semihosting exit (matches the main harness convention). */
static void __attribute__((noreturn)) do_semihosting_exit(int status)
{
    (void)status;
    __asm volatile(
        "mov r0, #0x18\n\t"
        "ldr r1, =0x20026\n\t"
        "bkpt #0xAB\n\t"
        ::: "r0", "r1", "memory");
    while (1) ;
}

static void fail(const char *tag)
{
    hal_send_str(tag);
    do_semihosting_exit(1);
}

int main(void)
{
    size_t siglen = 0;
    int    rc;
    size_t i;
    uint8_t rnd_zero[MLDSA65_RND_BYTES];

    hal_setup(CLOCK_BENCHMARK);
    hal_send_str("=========================================");
    hal_send_str("via-library test  (public header only)  ");
    hal_send_str("=========================================");
    send_unsigned("MLDSA65_PUBLIC_KEY_BYTES:", (unsigned)MLDSA65_PUBLIC_KEY_BYTES);
    send_unsigned("MLDSA65_SECRET_KEY_BYTES:", (unsigned)MLDSA65_SECRET_KEY_BYTES);
    send_unsigned("MLDSA65_SIGNATURE_BYTES :", (unsigned)MLDSA65_SIGNATURE_BYTES);

    for (i = 0; i < MSG_LEN; i++) msg[i] = (uint8_t)i;
    for (i = 0; i < sizeof(rnd_zero); i++) rnd_zero[i] = 0;

    /* -------- LIB-EXT-GATE: external-ctx round trip -------------- */
    hal_send_str("-- library: keypair --");
    rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
    if (rc != 0) fail("LIB-GATE: FAIL (keypair)");

    hal_send_str("-- library: external sign_ctx --");
    rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(
             sig, &siglen,
             msg, MSG_LEN,
             (const uint8_t *)"", 0,
             sk);
    if (rc != 0 || siglen != MLDSA65_SIGNATURE_BYTES)
        fail("LIB-GATE: FAIL (external sign)");

    hal_send_str("-- library: external verify_ctx --");
    rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
             sig, siglen,
             msg, MSG_LEN,
             (const uint8_t *)"", 0,
             pk);
    if (rc != 0) fail("LIB-EXT-GATE: FAIL (verify)");
    hal_send_str("LIB-EXT-GATE: PASS");

    /* -------- LIB-INT-GATE: internal round trip ------------------ */
    hal_send_str("-- library: internal sign --");
    rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_internal(
             sig, &siglen,
             msg, MSG_LEN,
             rnd_zero,
             sk);
    if (rc != 0 || siglen != MLDSA65_SIGNATURE_BYTES)
        fail("LIB-INT-GATE: FAIL (sign)");

    hal_send_str("-- library: internal verify --");
    rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_internal(
             sig, siglen,
             msg, MSG_LEN,
             pk);
    if (rc != 0) fail("LIB-INT-GATE: FAIL (verify)");
    hal_send_str("LIB-INT-GATE: PASS");

    /* -------- LIB-KAT-GATE: byte-exact NIST ACVP tcId=139 -------- */
    hal_send_str("-- library: NIST ACVP tcId=139 byte-exact --");
    rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_internal(
             sig, &siglen,
             kat139_msg, KAT139_MLEN,
             rnd_zero,
             kat139_sk);
    if (rc != 0 || siglen != (size_t)KAT139_SIGLEN)
        fail("LIB-KAT-GATE: FAIL (sign returned error or wrong length)");
    for (i = 0; i < (size_t)KAT139_SIGLEN; i++) {
        if (sig[i] != kat139_sig_expected[i])
            fail("LIB-KAT-GATE: FAIL (signature bytes differ)");
    }
    hal_send_str("LIB-KAT-GATE: PASS (byte-exact NIST ACVP tcId=139)");

    hal_send_str("=== via-library test: ALL GATES PASS ===");
    do_semihosting_exit(0);
    return 0;
}
