# impl_sc300/sources.mk —
# Shared source-list definitions included by every impl_sc300 Makefile
# (Makefile.gcc, Makefile.armclang, Makefile.gcc.lib, Makefile.armclang.lib).
#
# The including Makefile must set:
#   HERE    := absolute path of impl_sc300/
#   COMMON  := absolute path of ../common/
#   MCOMMON := absolute path of ../mupq/common/
#
# This file only defines variables; it never creates build rules.

# ------------------------------------------------------------------ #
# PQClean ML-DSA-65 CLEAN reference (non-NTT parts)                   #
# ------------------------------------------------------------------ #
IMPL_SRCS_REF_NONSIGN := \
    $(HERE)/ref/packing.c \
    $(HERE)/ref/poly.c \
    $(HERE)/ref/polyvec.c \
    $(HERE)/ref/reduce.c \
    $(HERE)/ref/rounding.c \
    $(HERE)/ref/symmetric-shake.c

# ------------------------------------------------------------------ #
# Issue #5 — Countermeasure 모듈 (KEM, DSA 공용)                      #
# ------------------------------------------------------------------ #
IMPL_SRCS_CM_C := \
    $(HERE)/sc300/cm_shuffling.c \
    $(HERE)/sc300/cm_masking.c \
    $(HERE)/sc300/cm_parity.c \
    $(HERE)/sc300/cm_integrity.c \
    $(HERE)/sc300/cm_rice_checksum.c

# ------------------------------------------------------------------ #
# ML-KEM-768 clean reference (PQClean) — sc300_kem/ overrides:        #
#   indcpa.c → streaming A/A^T row gen (saves ~6 KB stack peak).       #
#   ntt.c    → ntt/invntt thunk into pqm3-derived ARMv7-M assembly.    #
# ------------------------------------------------------------------ #
IMPL_SRCS_REF_KEM768 := \
    $(HERE)/ref_kem/cbd.c \
    $(HERE)/ref_kem/kem.c \
    $(HERE)/sc300_kem/ntt.c \
    $(HERE)/ref_kem/poly.c \
    $(HERE)/ref_kem/polyvec.c \
    $(HERE)/ref_kem/reduce.c \
    $(HERE)/ref_kem/symmetric-shake.c \
    $(HERE)/ref_kem/verify.c \
    $(HERE)/sc300_kem/indcpa.c \
    $(HERE)/sc300_kem/kem_cm.c \
    $(IMPL_SRCS_CM_C)

# Hand-tuned Kyber/ML-KEM ARMv7-M assembly (NTT, INVNTT, basemul, frommont,
# barrett_reduce, pointwise add/sub).  Linked alongside IMPL_SRCS_REF_KEM768.
IMPL_SRCS_KEM768_S := $(HERE)/sc300_kem/kyber_kernels.S

# Pristine PQClean reference sign.c / ntt.c kept in tree for audit, but
# NOT linked by any active build -- every target uses sc300/sign.c and
# sc300/ntt.S (the optimised replacements).
IMPL_SRCS_REF_SIGN_UNUSED := $(HERE)/ref/sign.c
IMPL_SRCS_REF_NTT_UNUSED  := $(HERE)/ref/ntt.c

# ------------------------------------------------------------------ #
# sc300 custom                                                         #
# ------------------------------------------------------------------ #
# Streaming sign + masked kernels  (DSA-side; CM 모듈은 IMPL_SRCS_CM_C)
IMPL_SRCS_SC300_C := \
    $(HERE)/sc300/sign.c \
    $(HERE)/sc300/masked_random.c \
    $(HERE)/sc300/masked_keccak_core.c \
    $(HERE)/sc300/masked_rhoprime.c \
    $(HERE)/sc300/masked_cs1.c \
    $(HERE)/sc300/masked_cs2_ct0.c \
    $(HERE)/sc300/masked_y_sample.c \
    $(HERE)/sc300/masked_chknorm.c \
    $(HERE)/sc300/masked_ba.c \
    $(IMPL_SRCS_CM_C)

# Hand-tuned ARMv7-M NTT + Dilithium scalar kernels (endian-safe; always
# included).  dilithium_kernels.S provides ARMv7-M-only pointwise_montgomery /
# poly_reduce_asm / poly_caddq_asm, used by ref/poly.c when MLDSA_SC300_ASM
# is set in CFLAGS.
IMPL_SRCS_SC300_S := \
    $(HERE)/sc300/ntt.S \
    $(HERE)/sc300/dilithium_kernels.S

# ------------------------------------------------------------------ #
# SHA-3 / SHAKE                                                        #
# ------------------------------------------------------------------ #
IMPL_SRCS_FIPS202    := $(MCOMMON)/fips202.c
IMPL_SRCS_KECCAK_ASM := $(COMMON)/keccakf1600.S   # LE only
IMPL_SRCS_KECCAK_C   := $(MCOMMON)/keccakf1600.c  # endian-safe

# ------------------------------------------------------------------ #
# Caller-facing API                                                    #
# ------------------------------------------------------------------ #
IMPL_SRCS_API := $(HERE)/api_wrapper.c

# ------------------------------------------------------------------ #
# Randombytes (some builds include it, some leave to the caller)      #
# ------------------------------------------------------------------ #
IMPL_SRCS_RANDOMBYTES := $(COMMON)/randombytes.c

# ------------------------------------------------------------------ #
# Test harness (QEMU builds only)                                     #
# ------------------------------------------------------------------ #
IMPL_SRCS_TEST_HARNESS := \
    $(HERE)/test/test_mldsa65_main.c \
    $(HERE)/test/hal_m3.c

# ------------------------------------------------------------------ #
# Library-runtime set                                                  #
# (what both .lib Makefiles ship in the archive; no test, no main)   #
# ------------------------------------------------------------------ #
IMPL_SRCS_LIB_C := \
    $(IMPL_SRCS_FIPS202) \
    $(IMPL_SRCS_REF_NONSIGN) \
    $(IMPL_SRCS_SC300_C) \
    $(IMPL_SRCS_API)

IMPL_SRCS_LIB_S := $(IMPL_SRCS_SC300_S)

# ML-KEM-768 library-runtime set (co-exported alongside ML-DSA).
# All sources are mode-independent (no MLDSA_MODE flag) and live in
# their own object directory to avoid filename collisions with ML-DSA.
IMPL_SRCS_LIB_KEM768_C := \
    $(IMPL_SRCS_REF_KEM768) \
    $(HERE)/api_wrapper_kem.c

# Library-runtime set plus the Keccak-C backend (used on BE builds).
# LE builds add IMPL_SRCS_KECCAK_ASM instead.
# The selection happens in each Makefile based on its BE= knob.

# ------------------------------------------------------------------ #
# MPS2 platform (startup + linker script template)                    #
# ------------------------------------------------------------------ #
IMPL_SRCS_MPS2_STARTUP_S := $(COMMON)/mps2/startup_MPS2.S
IMPL_SRCS_MPS2_LDSCRIPT  := $(COMMON)/mps2/MPS2.ld
