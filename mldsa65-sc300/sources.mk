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

# Pristine PQClean reference sign.c / ntt.c kept in tree for audit, but
# NOT linked by any active build -- every target uses sc300/sign.c and
# sc300/ntt.S (the optimised replacements).
IMPL_SRCS_REF_SIGN_UNUSED := $(HERE)/ref/sign.c
IMPL_SRCS_REF_NTT_UNUSED  := $(HERE)/ref/ntt.c

# ------------------------------------------------------------------ #
# sc300 custom                                                         #
# ------------------------------------------------------------------ #
# Streaming sign + masked kernels
IMPL_SRCS_SC300_C := \
    $(HERE)/sc300/sign.c \
    $(HERE)/sc300/masked_random.c \
    $(HERE)/sc300/masked_keccak_core.c \
    $(HERE)/sc300/masked_rhoprime.c \
    $(HERE)/sc300/masked_cs1.c \
    $(HERE)/sc300/masked_cs2_ct0.c \
    $(HERE)/sc300/masked_y_sample.c \
    $(HERE)/sc300/masked_chknorm.c \
    $(HERE)/sc300/masked_ba.c

# Hand-tuned ARMv7-M NTT (endian-safe; always included)
IMPL_SRCS_SC300_S := $(HERE)/sc300/ntt.S

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

# Library-runtime set plus the Keccak-C backend (used on BE builds).
# LE builds add IMPL_SRCS_KECCAK_ASM instead.
# The selection happens in each Makefile based on its BE= knob.

# ------------------------------------------------------------------ #
# MPS2 platform (startup + linker script template)                    #
# ------------------------------------------------------------------ #
IMPL_SRCS_MPS2_STARTUP_S := $(COMMON)/mps2/startup_MPS2.S
IMPL_SRCS_MPS2_LDSCRIPT  := $(COMMON)/mps2/MPS2.ld
