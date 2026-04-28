# ML-DSA-44/65 on ARM Cortex-M3 (SC300)

FIPS 204 ML-DSA-44 and ML-DSA-65 implementation targeting the ARM SC300 (Cortex-M3 compatible) core,
with SCA masking countermeasures.  Tested via QEMU `mps2-an385` and validated against NIST ACVP KAT vectors.

## Quick start

```bash
# Ubuntu (install toolchain + QEMU)
sudo apt install gcc-arm-none-eabi qemu-system-arm

# macOS
brew install qemu
# Download arm-gnu-toolchain from https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads

# Build and run ML-DSA-65
make -f Makefile.gcc build GNU_TC=/path/to/arm-gnu-toolchain
make -f Makefile.gcc qemu  GNU_TC=/path/to/arm-gnu-toolchain QEMU=$(which qemu-system-arm)

# Build and run ML-DSA-44
make -f Makefile.gcc build44 GNU_TC=/path/to/arm-gnu-toolchain
make -f Makefile.gcc qemu44  GNU_TC=/path/to/arm-gnu-toolchain QEMU=$(which qemu-system-arm)
```

Or use the interactive TUI (macOS/Linux):
```bash
bash tools/tui.sh
```

---

## Directory structure and file origins

```
.
├── ref/                        # Reference C implementation
│   ├── *.c / *.h               #   Derived from pqclean/mldsa (FIPS 204 ref)
│   └── LICENSE                 #   CC0 1.0 / public domain
│
├── sc300/                      # SC300-optimised implementation (this project)
│   ├── ntt.S                   #   ARM Thumb-2 NTT (original, this project)
│   ├── sign.c                  #   Signing core with SCA masking hooks (original)
│   ├── masked.h                #   SCA masking interface (original)
│   ├── masked_random.c/h       #   Masked random sampling (original)
│   ├── masked_rhoprime.c       #   Step 1: boolean masking of ρ′ (original)
│   ├── masked_cs1.c            #   Step 2: masked cs₁ polynomial (original)
│   ├── masked_cs2_ct0.c        #   Step 3: masked cs₂/ct₀ (original)
│   ├── masked_y_sample.c       #   Step 4: masked y sampling (original)
│   ├── masked_chknorm.c        #   Step 5: masked norm check (original)
│   ├── masked_ba.c             #   Step 6: masked b/a accumulation (original)
│   └── masked_keccak_core.c    #   Masked Keccak core (original)
│
├── test/                       # Test harness (original, this project)
│   ├── test_mldsa65_main.c     #   ML-DSA-65 QEMU test + NIST ACVP KAT (115 vectors)
│   ├── test_mldsa44_main.c     #   ML-DSA-44 QEMU test + NIST ACVP KAT (115 vectors)
│   └── kat139.h / kat_vectors*.h  # KAT vector headers (generated from NIST ACVP)
│
├── cmsis/                      # CMSIS core headers
│   └── *.h                     #   From ARM CMSIS (Apache 2.0)
│                               #   https://github.com/ARM-software/CMSIS_5
│
├── vendor/                     # Vendored upstream dependencies
│   │
│   ├── pqm4-common/            # From pqm4/common  (MIT / CC0)
│   │   │                       #   https://github.com/mupq/pqm4
│   │   ├── keccakf1600.S       #   ARMv7-M Keccak-f[1600] assembly (LE)
│   │   ├── randombytes.c       #   NIST DRBG / entropy source shim
│   │   └── mps2/               #   MPS2-AN385 platform support
│   │       ├── startup_MPS2.S  #     Reset handler and vector table
│   │       ├── MPS2.ld         #     Linker script
│   │       └── *.h             #     Platform / CMSIS headers
│   │
│   └── mupq-common/            # From pqm4/mupq/common  (MIT / CC0)
│       │                       #   https://github.com/mupq/mupq
│       ├── fips202.c/h         #   SHAKE128/256, SHA3 (public domain)
│       ├── keccakf1600.c/h     #   Portable Keccak-f[1600]
│       ├── hal.h               #   HAL interface (UART, cycle counter)
│       ├── sendfn.h            #   send_unsignedll() output helper
│       ├── randombytes.h       #   NIST randombytes API
│       ├── compat.h            #   Portability shims
│       └── crypto_declassify.h #   Constant-time declassify helper
│
├── tools/                      # Build + test tooling (original, this project)
│   ├── tui.sh                  #   Interactive TUI for build / test / perf
│   └── env.sh                  #   Toolchain auto-detection
│
├── docs/                       # Documentation
│
├── Makefile.gcc                # GCC build (direct-object, test ELF)
├── Makefile.gcc.lib            # GCC build (static library)
├── Makefile.armclang           # Arm Compiler 6 build (test ELF)
├── Makefile.armclang.lib       # Arm Compiler 6 build (static library)
├── sources.mk                  # Shared source file lists
├── api_wrapper.c/h             # Public API wrapper (original)
├── mldsa65_sc300.h             # Single public header for SC300 target
└── mldsa_dispatch.h            # Compile-time variant dispatch
```

---

## SCA masking steps

Enable individual steps with `EXTRA_CFLAGS`:

| Step | Flag | Notes |
|------|------|-------|
| 1 | `-DMLDSA_MASK_RHOPRIME` | Boolean masking of ρ′ |
| 2 | `-DMLDSA_MASK_CS1` | Masked cs₁ polynomial |
| 3 | `-DMLDSA_MASK_CS2_CT0` | Masked cs₂ / ct₀ |
| 4 | `-DMLDSA_MASK_Y_SAMPLE -DMLDSA_MASK_ACCEPT_EMULATION` | Masked y sampling |
| 5 | `-DMLDSA_MASK_CHKNORM -DMLDSA_MASK_ACCEPT_EMULATION` | Masked norm check |
| 6 | `-DMLDSA_MASK_BA -DMLDSA_MASK_ACCEPT_EMULATION` | Masked b/a accumulation |

Steps 4–6 require `MLDSA_MASK_ACCEPT_EMULATION` because the QEMU cycle counter
does not model timing side-channels; the flag acknowledges this limitation.

---

## Performance (estimated, 70 MHz Cortex-M3)

Measured via QEMU CYCCNT × 75 correction factor (QEMU undercounts ~50–100×).
Averaged over all NIST ACVP KAT vectors per operation.

| Operation | ML-DSA-44 | ML-DSA-65 |
|-----------|-----------|-----------|
| KeyGen | ~145 ms | ~240 ms |
| Sign (internal) | ~150 ms | ~240 ms |
| Sign (external) | ~420 ms | ~690 ms |
| Verify (internal) | ~23 ms | ~37 ms |
| Verify (external) | ~42 ms | ~68 ms |

Run `bash tools/tui.sh` → **Perf report** for exact numbers with current build.
