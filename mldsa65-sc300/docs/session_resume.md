# Session Resume — ML-DSA-65 SC300 (last updated 2026-04-23)

> New Claude session on this project: read this file first, then
> `cd /Users/ydoh/work/pqm4/impl_sc300` and treat the `sca-masking`
> branch as the stable working point.

## What this project is
- **Algorithm**: ML-DSA-65 per FIPS 204 (August 2024 final standard).
- **Target**: ARM Cortex-M3 (SC300 core) via QEMU mps2-an385.
- **Goal**: deliver a static library (armclang / armar) consumable from
  a customer-provided 10-arg API, with a PoC for side-channel masking
  on the signing path.

## Current state — DONE / STABLE

All planned work items are complete, tested, and **pushed to GitHub**.
Nothing in progress.  Start the next session from a clean, green
checkpoint.

- NIST ACVP byte-exact: **passing** (`tgId=10 tcId=139`, 3309/3309 bytes).
- Three gates in every QEMU run: `EXT-GATE PASS`, `INT-GATE PASS`,
  `KAT-GATE PASS`.
- Library-consumer harness (`qemu_lib`): `LIB-EXT`, `LIB-INT`,
  `LIB-KAT` all **PASS** using only `mldsa65_sc300.h`.
- Library matrix: `{BE=0,1} × {ENUM=short,long} × {BUILD=release,debug}`
  all compile clean under arm-none-eabi-gcc sanity build.
- Release archive has **0** `.debug_*` sections (stripped).

## Performance snapshot (QEMU mps2-an385 SysTick, 3-run avg)

| Op                | cycles    | stack   |
|-------------------|----------:|--------:|
| `keypair`         | ~147,500  |  8,528  |
| `sign`  (external)| ~437,500  | 12,336  |
| `verify`(external)|  ~52,000  | 11,160  |
| `sign_internal`   | ~185,000  | 12,264  |
| `verify_internal` |  ~35,000  | 11,120  |

With all real masking (Steps 1+2+3): sign ≈ +7 %, stack +48 B total.

## Repository coordinates

| | path |
|---|---|
| Source tree                   | `/Users/ydoh/work/pqm4` (git repo) |
| Primary work dir              | `/Users/ydoh/work/pqm4/impl_sc300` |
| Active branch                 | `sca-masking` (21 commits ahead of upstream `master`) |
| Upstream remote               | `origin` → `github.com/mupq/pqm4.git` (read-only to us) |
| **Public delivery repo**      | **`github.com/YoungdaeOh/mldsa65-sc300`** (our repo, `main` branch) |
| Last public commit            | `5b74d5f` (consolidated snapshot of sca-masking work) |

The local branch has step-by-step history (21 individual commits);
the public repo has a single consolidated commit on top of the
earlier two.

## Environment split (documented in docs/ENVIRONMENTS.md)

| Role       | Host   | Primary task                             | Tools                          |
|------------|--------|------------------------------------------|--------------------------------|
| `dev`      | macOS  | Claude-driven edits + QEMU loop          | gcc-arm-none-eabi, qemu        |
| `delivery` | Ubuntu | armclang library production + integration| gcc, qemu, armclang / armar    |

Auto-detection: `tools/env.sh` exports `HOST_TAG`, `HOST_ROLE`,
`GNU_TC`, `QEMU`, `ARMCLANG`, `ARMAR` based on `uname -s-m`.  Overrides
via env vars always win.

### macOS defaults
```
GNU_TC  = /tmp/arm-gnu-toolchain-13.3.rel1-darwin-arm64-arm-none-eabi
QEMU    = /opt/homebrew/bin/qemu-system-arm
```
### Ubuntu defaults
```
GNU_TC   = /tmp/arm-gnu-toolchain-13.3.rel1-x86_64-arm-none-eabi
QEMU     = /usr/bin/qemu-system-arm
ARMCLANG = /opt/armclang/bin/armclang
ARMAR    = /opt/armclang/bin/armar
```

## Directory layout (impl_sc300)
```
impl_sc300/
├── mldsa65_sc300.h              single public caller header
├── api_wrapper.c/h              10-arg wrapper API
├── sources.mk                   shared Makefile source list
├── Makefile.{gcc,armclang}          QEMU test
├── Makefile.{gcc,armclang}.lib      library archive (BE, ENUM, BUILD)
├── mps2_an385.sct               armlink scatter file
├── ref/                         PQClean reference (sign.c/ntt.c unused)
├── sc300/
│   ├── sign.c                   streaming sign + FIPS 204 Sign_internal
│   ├── ntt.S                    ARMv7-M NTT asm (+ forward 2-layer merge)
│   ├── masked.h
│   ├── masked_random.c/h        shared PRNG (xorshift64 PoC)
│   ├── masked_keccak_core.c     real masked Keccak-f[1600] w/ inline-asm SecAnd
│   ├── masked_rhoprime.c        Step 1 (rho'' masked Keccak)
│   ├── masked_cs1.c             Step 2 (Phase 2a cs1 arithmetic shares)
│   ├── masked_cs2_ct0.c         Step 3 (Phase 2b cs2 + ct0 shares)
│   ├── masked_y_sample.c        Step 4 (cost emulation)
│   ├── masked_chknorm.c         Step 5 (cost emulation)
│   └── masked_ba.c              Step 6 (cost emulation)
├── cmsis/                       CMSIS Cortex-M3 headers
├── test/
│   ├── test_mldsa65_main.c      direct-object QEMU harness (EXT/INT/KAT)
│   ├── test_via_lib_main.c      library-consumer harness (public API only)
│   ├── hal_m3.c                 MPS2 HAL
│   ├── api_bridge.h
│   └── kat139.h                 NIST ACVP sigGen tcId=139 vector
├── tools/
│   ├── env.sh                   host auto-detection
│   └── tui.sh                   interactive menu (role-aware)
├── docs/
│   ├── ENVIRONMENTS.md          Mac dev vs Ubuntu delivery
│   └── session_resume.md        this file
├── output/                      all generated artefacts (gitignored)
└── log/                         user-captured QEMU stdout (gitignored)
```

## Targets and artefacts (rename: `s8` is gone)

| Make | Produces |
|------|---------|
| `make -f Makefile.gcc build` | `output/mldsa65_test.elf/.bin` |
| `make -f Makefile.gcc qemu` | runs it on QEMU mps2-an385 |
| `make -f Makefile.gcc build_lib` / `qemu_lib` | `output/mldsa65_test_via_lib.elf` (linked against debug `.a` only) |
| `make -f Makefile.armclang build` / `qemu` | `output/mldsa65_test_armclang.elf/.bin/.map` |
| `make -f Makefile.gcc.lib BUILD=release BE=0 ENUM=long` | `output/libmldsa65_sc300_gcc_le_long.a` (stripped) |
| `make -f Makefile.armclang.lib BUILD=debug BE=1 ENUM=short` | `output/libmldsa65_sc300_be_short_dbg.a` |

## SCA masking steps (each independent `#define`)

| Define | Step | Quality | sign Δcycles | Δstack |
|--------|------|---------|-------------|-------|
| `MLDSA_MASK_RHOPRIME` | 1 | **real 1st-order** Boolean-masked Keccak | +1.1 % | +40 B |
| `MLDSA_MASK_CS1` | 2 | **real 1st-order** arithmetic shares (cs1) | +4.1 % | +8 B |
| `MLDSA_MASK_CS2_CT0` | 3 | **real 1st-order** arithmetic shares (cs2,ct0) | +2.5 % | 0 |
| `MLDSA_MASK_Y_SAMPLE` | 4 | cost emulation (ASM Keccak ×2) | +27 % | +8 B |
| `MLDSA_MASK_CHKNORM` | 5 | cost emulation (constant-time chknorm) | ~0 % | 0 |
| `MLDSA_MASK_BA` | 6 | cost emulation (B→A unpack) | +0.9 % | 0 |

Emulation-level steps emit a compile `#warning` unless
`MLDSA_MASK_ACCEPT_EMULATION` is also defined.  **KAT byte-exact in
every combination.**

## Library profiles

`BUILD=release` (default) vs `BUILD=debug`:
- release : no `-g`; archive post-stripped.  **Safe to ship.**  Suffix none.
- debug   : `-O2 -g`, DWARF retained, no strip.  Used by `qemu_lib`.  Suffix `_dbg`.

Measured (le/long):
- debug   ≈ 167 KB, 139 `.debug_*` sections, 7,706 DWARF lines
- release ≈  55 KB, **0** `.debug_*` sections

Big-endian builds automatically substitute `mupq/common/keccakf1600.c`
(pure-C, endian-safe) for the LE-only `common/keccakf1600.S`.

## Commit history on `sca-masking`
```
b2de591  rename 's8' dev-milestone names to descriptive targets / artefacts
3acf94d  Consolidate build artefacts under output/ and log/; drop legacy files
fe92f2d  tui: show produced artifacts + next-step hints after every action
de98897  fix: lib Makefiles silently hijacked by make's built-in CC / trailing-comment BUILD knob
78be121  Add qemu_lib target + BUILD=debug|release library profiles
c76f472  Add host-aware TUI + environment separation
e104141  refactor: add single public header + emulation-level compile warning
42603a9  refactor: factor library source lists into sources.mk
ef4bf1e  refactor: move test-only sources into impl_sc300/test/
22b4ba2  refactor: unify seven per-file masked PRNGs into masked_random.c
31d8baf  Add library-only build for armclang with BE + enum-size knobs
34a9c62  Step 2 & 3: eliminate share-scratch poly by reusing y_elem
d5171d4  Step 4: revert to ASM cost emulation; keep real masking only in Step 1
f6d28a7  Step 4 revised again: real 1st-order masked Keccak with inline-asm SecAnd
793e29c  Step 4 revised: route through ARMv7-M ASM Keccak, near-zero stack
5a2ee89  Step 6 (MLDSA_MASK_BA): B->A conversion cost emulation at unpack sites
70bd552  Step 5 (MLDSA_MASK_CHKNORM): Constant-time chknorm + refresh-cost hint
90e39fb  Step 4 (MLDSA_MASK_Y_SAMPLE): Boolean-masked SHAKE256 for y sampling
5a41d06  Step 3 (MLDSA_MASK_CS2_CT0): Arithmetic masking of Phase 2b s2 and t0
b5ef3ae  Step 2 (MLDSA_MASK_CS1): Arithmetic masking of Phase 2a cs1 chain
ad1e169  Step 1 (MLDSA_MASK_RHOPRIME): Boolean-masked Keccak for rho''
58f3de8  Step 0: SCA masking baseline — impl_sc300 ML-DSA-65 SC300
```

## How to resume on Mac mini

```bash
cd /Users/ydoh/work/pqm4/impl_sc300
git status                               # should be clean on sca-masking
source tools/env.sh && report_env        # verify paths
tools/tui.sh                             # interactive (dev menu)
# or directly:
make -f Makefile.gcc qemu                # EXT/INT/KAT GATE
make -f Makefile.gcc qemu_lib            # LIB-EXT/INT/KAT GATE
```

## How to resume on Ubuntu (delivery host)

```bash
# first time setup
sudo apt install build-essential git qemu-system-arm
# ARM toolchain
wget https://developer.arm.com/-/media/Files/downloads/gnu/13.3.rel1/binrel/arm-gnu-toolchain-13.3.rel1-x86_64-arm-none-eabi.tar.xz
sudo tar -xf arm-gnu-toolchain-13.3.rel1-x86_64-arm-none-eabi.tar.xz -C /tmp
# armclang: install per ARM Keil instructions, expected at /opt/armclang/

# clone and go
git clone git@github.com:YoungdaeOh/mldsa65-sc300.git
cd mldsa65-sc300/impl_sc300
tools/tui.sh                             # auto-shows delivery menu
```

## Known caveats for a new session
- `impl_sc300/ref/sign.c` and `ref/ntt.c` are PQClean reference; kept
  for audit but not linked by any active target.  `sources.mk` marks
  them as `IMPL_SRCS_REF_{SIGN,NTT}_UNUSED`.
- Legacy S0/S1/S2/dil3s3 Makefile targets deleted in commit `3acf94d`
  along with their test sources.
- `common/keccakf1600.S.bak` exists upstream; untouched.
- Library Makefiles deliberately use `:=` (not `?=`) for `CC` / `AR` /
  `STRIP` because `make`'s built-in `CC=cc` hijacks `?=`.  Command-line
  overrides still work.
- `qemu_lib` link uses `-Wl,--no-warn-mismatch` to silence a cosmetic
  enum-size warning between our `-fno-short-enums` archive and
  newlib's `-fshort-enums` memset.  Functionally harmless.

## Possible follow-up directions (not yet requested)

1. **Real bit-interleaved masked Keccak-f[1600].S** replacing the
   Step 4 cost emulation.  Would move Step 4 from +27 % to ~+2 %.
   Estimated ~1000 LOC ARMv7-M Thumb-2 + TVLA validation.  Non-trivial.
2. **TVLA measurement rig** on ChipWhisperer-Nano or similar hardware;
   confirm the PoC masking's actual DPA resistance.
3. **Second-order masking** study for Steps 1-3.
4. **Upstream pqm4 integration test** — build under the vanilla pqm4
   framework, compare sign cycles against its existing `mldsa65_clean`.
5. **CI** (GitHub Actions) — run `tools/tui.sh`-equivalent non-interactive
   commands across all 4 library configs on every push.
6. **Release tag** on the public repo (e.g. `v0.1-sca-masking-poc`).

## User preferences captured during the session
- Korean chat, **English** code / comments / docs / Markdown.
- Aggressive cleanup is OK (user said "안쓰는 파일은 제거", "전체 리팩토링").
- Performance changes must be **measured before/after**; anything
  slower than current baseline is reverted (cf. Forward-NTT 2×
  unroll experiment which was reverted after showing +6 % cost).
- Prefer descriptive names over dev-milestone codenames (hence the
  `s8` → `build/qemu` / `mldsa65_test.elf` rename).
- Commit locally freely; push to GitHub only on explicit request.
- Shell command execution is generally autonomous on the dev host,
  except for actions with external blast radius (pushes, emails) which
  are always confirmed.

## Not in scope / do not do without explicit user request
- Do not push to `origin` (that is `mupq/pqm4`, read-only for us).
- Do not force-push anything on the public repo.
- Do not claim DPA resistance from the Step-4/5/6 cost-emulation
  code — it captures the cycle envelope only.
- Do not touch the stock-trader project at `/Users/ydoh/work/stock`
  while resuming this ML-DSA work.
