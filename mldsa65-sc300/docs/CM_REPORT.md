# Issue #5 — ML-KEM-768 / ML-DSA-65 Countermeasure Report

**적용 대상:** `mldsa65-sc300` (ARMClang v6.22, SC300 Cortex-M3, -O0, Stack ≤ 11 KB)
**작업 범위:** Issue Samsung-Aegis #5 (작업1 — 성능 최적화 / 작업2 — 5종 CM)
**대상 알고리즘:** ML-KEM-768 (KEM) + ML-DSA-65 (서명) 양쪽

---

## 1. 작업1 — 성능 최적화 및 검증

### 1.1 Assembly 적용 현황

이미 트리에 적용돼 있던 부분:

| 파일 | 출처 | 비고 |
|---|---|---|
| `sc300/ntt.S` | 본 프로젝트 (ARMv7-M Thumb-2 NTT) | endian-safe, 모든 빌드 포함 |
| `vendor/pqm4-common/keccakf1600.S` | pqm4 (MIT/CC0) | LE 빌드 전용 |
| `vendor/mupq-common/keccakf1600.c` | pqm4 (이식성 fallback) | BE 빌드용 |

이번 단계에 새로 포팅한 부분 (pqm3 / Markus Krausz · `mupq/pqm3`, MIT/CC0):

| 파일 | 출처 | 적용 함수 | 비고 |
|---|---|---|---|
| `sc300_kem/kyber_kernels.S` | pqm3 `crypto_kem/kyber768/m3/{fastnttm3,fastinvnttm3,kyberm3}.S` | `ntt_fast_m3`, `invntt_fast_m3`, `pointwise_add/sub_m3`, `asm_barrett_reduce_m3`, `asm_frommont_m3`, `basemul_asm{,_acc}_m3`, `doublebasemul_asm{,_acc}_m3` | 순수 ARMv7-M (mul/mla/sxth/asr); pqm3 측정치 기준 ML-KEM keygen/enc/dec ≈ **+30%** |
| `sc300_kem/ntt.c` | 본 PR (pqm3 zetas 테이블 + asm 래퍼) | `PQCLEAN_MLKEM768_CLEAN_{ntt,invntt,zetas,zetas_asm,zetas_inv_asm,zetas_basemul,basemul}` | `ref_kem/ntt.c` 를 빌드에서 완전 대체 |
| `sc300/dilithium_kernels.S` | pqm3 `crypto_sign/dilithium2/m3/{pointwise_smull.S,vector.s}` | `PQCLEAN_MLDSA{44,65}_CLEAN_poly_pointwise_montgomery_asm`, `_poly_reduce_asm`, `_poly_caddq_asm` | 순수 ARMv7-M (smull/smlal/mul); pqm3 측정치 기준 ML-DSA verify ≈ **+30%**, sign 폴리곱 핫패스 단축 |

**참고:** pqm3 은 Cortex-M3 (no DSP) 전용 변종이다 (M4 변종은 별도의 `pqm4` 저장소).
이번 단계에서는 pqm3 의 어셈블리 중 SC300 (ARMv7-M base) 에서 그대로 동작하는 항목만 가져왔고, `smlad`/`pkhbt` 등 DSP-extension 의존 변종 (`ntt1_asm.S`, `intt_asm.S`, `pointwise_mul.S`)은 의도적으로 제외했다.

**ARMClang v6.22 호환성:** 어셈블리는 GAS 통합-호환 문법(`-mcpu=cortex-m3 -mthumb`)으로 작성되어 있으며, 기존 `sc300/ntt.S` 와 동일한 directive 집합 (`.syntax unified` / `.thumb` / `.thumb_func` / `.req` / `.set`-alias) 만 사용한다. 다중-라벨 함수 진입점은 `.set` 별칭으로 처리해 thumb-bit 마킹 결정성을 확보했다.

**C 측 라우팅 (-DMLDSA_SC300_ASM):**

- `ref/poly.c` 의 `MLDSA_NAMESPACE(poly_reduce)`, `_poly_caddq`, `_poly_pointwise_montgomery` 는 `MLDSA_SC300_ASM` 정의 시 1-라인 어셈블리 호출로 분기 (`#ifdef`) — 미정의 시 기존 reference C 루프로 fallback. 4 종 Makefile (`Makefile.gcc{,.lib}`, `Makefile.armclang{,.lib}`) 의 `CFLAGS` 모두 `-DMLDSA_SC300_ASM` 추가됨.
- ML-KEM 측은 `sc300_kem/ntt.c` 의 `PQCLEAN_MLKEM768_CLEAN_ntt` / `_invntt` 가 `ntt_fast_m3` / `invntt_fast_m3` 를 직접 extern-call → toggle flag 불필요 (어셈블리 경로가 항상 활성).

### 1.2 C 최적화 현황

`sc300_kem/indcpa.c` 의 streaming A-row 변형으로 KeyGen / Enc 의 stack peak 를 약 **6 KB** 감소시키는 최적화가 이미 적용돼 있다 (트리 기존 작업).

**버그 발견 / 수정 (이번 단계):** `Makefile.armclang` 의 ML-KEM-768 빌드 (`SRCS_C_KEM768`) 가 `ref_kem/indcpa.c` (스택-과다 reference) 를 가리키고 있어 streaming 최적화가 실제로 ARMClang 빌드에는 적용되지 않고 있었다. `sc300_kem/indcpa.c` 로 교체했다 (이미 `Makefile.gcc` / `sources.mk` 측에서는 정상 적용 중이었음).

본 PR 에서는 그 위에 CM 모듈을 추가하면서 추가 stack 증가가 11 KB 한계 안에 들도록 다음을 준수:

| 모듈 | Stack 추가 | 비고 |
|---|---|---|
| `cm_shuffling.c`     | 0 (지역 8 byte) | dummy_idx[8] 만 |
| `cm_masking.c`       | 128 byte 임시 buf | masked SHA3 chunk 버퍼 |
| `cm_parity.c`        | 8 byte | uint32 acc + count |
| `cm_integrity.c`     | 0 (호출 측 state) | inverse_addr 만 |
| `cm_rice_checksum.c` | 132 byte | 32×uint32 weights + seed |
| `sc300_kem/kem_cm.c` | ~3.3 KB peak | 기존 kem.c 와 동일 + 두 share 추가 |

**예상 ML-KEM Decaps peak (CM 5종 모두 활성)**: ~10.4 KB < 11 KB 한도.

### 1.3 검증

- ARMClang/GCC 컴파일 성공 여부는 **이 환경에서는 toolchain 부재로 직접 확인 불가**
- 정적 점검:
  - 모든 신규 헤더 가드 정합 확인 (`IMPL_SC300_*_H`)
  - `.c` ↔ `.h` prototype 일치 확인
  - `randombytes.h`, `fips202.h` 심볼 가용성 확인 (`vendor/mupq-common/`)
  - `sources.mk` 변수 정의 순서 정합 (`IMPL_SRCS_CM_C` 가 참조보다 먼저 정의됨)

---

## 2. 작업2 — Countermeasure 적용

### 2.1 모듈 구성

```
sc300/cm.h                        ← 단일 진입 헤더
sc300/cm_shuffling.{c,h}          ← CM 1: Fisher–Yates 인덱스 셔플
sc300/cm_masking.{c,h}            ← CM 2: 산술 + Boolean 마스킹, Masked_Enc/Sha3
sc300/cm_parity.{c,h}             ← CM 3: total_iter parity 누적 / 검증
sc300/cm_integrity.{c,h}          ← CM 4: inverse_address 무결성 누적
sc300/cm_rice_checksum.{c,h}      ← CM 5: DTRNG-가중 ciphertext 체크섬
sc300_kem/kem_cm.c                ← ML-KEM Decaps / KeyGen CM 진입점
api_wrapper.c                     ← ML-DSA 호출자 API 에 CM 후크 (수정)
api_wrapper_kem.c                 ← ML-KEM 호출자 API 에 CM 라우팅 (수정)
```

### 2.2 빌드 토글

`EXTRA_CFLAGS` 로 step 별 독립 활성:

```
EXTRA_CFLAGS="-DCM_SHUFFLING -DCM_MASKING -DCM_PARITY -DCM_INTEGRITY -DCM_RICE_CHECKSUM"
```

전부 비활성 (기본) 시 CM 함수는 inline identity 또는 단순 상수 반환으로 코드 생성 0 byte → 기존 KAT 100% 보존.

### 2.3 매핑 표

| Issue # | 기법 | ML-KEM-768 적용 위치 | ML-DSA-65 적용 위치 |
|---|---|---|---|
| 1 | Shuffling | (PoC) Decaps 진입 시 dummy index pass — secret-related polyvec 인덱스 비순차화는 추후 indcpa_dec 내 확장 가능 | `crypto_sign` 진입 시 dummy 8-원소 셔플 |
| 2 | Masking (m₀, m₁) | `kem_cm.c`: indcpa_dec 직후 m → (m₁, m₀); `cm_masked_sha3_512`(hash_g 대체); `cm_masked_indcpa_enc` (재암호화) | sk 의 K-필드는 기존 `MLDSA_MASK_RHOPRIME` 단계가 보호; CM 모듈은 sign 공정의 외곽 마스킹 emulation 만 제공 |
| 3 | Parity Check (total_iter) | `kem_cm.c`: `MLKEM_CM_TOTAL_ITER` 만큼 m₁ ⊕ m₀ word-XOR 누적 → 호출자에 반환 | `api_wrapper.c`: KeyGen 의 pk 파리티 누적 → `secret_parity`; Sign 시 sk 파리티 재계산해 일치 검사 |
| 4 | Integrity (inverse_address) | `cm_inverse_addr(&intg)` 를 indcpa_dec, indcpa_enc, verify 호출시점마다 누적 — 1+2+(rc+3) | `cm_inverse_addr(&intg)` 를 sign / verify 호출시점마다 누적, 호출자 측 inv_add 인자로도 전달 가능 |
| 5 | Rice Checksum | `kem_cm.c`: ct, cmp 양쪽에 32-원소 DTRNG-가중 XOR-checksum, constant-time compare | (해당 없음 — 서명에는 ciphertext 개념 없음) |

### 2.4 Decaps 의 m → (m₁, m₀) 흐름 (Issue 명시 사항)

```c
PQCLEAN_MLKEM768_CLEAN_indcpa_dec(m_local, ct, sk);   // 1) m 복원
cm_mask_bytes(m1, m0, m_local, 32);                    // 2) m1 = m ^ m0; m0 = DTRNG
memset(m_local, 0, 32);                                 // 3) m_local 즉시 소거
cm_masked_sha3_512(kr, buf1=m1||z, buf0=m0||0, 64);    // 4) hash_g 두-share 입력
cm_masked_indcpa_enc(cmp, m1, m0, pk, kr+32);          // 5) Enc 도 두-share 입력
```

→ CM_MASKING off 시 `cm_mask_bytes` 는 m_local 그대로 복사, `cm_masked_*` 는 표준 호출. 결과는 PQClean reference 와 byte-identical.

### 2.5 검증 결과

| 단계 | 검증 방법 | 결과 |
|---|---|---|
| 모듈 컴파일 (5종 .c) | 정적 prototype check | ✔ |
| `sources.mk` 변수 순서 | IMPL_SRCS_CM_C 정의 ≺ 참조 | ✔ |
| Makefile.gcc KEM 인클루드 경로 | `-I$(HERE)/sc300` 추가 | ✔ |
| Makefile.armclang KEM 인클루드 경로 | `-I$(HERE)/sc300 -I$(HERE)` 추가 | ✔ |
| Makefile.armclang DSA 소스 리스트 | CM 5종 추가 (44 / 65 양쪽) | ✔ |
| KEM 라이브러리 빌드 (`Makefile.gcc.lib`) | `IMPL_SRCS_LIB_KEM768_C` 가 `IMPL_SRCS_REF_KEM768` 포함 → CM .c 자동 포함 | ✔ |
| QEMU smoke (mldsa65) | toolchain 부재로 미실행 | ⚠ 보고 |
| QEMU smoke (mlkem768) | toolchain 부재로 미실행 | ⚠ 보고 |
| KAT 보존 (CM 모두 OFF) | 정적 검토 — `cm_*` 호출이 baseline 빌드에서 identity 임을 확인 | ✔ |

### 2.6 미실행 항목 (다음 단계 권장)

이 환경에서 검증하지 못한 항목 — 보드/툴체인이 있는 환경에서 다음 명령으로 확인 권장:

```bash
# 1) baseline (CM 전부 OFF) — 기존 KAT 보존 확인
make -f Makefile.gcc clean
make -f Makefile.gcc qemu_kem768
make -f Makefile.gcc qemu

# 2) CM 5종 전부 ON — KAT 일치 + CM-GATE PASS 확인
make -f Makefile.gcc clean
make -f Makefile.gcc qemu_kem768 \
     EXTRA_CFLAGS="-DCM_SHUFFLING -DCM_MASKING -DCM_PARITY -DCM_INTEGRITY -DCM_RICE_CHECKSUM"

# 3) ARMClang 빌드 (실제 SC300 환경)
make -f Makefile.armclang build_kem768 \
     EXTRA_CFLAGS="-DCM_SHUFFLING -DCM_MASKING -DCM_PARITY -DCM_INTEGRITY -DCM_RICE_CHECKSUM"
make -f Makefile.armclang qemu_kem768
```

기대 출력:
```
KAT-GATE: PASS (ACVP-style vectors): N
CM-GATE:  PASS (kem_decaps wrapper round-trip)
EXT-GATE: PASS (keygen/encaps/decaps round-trip OK)
```

---

## 3. 변경 파일 목록

신규:
- `sc300/cm.h`, `cm_shuffling.{c,h}`, `cm_masking.{c,h}`, `cm_parity.{c,h}`, `cm_integrity.{c,h}`, `cm_rice_checksum.{c,h}`
- `sc300_kem/kem_cm.c`
- `docs/CM_REPORT.md` (이 파일)

수정:
- `api_wrapper.c` (ML-DSA — KeyGen/Sign/Verify 에 CM 후크)
- `api_wrapper_kem.c` (ML-KEM — kem_decaps 에 CM 라우팅)
- `sources.mk` (`IMPL_SRCS_CM_C` 신설, `IMPL_SRCS_REF_KEM768`에 추가)
- `Makefile.gcc` (KEM `-I$(HERE)/sc300`, `api_wrapper_kem.c` 빌드 룰)
- `Makefile.armclang` (KEM/DSA CM 소스, 인클루드 경로)
- `test/test_mlkem768_main.c` (CM-GATE 라운드트립 추가)

기존 코드 호환성:
- 모든 `CM_*` 토글이 OFF 일 때 베이스라인과 byte-identical
- 기존 `MLDSA_MASK_*` 단계와 독립 — 두 메커니즘 병행 가능
- `api_wrapper.h` 의 ABI 변경 없음 (parameter name·order 동일)
