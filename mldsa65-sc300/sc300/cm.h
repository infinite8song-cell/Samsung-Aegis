/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/cm.h — Countermeasure (CM) integration header (ML-KEM/ML-DSA).
 *
 * Issue Samsung-Aegis #5 의 5 가지 CM 기법을 양 알고리즘에 공통으로 적용
 * 하기 위한 단일 진입 헤더.  각 모듈은 독립 토글로 빌드된다.
 *
 *   CM_SHUFFLING       : 비순차 인덱스 배열 기반 secret op
 *   CM_MASKING         : 산술 마스크 (덧/뺄/곱) 적용·해제 헬퍼
 *   CM_PARITY          : KeyGen / Decaps total_iter parity check
 *   CM_INTEGRITY       : inverse_address 누적 무결성 체크
 *   CM_RICE_CHECKSUM   : ML-KEM Dec 에서 c, c' DTRNG-가중 체크섬 비교
 *
 * 모든 CM 은 baseline (define 없음) 시 코드 생성 0 byte 가 되도록
 * static inline + #if 가드로 작성됐다.  EXTRA_CFLAGS 로 step 별 토글:
 *
 *     -DCM_SHUFFLING            -DCM_MASKING
 *     -DCM_PARITY               -DCM_INTEGRITY
 *     -DCM_RICE_CHECKSUM
 *
 * ALL_CMS = -DCM_SHUFFLING -DCM_MASKING -DCM_PARITY -DCM_INTEGRITY -DCM_RICE_CHECKSUM
 */
#ifndef IMPL_SC300_CM_H
#define IMPL_SC300_CM_H

#include <stdint.h>
#include <stddef.h>

#include "cm_shuffling.h"
#include "cm_masking.h"
#include "cm_parity.h"
#include "cm_integrity.h"
#include "cm_rice_checksum.h"

#endif /* IMPL_SC300_CM_H */
