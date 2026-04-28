/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/cm_integrity.h — Inverse-address integrity check CM
 *                         (Issue #5, 작업2-4)
 *
 *   "특정 변수를 생성해 함수 수행 시마다 리턴값을 누적. 함수 입력으로
 *    해당 변수의 Inverse_address 를 대입하여 내부 무결성을 체크하라."
 *
 * 의도:
 *   호출 측: cm_integrity_state s = {0};
 *           PROTECTED_FN(args, cm_inverse_addr(&s.acc));
 *           PROTECTED_FN(args, cm_inverse_addr(&s.acc));
 *           if (!cm_integrity_verify(&s, expected)) fault();
 *
 *   내부:   PROTECTED_FN(... uintptr_t inv) {
 *               uint32_t *p = (uint32_t *)cm_invert_addr(inv);
 *               *p ^= return_value;
 *               ...
 *           }
 *
 *  포인터 자체는 함수 인자로 직접 전달되지 않고 inverse 변환을 거쳐
 *  내부에서 복원됨으로써 fault-injection 시 변조 탐지를 강화한다.
 */
#ifndef IMPL_SC300_CM_INTEGRITY_H
#define IMPL_SC300_CM_INTEGRITY_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t acc;
    uint32_t count;
} cm_integrity_state;

/* canonical inverse: bitwise NOT of the address (architecture-agnostic).  */
static inline uintptr_t cm_inverse_addr(volatile void *p)
{
    return (uintptr_t)~(uintptr_t)p;
}

static inline void *cm_revert_addr(uintptr_t inv)
{
    return (void *)(uintptr_t)(~inv);
}

void cm_integrity_init  (cm_integrity_state *s);

/* 보호 함수에서 사용: cm_integrity_record(inv, ret_value)
 * inv 는 cm_inverse_addr(&state.acc) 의 결과.                      */
void cm_integrity_record(uintptr_t inv, uint32_t ret_value);

/* 누적 결과를 외부에서 검증. CM_INTEGRITY OFF 시 항상 1.            */
int  cm_integrity_verify(const cm_integrity_state *s, uint32_t expected);

#endif /* IMPL_SC300_CM_INTEGRITY_H */
