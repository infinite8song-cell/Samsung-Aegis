/* SPDX-License-Identifier: Apache-2.0 or CC0-1.0
 * sc300/cm_integrity.c — Inverse-address integrity (Issue #5, 작업2-4) */

#include "cm_integrity.h"

void cm_integrity_init(cm_integrity_state *s)
{
    s->acc   = 0u;
    s->count = 0u;
}

void cm_integrity_record(uintptr_t inv, uint32_t ret_value)
{
#if defined(CM_INTEGRITY)
    cm_integrity_state *p = (cm_integrity_state *)cm_revert_addr(inv);
    p->acc   += ret_value;          /* 곱셈 분포보다 덧셈 분포가 충돌 적음 */
    p->count += 1u;
#else
    (void)inv; (void)ret_value;
#endif
}

int cm_integrity_verify(const cm_integrity_state *s, uint32_t expected)
{
#if defined(CM_INTEGRITY)
    return (s->acc == expected) ? 1 : 0;
#else
    (void)s; (void)expected;
    return 1;
#endif
}
