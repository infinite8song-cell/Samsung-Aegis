#ifndef MLDSA_NTT_H
#define MLDSA_NTT_H
#include "params.h"
#include <stdint.h>

void MLDSA_NAMESPACE(ntt)(int32_t a[N]);

void MLDSA_NAMESPACE(invntt_tomont)(int32_t a[N]);

#endif
