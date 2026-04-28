#ifndef MLDSA_REDUCE_H
#define MLDSA_REDUCE_H
#include "params.h"
#include <stdint.h>

#define MONT (-4186625) // 2^32 % Q
#define QINV 58728449 // q^(-1) mod 2^32

int32_t MLDSA_NAMESPACE(montgomery_reduce)(int64_t a);

int32_t MLDSA_NAMESPACE(reduce32)(int32_t a);

int32_t MLDSA_NAMESPACE(caddq)(int32_t a);

int32_t MLDSA_NAMESPACE(freeze)(int32_t a);

#endif
