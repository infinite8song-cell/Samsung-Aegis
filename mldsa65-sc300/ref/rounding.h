#ifndef MLDSA_ROUNDING_H
#define MLDSA_ROUNDING_H
#include "params.h"
#include <stdint.h>

int32_t MLDSA_NAMESPACE(power2round)(int32_t *a0, int32_t a);

int32_t MLDSA_NAMESPACE(decompose)(int32_t *a0, int32_t a);

unsigned int MLDSA_NAMESPACE(make_hint)(int32_t a0, int32_t a1);

int32_t MLDSA_NAMESPACE(use_hint)(int32_t a, unsigned int hint);

#endif
