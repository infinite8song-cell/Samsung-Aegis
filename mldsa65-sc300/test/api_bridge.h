/*
 * api_bridge.h — short aliases for the test harness.
 * CRYPTO_* constants come from params.h via api.h.
 */
#ifndef IMPL_SC300_API_BRIDGE_H
#define IMPL_SC300_API_BRIDGE_H

#include "api.h"

/* Short function name aliases (context-less = NULL ctx). */
#define crypto_sign_keypair MLDSA_NAMESPACE(crypto_sign_keypair)

#define crypto_sign(sm, smlen, m, mlen, sk) \
    MLDSA_NAMESPACE(crypto_sign_ctx)(sm, smlen, m, mlen, NULL, 0, sk)

#define crypto_sign_open(m, mlen, sm, smlen, pk) \
    MLDSA_NAMESPACE(crypto_sign_open_ctx)(m, mlen, sm, smlen, NULL, 0, pk)

#endif
