#ifndef MLDSA_PACKING_H
#define MLDSA_PACKING_H
#include "params.h"
#include "polyvec.h"
#include <stdint.h>

void MLDSA_NAMESPACE(pack_pk)(uint8_t pk[CRYPTO_PUBLICKEYBYTES], const uint8_t rho[SEEDBYTES], const polyveck *t1);

void MLDSA_NAMESPACE(pack_sk)(uint8_t sk[CRYPTO_SECRETKEYBYTES],
                                   const uint8_t rho[SEEDBYTES],
                                   const uint8_t tr[TRBYTES],
                                   const uint8_t key[SEEDBYTES],
                                   const polyveck *t0,
                                   const polyvecl *s1,
                                   const polyveck *s2);

void MLDSA_NAMESPACE(pack_sig)(uint8_t sig[CRYPTO_BYTES], const uint8_t c[CTILDEBYTES], const polyvecl *z, const polyveck *h);

void MLDSA_NAMESPACE(unpack_pk)(uint8_t rho[SEEDBYTES], polyveck *t1, const uint8_t pk[CRYPTO_PUBLICKEYBYTES]);

void MLDSA_NAMESPACE(unpack_sk)(uint8_t rho[SEEDBYTES],
                                     uint8_t tr[TRBYTES],
                                     uint8_t key[SEEDBYTES],
                                     polyveck *t0,
                                     polyvecl *s1,
                                     polyveck *s2,
                                     const uint8_t sk[CRYPTO_SECRETKEYBYTES]);

int MLDSA_NAMESPACE(unpack_sig)(uint8_t c[CTILDEBYTES], polyvecl *z, polyveck *h, const uint8_t sig[CRYPTO_BYTES]);

#endif /* MLDSA_PACKING_H */
