#ifndef MLDSA_PARAMS_H
#define MLDSA_PARAMS_H

/* Compile-time parameter set: -DMLDSA_MODE=44 or 65 (default 65) */
#ifndef MLDSA_MODE
#define MLDSA_MODE 65
#endif

#if MLDSA_MODE == 44
#  define MLDSA_NAMESPACE(x) PQCLEAN_MLDSA44_CLEAN_##x
#elif MLDSA_MODE == 65
#  define MLDSA_NAMESPACE(x) PQCLEAN_MLDSA65_CLEAN_##x
#else
#  error "MLDSA_MODE must be 44 or 65"
#endif

/* Common parameters */
#define SEEDBYTES      32
#define CRHBYTES       64
#define TRBYTES        64
#define RNDBYTES       32
#define N             256
#define Q         8380417
#define D              13
#define ROOT_OF_UNITY 1753

/* Parameter-set-specific */
#if MLDSA_MODE == 44
#  define K               4
#  define L               4
#  define ETA             2
#  define TAU            39
#  define BETA           78
#  define GAMMA1         (1 << 17)
#  define GAMMA2         ((Q-1)/88)
#  define OMEGA          80
#  define CTILDEBYTES    32
#  define POLYZ_PACKEDBYTES    576
#  define POLYW1_PACKEDBYTES   192
#  define POLYETA_PACKEDBYTES   96
#else  /* ML-DSA-65 */
#  define K               6
#  define L               5
#  define ETA             4
#  define TAU            49
#  define BETA          196
#  define GAMMA1         (1 << 19)
#  define GAMMA2         ((Q-1)/32)
#  define OMEGA          55
#  define CTILDEBYTES    48
#  define POLYZ_PACKEDBYTES    640
#  define POLYW1_PACKEDBYTES   128
#  define POLYETA_PACKEDBYTES  128
#endif

/* Derived sizes (same formula for all parameter sets) */
#define POLYT1_PACKEDBYTES   320
#define POLYT0_PACKEDBYTES   416
#define POLYVECH_PACKEDBYTES (OMEGA + K)

/* Canonical key/sig sizes (computed from params above) */
#define CRYPTO_PUBLICKEYBYTES \
    (SEEDBYTES + K * POLYT1_PACKEDBYTES)
#define CRYPTO_SECRETKEYBYTES \
    (2*SEEDBYTES + TRBYTES \
     + L*POLYETA_PACKEDBYTES \
     + K*POLYETA_PACKEDBYTES \
     + K*POLYT0_PACKEDBYTES)
#define CRYPTO_BYTES \
    (CTILDEBYTES + L*POLYZ_PACKEDBYTES + POLYVECH_PACKEDBYTES)

#endif /* MLDSA_PARAMS_H */
