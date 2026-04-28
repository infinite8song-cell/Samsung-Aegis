#ifndef PQCLEAN_RANDOMBYTES_H
#define PQCLEAN_RANDOMBYTES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#ifdef _WIN32
/* Load size_t on windows */
#include <crtdefs.h>
#elif defined(__arm__) || defined(__ARM_ARCH)
/* Bare-metal ARM: unistd.h unavailable, size_t comes from stddef.h */
#include <stddef.h>
#else
#include <unistd.h>
#endif /* _WIN32 */

/*
 * Write `n` bytes of high quality random bytes to `buf`
 *
 * The library calls the bare 'randombytes' symbol; the caller must
 * provide it (see api_wrapper.h quick-start).  (The PQClean build
 * system aliases this to PQCLEAN_randombytes via a macro, but we
 * link against caller-supplied randombytes directly.)
 */
int randombytes(uint8_t *output, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* PQCLEAN_RANDOMBYTES_H */
