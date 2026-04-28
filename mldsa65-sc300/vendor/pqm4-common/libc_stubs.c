/* libc_stubs.c — minimal C library stubs for bare-metal ARM builds.
 *
 * Provides memcpy/memset/memcmp without including system headers so
 * this file compiles even with stripped-down ARM toolchains that lack
 * stddef.h / stdint.h (e.g. arm-gnu-toolchain-13.3 on macOS).
 */
typedef unsigned long  size_t;
typedef unsigned char  uint8_t;

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t       *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;
    while (n--) *p++ = (uint8_t)c;
    return s;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *a = (const uint8_t *)s1;
    const uint8_t *b = (const uint8_t *)s2;
    while (n--) {
        if (*a != *b) return (int)*a - (int)*b;
        a++; b++;
    }
    return 0;
}
