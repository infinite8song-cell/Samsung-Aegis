/* Minimal freestanding stdlib.h for ARM Cortex-M bare-metal builds. */
#ifndef _STDLIB_H
#define _STDLIB_H

#include <stddef.h>

void abort(void);
void exit(int status);

#endif /* _STDLIB_H */
