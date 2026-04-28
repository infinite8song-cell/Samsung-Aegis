/*
 * hal_m3.c — MPS2 AN385 HAL for Cortex-M3 / SC300 (impl_sc300)
 *
 * Implements the mupq HAL interface (see mupq/common/hal.h) for the
 * impl_sc300 fresh ML-DSA-65 port. No FPU, no DSP, ARMv7-M Thumb-2 only.
 *
 * Stack measurement here is a canary-buffer probe suitable for S0
 * (SHAKE256 KAT). Later phases will switch to a heap_end-based
 * watermark that matches the plan's 10 KB sign-stack budget.
 */

#include "hal.h"
#include <CMSDK_CM3.h>

#define BAUD             38400u
#ifndef SYSTEM_CLOCK
#define SYSTEM_CLOCK     25000000UL
#endif

/* ------------------------------------------------------------------ */
/* Called by Reset_Handler before main(). Brings up UART0 + SysTick.  */
/* ------------------------------------------------------------------ */
void SystemInit(void)
{
    /* UART0 alternate function on GPIO0 pins 0 and 1 */
    CMSDK_GPIO0->ALTFUNCSET |= 1u;
    CMSDK_GPIO0->ALTFUNCSET |= 2u;

    /* UART0 baud + TX/RX enable */
    CMSDK_UART0->BAUDDIV = SYSTEM_CLOCK / BAUD;
    CMSDK_UART0->CTRL   |= (1u << CMSDK_UART_CTRL_RXEN_Pos);
    CMSDK_UART0->CTRL   |= (1u << CMSDK_UART_CTRL_TXEN_Pos);

    /* 24-bit free-running SysTick for hal_get_time() */
    SysTick->LOAD = 0x00FFFFFFu;
    SysTick->VAL  = 0u;
    SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;
}

/* ------------------------------------------------------------------ */
/* hal_setup                                                           */
/* ------------------------------------------------------------------ */
void hal_setup(const enum clock_mode clock)
{
    (void)clock;  /* single fixed clock on QEMU mps2-an385 */
}

/* ------------------------------------------------------------------ */
/* UART output                                                         */
/* ------------------------------------------------------------------ */
static void uart_tx_char(char c)
{
    while (CMSDK_UART0->STATE & CMSDK_UART_STATE_TXBF_Msk) {
        /* TX FIFO full — spin */
    }
    CMSDK_UART0->DATA = (uint32_t)(unsigned char)c;
}

void hal_send_str(const char *s)
{
    while (*s) {
        uart_tx_char(*s++);
    }
    uart_tx_char('\n');
}

/* ------------------------------------------------------------------ */
/* Cycle counter (SysTick reconstruction)                              */
/* ------------------------------------------------------------------ */
uint64_t hal_get_time(void)
{
    static uint64_t overflow_count = 0;
    static uint32_t last_val       = 0;
    uint32_t val = SysTick->VAL;
    if (val > last_val) {
        overflow_count++;
    }
    last_val = val;
    return (overflow_count << 24) | (0x00FFFFFFu - val);
}

/* ------------------------------------------------------------------ */
/* Stack measurement — SP-relative watermark probe.                    */
/*                                                                     */
/* Previous approach used a BSS array as canary, but BSS lives near   */
/* the bottom of RAM while the stack grows down from the top of RAM   */
/* (StackTop = 0x20400000 on MPS2 AN385 4 MB SRAM). They never        */
/* overlap, so hal_checkstack() always returned 0.                     */
/*                                                                     */
/* Fix: read SP at spray time and fill the 32 KB region immediately   */
/* below that address. The function under test will consume stack from  */
/* that region downward. hal_checkstack() scans upward from the spray  */
/* base to find the lowest address touched.                            */
/* ------------------------------------------------------------------ */
#define HAL_STACK_CANARY_SIZE  0x8000u       /* 32 KiB — covers 11 KB sign depth */
#define HAL_STACK_CANARY_BYTE  ((uint8_t)0xA5)

static uintptr_t spray_base;

size_t hal_get_stack_size(void)
{
    return (size_t)HAL_STACK_CANARY_SIZE;
}

void hal_spraystack(void)
{
    uint32_t sp;
    __asm volatile ("mov %0, sp" : "=r" (sp));
    spray_base = (uintptr_t)(sp - HAL_STACK_CANARY_SIZE);
    volatile uint8_t *p = (volatile uint8_t *)spray_base;
    for (size_t i = 0; i < HAL_STACK_CANARY_SIZE; i++)
        p[i] = HAL_STACK_CANARY_BYTE;
}

size_t hal_checkstack(void)
{
    volatile uint8_t *p = (volatile uint8_t *)spray_base;
    /* Scan from the bottom of the spray region upward.
     * First non-canary byte = deepest stack address used.
     * Depth = distance from that address to the top of the spray region. */
    for (size_t i = 0; i < HAL_STACK_CANARY_SIZE; i++) {
        if (p[i] != HAL_STACK_CANARY_BYTE)
            return (size_t)(HAL_STACK_CANARY_SIZE - i);
    }
    return 0;  /* entire region untouched — increase HAL_STACK_CANARY_SIZE */
}
