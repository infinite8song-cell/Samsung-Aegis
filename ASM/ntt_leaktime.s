; -----------------------------------------------------------------------------
; ntt_leaktime.s
;
; Port of pqm3 crypto_sign/dilithium2/m3/ntt_leaktime.S (GNU `as`,
; Thumb-2 UAL) to ARM Compiler v5.06 `armasm` syntax, targeting an SC300
; (Cortex-M3 / ARMv7-M) core.  Forward and inverse Dilithium NTT using
; the SMULL/SMLAL 32x32->64 long-multiply path.
;
; Author credit preserved from upstream:
;   author: Markus Krausz, date: 18.03.18
;   GPL v3 or later — see upstream for license text.
;
; Register binding (inline-expanded from the original .req tables;
; identical for both functions):
;   r0  = ptr_p     r1  = ptr_zeta (reused as f in inv stage 7/8)
;   r2  = qinv      r3  = q        r4  = cntr
;   r5  = pol0      r6  = pol1     r7  = pol2    r8  = pol3
;   r9  = temp_h    r10 = temp_l
;   r11 = zeta0     r12 = zeta1    r14 = zeta2
;
; Source upstream: https://github.com/mupq/pqm3
; -----------------------------------------------------------------------------

        PRESERVE8
        THUMB

        AREA    |.text|, CODE, READONLY

; =============================================================================
; Macros
; =============================================================================

; Cooley-Tukey butterfly with Montgomery reduction — SIGNED
        MACRO
        ct_butterfly_montg $pol0, $pol1, $zeta, $q, $qinv, $th, $tl
        smull   $tl, $th, $pol1, $zeta
        mul     $pol1, $tl, $qinv                   ; qinv is -qinv
        smlal   $tl, $th, $pol1, $q
        sub     $pol1, $pol0, $th
        add.w   $pol0, $pol0, $th
        MEND

; Gentleman-Sande butterfly with Montgomery reduction — SIGNED
        MACRO
        gs_butterfly_montg $pol0, $pol1, $zeta, $q, $qinv, $x, $y
        sub     $x, $pol0, $pol1
        add.w   $pol0, $pol0, $pol1
        smull   $y, $pol1, $x, $zeta
        mul     $x, $y, $qinv                       ; qinv is -qinv
        smlal   $y, $pol1, $x, $q
        MEND

; Standalone Montgomery reduction with constant f — SIGNED
        MACRO
        montg_red $f, $pol, $q, $qinv, $x, $y
        smull   $y, $pol, $pol, $f
        mul     $x, $y, $qinv                       ; qinv is -qinv
        smlal   $y, $pol, $x, $q
        MEND

; =============================================================================
; void ntt_asm_smull(int32_t p[N], const uint32_t zetas_asm[N]);
; =============================================================================
        ALIGN   4
        EXPORT  ntt_asm_smull
ntt_asm_smull PROC
        push    {r4-r11, r14}
        add     r1, #4                              ; &zeta[1]

        ldr.w   r2, ntt_leaktime_qinv               ; -qinv_signed
        ldr.w   r3, ntt_leaktime_q

        ; --- stage 1 and 2 ---
        ldr.w   r4, ntt_leaktime_64                 ; cntr = 64

        ldr     r12, [r1, #4]                       ; z2
        ldr     r14, [r1, #8]                       ; z3
        ldr     r11, [r1], #12                      ; z1
ntt_smull_L1
        ldr.w   r5, [r0]
        ldr     r6, [r0, #256]                      ; 64*4
        ldr     r7, [r0, #512]                      ; 128*4
        ldr     r8, [r0, #768]                      ; 192*4
        ct_butterfly_montg r5, r7, r11, r3, r2, r9, r10    ; stage1
        ct_butterfly_montg r6, r8, r11, r3, r2, r9, r10    ; stage1
        ct_butterfly_montg r5, r6, r12, r3, r2, r9, r10    ; stage2
        ct_butterfly_montg r7, r8, r14, r3, r2, r9, r10    ; stage2

        str     r6, [r0, #256]
        str     r7, [r0, #512]
        str     r8, [r0, #768]
        str     r5, [r0], #4
        subs    r4, #1
        bne     ntt_smull_L1
        sub     r0, #256                            ; back on pol0

        ; --- stage 3 and 4 (four groups of 16) ---
        movw    r4, #16
        ldr     r12, [r1, #4]                       ; z8
        ldr     r14, [r1, #8]                       ; z9
        ldr     r11, [r1], #12                      ; z4
ntt_smull_L2
        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #64]
        ldr.w   r7, [r0, #128]
        ldr.w   r8, [r0, #192]
        ct_butterfly_montg r5, r7, r11, r3, r2, r9, r10    ; stage3
        ct_butterfly_montg r6, r8, r11, r3, r2, r9, r10    ; stage3
        ct_butterfly_montg r5, r6, r12, r3, r2, r9, r10    ; stage4
        ct_butterfly_montg r7, r8, r14, r3, r2, r9, r10    ; stage4

        str.w   r6, [r0, #64]
        str.w   r7, [r0, #128]
        str.w   r8, [r0, #192]
        str     r5, [r0], #4
        subs    r4, #1
        bne     ntt_smull_L2
        add.w   r0, r0, #192                        ; (64-16)*4

        movw    r4, #16
        ldr     r12, [r1, #4]                       ; z10
        ldr     r14, [r1, #8]                       ; z11
        ldr     r11, [r1], #12                      ; z5
ntt_smull_L3
        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #64]
        ldr.w   r7, [r0, #128]
        ldr.w   r8, [r0, #192]
        ct_butterfly_montg r5, r7, r11, r3, r2, r9, r10
        ct_butterfly_montg r6, r8, r11, r3, r2, r9, r10
        ct_butterfly_montg r5, r6, r12, r3, r2, r9, r10
        ct_butterfly_montg r7, r8, r14, r3, r2, r9, r10

        str.w   r6, [r0, #64]
        str.w   r7, [r0, #128]
        str.w   r8, [r0, #192]
        str     r5, [r0], #4
        subs    r4, #1
        bne     ntt_smull_L3
        add     r0, r0, #192

        movw    r4, #16
        ldr.w   r12, [r1, #4]                       ; z12
        ldr.w   r14, [r1, #8]                       ; z13
        ldr     r11, [r1], #12                      ; z6
ntt_smull_L4
        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #64]
        ldr.w   r7, [r0, #128]
        ldr.w   r8, [r0, #192]
        ct_butterfly_montg r5, r7, r11, r3, r2, r9, r10
        ct_butterfly_montg r6, r8, r11, r3, r2, r9, r10
        ct_butterfly_montg r5, r6, r12, r3, r2, r9, r10
        ct_butterfly_montg r7, r8, r14, r3, r2, r9, r10
        str.w   r6, [r0, #64]
        str.w   r7, [r0, #128]
        str.w   r8, [r0, #192]
        str     r5, [r0], #4
        subs    r4, #1
        bne     ntt_smull_L4
        add     r0, #192

        movw    r4, #16
        ldr.w   r12, [r1, #4]                       ; z14
        ldr.w   r14, [r1, #8]                       ; z15
        ldr     r11, [r1], #12                      ; z7
ntt_smull_L5
        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #64]
        ldr.w   r7, [r0, #128]
        ldr.w   r8, [r0, #192]
        ct_butterfly_montg r5, r7, r11, r3, r2, r9, r10
        ct_butterfly_montg r6, r8, r11, r3, r2, r9, r10
        ct_butterfly_montg r5, r6, r12, r3, r2, r9, r10
        ct_butterfly_montg r7, r8, r14, r3, r2, r9, r10
        str.w   r6, [r0, #64]
        str.w   r7, [r0, #128]
        str.w   r8, [r0, #192]
        str     r5, [r0], #4
        subs    r4, #1
        bne     ntt_smull_L5
        sub     r0, #832                            ; 208*4

        ; --- stage 5 and 6 ---
        movw    r4, #16
ntt_smull_L6
        ldr.w   r12, [r1, #4]                       ; z32..z62
        ldr.w   r14, [r1, #8]                       ; z33..z63
        ldr     r11, [r1], #12                      ; z16..z31

        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #16]
        ldr.w   r7, [r0, #32]
        ldr.w   r8, [r0, #48]
        ct_butterfly_montg r5, r7, r11, r3, r2, r9, r10
        ct_butterfly_montg r6, r8, r11, r3, r2, r9, r10
        ct_butterfly_montg r5, r6, r12, r3, r2, r9, r10
        ct_butterfly_montg r7, r8, r14, r3, r2, r9, r10

        str.w   r6, [r0, #16]
        str.w   r7, [r0, #32]
        str.w   r8, [r0, #48]
        str     r5, [r0], #4

        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #16]
        ldr.w   r7, [r0, #32]
        ldr.w   r8, [r0, #48]
        ct_butterfly_montg r5, r7, r11, r3, r2, r9, r10
        ct_butterfly_montg r6, r8, r11, r3, r2, r9, r10
        ct_butterfly_montg r5, r6, r12, r3, r2, r9, r10
        ct_butterfly_montg r7, r8, r14, r3, r2, r9, r10

        str.w   r6, [r0, #16]
        str.w   r7, [r0, #32]
        str.w   r8, [r0, #48]
        str     r5, [r0], #4

        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #16]
        ldr.w   r7, [r0, #32]
        ldr.w   r8, [r0, #48]
        ct_butterfly_montg r5, r7, r11, r3, r2, r9, r10
        ct_butterfly_montg r6, r8, r11, r3, r2, r9, r10
        ct_butterfly_montg r5, r6, r12, r3, r2, r9, r10
        ct_butterfly_montg r7, r8, r14, r3, r2, r9, r10

        str.w   r6, [r0, #16]
        str.w   r7, [r0, #32]
        str.w   r8, [r0, #48]
        str     r5, [r0], #4

        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #16]
        ldr.w   r7, [r0, #32]
        ldr.w   r8, [r0, #48]
        ct_butterfly_montg r5, r7, r11, r3, r2, r9, r10
        ct_butterfly_montg r6, r8, r11, r3, r2, r9, r10
        ct_butterfly_montg r5, r6, r12, r3, r2, r9, r10
        ct_butterfly_montg r7, r8, r14, r3, r2, r9, r10

        str.w   r6, [r0, #16]
        str.w   r7, [r0, #32]
        str.w   r8, [r0, #48]
        str     r5, [r0], #52

        subs.w  r4, r4, #1
        bne     ntt_smull_L6
        sub     r0, #1024

        ; --- stage 7 and 8 ---
        mov     r4, #64
ntt_smull_L7
        ldr.w   r12, [r1, #4]                       ; z128..z254
        ldr.w   r14, [r1, #8]                       ; z129..z255
        ldr     r11, [r1], #12                      ; z64..z127
        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #4]
        ldr.w   r7, [r0, #8]
        ldr.w   r8, [r0, #12]
        ct_butterfly_montg r5, r7, r11, r3, r2, r9, r10
        ct_butterfly_montg r6, r8, r11, r3, r2, r9, r10
        ct_butterfly_montg r5, r6, r12, r3, r2, r9, r10
        ct_butterfly_montg r7, r8, r14, r3, r2, r9, r10

        str.w   r6, [r0, #4]
        str.w   r7, [r0, #8]
        str.w   r8, [r0, #12]
        str     r5, [r0], #16
        subs    r4, #1
        bne     ntt_smull_L7

        pop     {r4-r11, pc}
        ENDP

; =============================================================================
; void inv_ntt_asm_smull(int32_t p[N], const uint32_t zetas_inv_asm[N]);
; =============================================================================
        ALIGN   4
        EXPORT  inv_ntt_asm_smull
inv_ntt_asm_smull PROC
        push    {r4-r11, r14}
        ldr.w   r2, ntt_leaktime_qinv               ; -qinv_signed
        ldr.w   r3, ntt_leaktime_q

        ; --- stage 1 and 2 ---
        ldr.w   r4, ntt_leaktime_64                 ; cntr = 64
invntt_smull_L1
        ldr.w   r12, [r1, #4]                       ; z1..z127
        ldr.w   r14, [r1, #8]                       ; z128..z191
        ldr     r11, [r1], #12                      ; z0..z126
        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #4]
        ldr.w   r7, [r0, #8]
        ldr.w   r8, [r0, #12]
        gs_butterfly_montg r5, r6, r11, r3, r2, r9, r10    ; stage1
        gs_butterfly_montg r7, r8, r12, r3, r2, r9, r10    ; stage1
        gs_butterfly_montg r5, r7, r14, r3, r2, r9, r10    ; stage2
        gs_butterfly_montg r6, r8, r14, r3, r2, r9, r10    ; stage2
        str.w   r6, [r0, #4]
        str.w   r7, [r0, #8]
        str.w   r8, [r0, #12]
        str     r5, [r0], #16
        subs    r4, #1
        bne     invntt_smull_L1
        sub     r0, #1024                           ; on pol0 again

        ; --- stage 3 and 4 (unrolled 4x inside) ---
        movw    r4, #16
invntt_smull_L2
        ldr.w   r12, [r1, #4]
        ldr.w   r14, [r1, #8]
        ldr     r11, [r1], #12

        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #16]
        ldr.w   r7, [r0, #32]
        ldr.w   r8, [r0, #48]
        gs_butterfly_montg r5, r6, r11, r3, r2, r9, r10
        gs_butterfly_montg r7, r8, r12, r3, r2, r9, r10
        gs_butterfly_montg r5, r7, r14, r3, r2, r9, r10
        gs_butterfly_montg r6, r8, r14, r3, r2, r9, r10

        str.w   r6, [r0, #16]
        str.w   r7, [r0, #32]
        str.w   r8, [r0, #48]
        str     r5, [r0], #4

        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #16]
        ldr.w   r7, [r0, #32]
        ldr.w   r8, [r0, #48]
        gs_butterfly_montg r5, r6, r11, r3, r2, r9, r10
        gs_butterfly_montg r7, r8, r12, r3, r2, r9, r10
        gs_butterfly_montg r5, r7, r14, r3, r2, r9, r10
        gs_butterfly_montg r6, r8, r14, r3, r2, r9, r10

        str.w   r6, [r0, #16]
        str.w   r7, [r0, #32]
        str.w   r8, [r0, #48]
        str     r5, [r0], #4

        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #16]
        ldr.w   r7, [r0, #32]
        ldr.w   r8, [r0, #48]
        gs_butterfly_montg r5, r6, r11, r3, r2, r9, r10
        gs_butterfly_montg r7, r8, r12, r3, r2, r9, r10
        gs_butterfly_montg r5, r7, r14, r3, r2, r9, r10
        gs_butterfly_montg r6, r8, r14, r3, r2, r9, r10

        str.w   r6, [r0, #16]
        str.w   r7, [r0, #32]
        str.w   r8, [r0, #48]
        str     r5, [r0], #4

        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #16]
        ldr.w   r7, [r0, #32]
        ldr.w   r8, [r0, #48]
        gs_butterfly_montg r5, r6, r11, r3, r2, r9, r10
        gs_butterfly_montg r7, r8, r12, r3, r2, r9, r10
        gs_butterfly_montg r5, r7, r14, r3, r2, r9, r10
        gs_butterfly_montg r6, r8, r14, r3, r2, r9, r10
        str.w   r6, [r0, #16]
        str.w   r7, [r0, #32]
        str.w   r8, [r0, #48]
        str     r5, [r0], #52
        subs.w  r4, r4, #1
        bne     invntt_smull_L2
        sub     r0, #1024

        ; --- stage 5 and 6 (four groups of 16) ---
        movw    r4, #16
        ldr.w   r12, [r1, #4]
        ldr.w   r14, [r1, #8]
        ldr     r11, [r1], #12
invntt_smull_L3
        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #64]
        ldr.w   r7, [r0, #128]
        ldr.w   r8, [r0, #192]
        gs_butterfly_montg r5, r6, r11, r3, r2, r9, r10
        gs_butterfly_montg r7, r8, r12, r3, r2, r9, r10
        gs_butterfly_montg r5, r7, r14, r3, r2, r9, r10
        gs_butterfly_montg r6, r8, r14, r3, r2, r9, r10

        str.w   r6, [r0, #64]
        str.w   r7, [r0, #128]
        str.w   r8, [r0, #192]
        str     r5, [r0], #4
        subs    r4, #1
        bne     invntt_smull_L3
        add     r0, #192

        movw    r4, #16
        ldr.w   r12, [r1, #4]
        ldr.w   r14, [r1, #8]
        ldr     r11, [r1], #12
invntt_smull_L4
        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #64]
        ldr.w   r7, [r0, #128]
        ldr.w   r8, [r0, #192]
        gs_butterfly_montg r5, r6, r11, r3, r2, r9, r10
        gs_butterfly_montg r7, r8, r12, r3, r2, r9, r10
        gs_butterfly_montg r5, r7, r14, r3, r2, r9, r10
        gs_butterfly_montg r6, r8, r14, r3, r2, r9, r10
        str.w   r6, [r0, #64]
        str.w   r7, [r0, #128]
        str.w   r8, [r0, #192]
        str     r5, [r0], #4
        subs    r4, #1
        bne     invntt_smull_L4
        add.w   r0, r0, #192

        movw    r4, #16
        ldr.w   r12, [r1, #4]
        ldr.w   r14, [r1, #8]
        ldr     r11, [r1], #12
invntt_smull_L5
        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #64]
        ldr.w   r7, [r0, #128]
        ldr.w   r8, [r0, #192]
        gs_butterfly_montg r5, r6, r11, r3, r2, r9, r10
        gs_butterfly_montg r7, r8, r12, r3, r2, r9, r10
        gs_butterfly_montg r5, r7, r14, r3, r2, r9, r10
        gs_butterfly_montg r6, r8, r14, r3, r2, r9, r10
        str.w   r6, [r0, #64]
        str.w   r7, [r0, #128]
        str.w   r8, [r0, #192]
        str     r5, [r0], #4
        subs    r4, #1
        bne     invntt_smull_L5
        add     r0, #192

        movw    r4, #16
        ldr.w   r12, [r1, #4]
        ldr.w   r14, [r1, #8]
        ldr     r11, [r1], #12
invntt_smull_L6
        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #64]
        ldr.w   r7, [r0, #128]
        ldr.w   r8, [r0, #192]
        gs_butterfly_montg r5, r6, r11, r3, r2, r9, r10
        gs_butterfly_montg r7, r8, r12, r3, r2, r9, r10
        gs_butterfly_montg r5, r7, r14, r3, r2, r9, r10
        gs_butterfly_montg r6, r8, r14, r3, r2, r9, r10
        str.w   r6, [r0, #64]
        str.w   r7, [r0, #128]
        str.w   r8, [r0, #192]
        str     r5, [r0], #4
        subs    r4, #1
        bne     invntt_smull_L6
        sub     r0, #832

        ; --- stage 7 and 8 ---
        ; ptr_zeta (r1) is retired here and immediately reused to hold
        ; the final Montgomery reduction constant f (= 41978 = 0xA3FA).
        movw    r4, #64
        ldr.w   r11, [r1]
        ldr.w   r12, [r1, #4]
        ldr.w   r14, [r1, #8]
        ldr.w   r1, ntt_leaktime_f                  ; r1 now holds f
invntt_smull_L7
        ldr.w   r5, [r0]
        ldr.w   r6, [r0, #256]                      ; 64*4
        ldr.w   r7, [r0, #512]                      ; 128*4
        ldr.w   r8, [r0, #768]                      ; 192*4
        gs_butterfly_montg r5, r6, r11, r3, r2, r9, r10    ; stage7
        gs_butterfly_montg r7, r8, r12, r3, r2, r9, r10    ; stage7
        gs_butterfly_montg r5, r7, r14, r3, r2, r9, r10    ; stage8
        gs_butterfly_montg r6, r8, r14, r3, r2, r9, r10    ; stage8
        montg_red r1, r5, r3, r2, r9, r10                  ; final reduction
        montg_red r1, r6, r3, r2, r9, r10                  ; final reduction

        ; Original note preserved: the multiplications by f for pol2/pol3
        ; are skipped here; they are absorbed into the zeta2 twiddle of
        ; the previous butterfly (3975713 = (8354570 * 16382) mod q).

        str.w   r6, [r0, #256]
        str.w   r7, [r0, #512]
        str.w   r8, [r0, #768]
        str     r5, [r0], #4
        subs    r4, #1
        bne     invntt_smull_L7

        pop     {r4-r11, pc}
        ENDP

; =============================================================================
; Literal pool (read-only constants used by both functions)
; =============================================================================
        ALIGN   4
ntt_leaktime_f
        DCD     41978
ntt_leaktime_qinv
        DCD     0xFC7FDFFF
ntt_leaktime_q
        DCD     8380417
ntt_leaktime_64
        DCD     64

        END
