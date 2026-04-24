; -----------------------------------------------------------------------------
; intt_asm.s   [ASMCM — side-channel countermeasure variant]
;
; Port of pqm3 crypto_sign/dilithium2/m3/intt_asm.S (GNU `as`, Thumb-2
; UAL) to ARM Compiler v5.06 `armasm` syntax, targeting an SC300
; (Cortex-M3 / ARMv7-M) core.  Dilithium inverse NTT using schoolbook
; 32x32 multiplication built from MUL/MLA (no SMULL).
;
; Register binding (inline-expanded from the original .req table):
;   r0  = ptr_p     r1  = ptr_zeta (and later rebinds as `f` after level 7
;                                   zetas are loaded)
;   r2  = qinv      r3  = ql        r4  = cntr     r5  = pol0
;   r6  = pol1      r7  = qh        r8  = temp_1   r9  = temp_2
;   r10 = temp_3    r11 = zeta_l    r12 = zeta_h   r14 = temp_q
;
; ===========================================================================
; COUNTERMEASURE — First-order arithmetic masked inverse NTT
; ===========================================================================
;
; This file adds `inv_ntt_masked_asm_schoolbook` alongside the original
; `inv_ntt_asm_schoolbook`, providing first-order side-channel protection
; for the secret polynomial processed by the inverse NTT.
;
; Threat model
; ------------
; Differential / Correlation Power Analysis (DPA / CPA) and EM emanation
; on the Dilithium signing inverse NTT can expose intermediates that
; leak the secret key.  The classical masking countermeasure splits each
; secret coefficient into two arithmetic shares:
;
;       p[i]  =  s0[i] + s1[i]   (mod q)     with s1[i] uniformly random
;
; An attacker observing a single leakage trace sees operations on only
; one share; they must combine leakage from BOTH shares to recover p[i].
; The correlation between measurements and the secret drops from first
; order (linear in the number of traces needed) to second order
; (quadratic), raising the attack cost by several orders of magnitude.
;
; Why NTT is compatible with arithmetic masking
; ---------------------------------------------
; The NTT (and its inverse) is a Z_q-linear map.  For any linear T:
;
;       T(s0 + s1)  =  T(s0) + T(s1)   (mod q)
;
; So masked inverse NTT can be computed by running the *unmasked* inverse
; NTT on each share independently:
;
;       inv_ntt(p)  =  inv_ntt(s0) + inv_ntt(s1)   (mod q)
;
; The caller holds the two output shares in s0[] and s1[]; summing them
; mod q reconstructs the standard-domain polynomial when needed.  The
; shares remain split for downstream masked operations (rounding,
; rejection sampling, packing) until the final step where the value is
; demasked into a public output (e.g. signature component z).
;
; Implementation strategy
; -----------------------
; We reuse the existing tested `inv_ntt_asm_schoolbook` and invoke it
; twice — once per share — with a fresh `zetas` pointer each time
; (the inner routine advances r1 during execution, so the second call
; must receive an unmoved copy).  Both shares traverse identical code
; and memory-access patterns, so the *only* quantity that differs
; between the two invocations is the share data itself — precisely the
; condition required for first-order arithmetic masking security.
;
; Limitations (documented for future hardening)
; ---------------------------------------------
; 1. Shares are processed sequentially on the same core.  A higher-order
;    attacker combining leakage across the two calls can still mount a
;    second-order attack.  Mitigating that requires share-interleaved
;    butterflies (stage-level share interleaving) or a refresh gadget
;    between shares — planned for a follow-up commit.
; 2. No operation shuffling / randomized coefficient order; an attacker
;    with precise timing can align traces.
; 3. Micro-architectural leakage (instruction cache warm-up, register-
;    rename port pressure) between the two calls is not addressed.  On
;    Cortex-M3 / SC300 this surface is much smaller than on out-of-order
;    cores, but it is non-zero.
;
; External API
; ------------
;   void inv_ntt_masked_asm_schoolbook(
;            int32_t        s0[N],           ; r0 - share 0 (in NTT domain, in/out)
;            int32_t        s1[N],           ; r1 - share 1 (in NTT domain, in/out)
;            const uint32_t zetas_inv_asm[N]); r2 - twiddle factor table
;
; On return, s0[] and s1[] hold the two arithmetic shares of the standard
; (non-NTT-domain) polynomial; their sum (mod q) equals inv_ntt(s0+s1).
; ===========================================================================
;
; Source upstream: https://github.com/mupq/pqm3
; -----------------------------------------------------------------------------

        AREA    |.text|, CODE, READONLY
        THUMB
        PRESERVE8

        GBLA    count

; -----------------------------------------------------------------------------
; Schoolbook 32x32 multiply-accumulate into {acc1:acc0}.
; -----------------------------------------------------------------------------
        MACRO
        const_mul32_acc $acc0, $acc1, $a0, $a1, $b0, $b1, $tmp
        mul.w   $tmp, $a0, $b0
        adds.w  $acc0, $acc0, $tmp
        mul.w   $tmp, $a1, $b1
        adc.w   $acc1, $acc1, $tmp
        mul.w   $tmp, $a1, $b0
        mla.w   $tmp, $a0, $b1, $tmp
        adds.w  $acc0, $acc0, $tmp, lsl #16
        adc.w   $acc1, $acc1, $tmp, asr #16
        MEND

; -----------------------------------------------------------------------------
; Schoolbook 32x32 multiply into {c1:c0}.
; -----------------------------------------------------------------------------
        MACRO
        const_mul32 $c0, $c1, $a0, $a1, $b0, $b1, $tmp
        mul     $c0, $a0, $b0
        mul     $c1, $a1, $b1
        mul     $tmp, $a1, $b0
        mla     $tmp, $a0, $b1, $tmp
        adds    $c0, $c0, $tmp, lsl #16
        adc     $c1, $c1, $tmp, asr #16
        MEND

; -----------------------------------------------------------------------------
; Schoolbook 32x16 multiply into {c1:c0}  (b1 = 0 optimization).
; -----------------------------------------------------------------------------
        MACRO
        const_mul32x16 $c0, $c1, $a0, $a1, $b0, $tmp
        mul     $c0, $a0, $b0
        mul     $tmp, $a1, $b0
        movw    $c1, #0
        adds    $c0, $c0, $tmp, lsl #16
        adc     $c1, $c1, $tmp, asr #16
        MEND

; -----------------------------------------------------------------------------
; Gentleman-Sande butterfly with Montgomery reduction (schoolbook mult).
; -----------------------------------------------------------------------------
        MACRO
        gs_butterfly_montg $pol0, $pol1, $zeta_l, $zeta_h, $ql, $qh, $qinv, $tmp1, $tmp2, $tmp3, $tmp_q
        sub     $tmp1, $pol0, $pol1
        add.w   $pol0, $pol0, $pol1
        ubfx    $tmp3, $tmp1, #0, #16               ; low16(tmp1)
        asr     $tmp1, $tmp1, #16                   ; high16(tmp1)
        const_mul32 $tmp2, $pol1, $tmp3, $tmp1, $zeta_l, $zeta_h, $tmp_q
        mul     $tmp1, $tmp2, $qinv
        ubfx    $tmp3, $tmp1, #0, #16
        asr     $tmp1, $tmp1, #16
        const_mul32_acc $tmp2, $pol1, $tmp3, $tmp1, $ql, $qh, $tmp_q
        MEND

; -----------------------------------------------------------------------------
; Standalone Montgomery reduction of a 32-bit value pol by constant f.
; -----------------------------------------------------------------------------
        MACRO
        montg_red $f, $pol, $ql, $qh, $qinv, $t0, $t1, $pol_l, $pol_h
        ubfx    $pol_l, $pol, #0, #16
        asr     $pol_h, $pol, #16
        const_mul32x16 $t1, $pol, $pol_l, $pol_h, $f, $t0
        mul     $t0, $t1, $qinv
        ubfx    $pol_l, $t0, #0, #16
        asr     $pol_h, $t0, #16
        const_mul32_acc $t1, $pol, $pol_l, $pol_h, $ql, $qh, $t0
        MEND

; -----------------------------------------------------------------------------
; Load pol0/pol1 at stride `const`, GS-butterfly, store back, advance
; ptr_p by 4+`incr`.
; -----------------------------------------------------------------------------
        MACRO
        wrap_butterfly $const, $incr
        ldr.w   r5, [r0]                            ; pol0
        ldr.w   r6, [r0, #$const]                   ; pol1
        gs_butterfly_montg r5, r6, r11, r12, r3, r7, r2, r8, r9, r10, r14
        str.w   r5, [r0], #4+($incr)
        str.w   r6, [r0, #($const)-4-($incr)]
        MEND

; -----------------------------------------------------------------------------
; Load one zeta pair (low halfword then signed high halfword).
; -----------------------------------------------------------------------------
        MACRO
        load_zeta
        ldrh    r11, [r1], #2                       ; zeta_l
        ldrsh   r12, [r1], #2                       ; zeta_h
        MEND

; =============================================================================
; void inv_ntt_asm_schoolbook(int32_t p[N], const uint32_t zetas_inv_asm[N]);
; =============================================================================
        ALIGN   4
        EXPORT  inv_ntt_asm_schoolbook
inv_ntt_asm_schoolbook PROC
        push    {r4-r11, r14}

        ; qinv = 0xFC7FDFFF (= -q^{-1} signed, mod 2^32)
        ; NOTE: originally `ldr r2, inv_ntt_asm_neg_qinv_signed`.  armasm
        ; v5.06 rejected the PC-relative LDR(literal) form with A1875E
        ; because the data-table label at the end of this 2 KB function
        ; sits outside the Thumb-2 LDR(literal) encoding range
        ; (T1: 0..1020 B, T2: ±4095 B).  Replaced with a direct
        ; MOVW+MOVT pair, which is encoding-range-free and uses the
        ; same 8 bytes of code as LDR + 4-byte pool entry.
        movw    r2, #0xDFFF
        movt    r2, #0xFC7F
        movw    r3, #0xE001                         ; ql
        movw    r7, #0x7F                           ; qh

        ; --------------------------------------------------------------
        ;  Level 0-3 iterate over blocks
        ; --------------------------------------------------------------

        ; level 0
        movw    r4, #128
inv_sch_level_0
        load_zeta
        wrap_butterfly 4, 4
        subs.n  r4, #1
        bne.n   inv_sch_level_0
        sub     r0, #1024

        ; level 1
        movw    r4, #64
inv_sch_level_1
        load_zeta
        wrap_butterfly 8, 0
        wrap_butterfly 8, 8
        subs.n  r4, #1
        bne.n   inv_sch_level_1
        sub     r0, #1024

        ; level 2: 3 inner butterflies then one "+incr"
        movw    r4, #32
inv_sch_level_2
        load_zeta
count   SETA    0
        WHILE   count < 3
        wrap_butterfly 16, 0
count   SETA    count + 1
        WEND
        wrap_butterfly 16, 16
        subs.w  r4, #1
        bne.w   inv_sch_level_2
        sub     r0, #1024

        ; level 3: 7 inner butterflies then one "+incr"
        movw    r4, #16
inv_sch_level_3
        load_zeta
count   SETA    0
        WHILE   count < 7
        wrap_butterfly 32, 0
count   SETA    count + 1
        WEND
        wrap_butterfly 32, 32
        subs.w  r4, #1
        bne.w   inv_sch_level_3
        sub     r0, #1024

        ; --------------------------------------------------------------
        ;  Level 4-7 iterate inside blocks
        ; --------------------------------------------------------------
        ; level 4 (eight groups of 16)
        load_zeta
        movw    r4, #16
inv_sch_level_4_1
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_1
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_2
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_2
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_3
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_3
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_4
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_4
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_5
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_5
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_6
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_6
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_7
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_7
        add.w   r0, r0, #64

        load_zeta
        movw    r4, #16
inv_sch_level_4_8
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_4_8
        sub.w   r0, r0, #960

        ; level 5 (four groups of 32)
        load_zeta
        movw    r4, #32
inv_sch_level_5_1
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_5_1
        add     r0, r0, #128

        load_zeta
        movw    r4, #32
inv_sch_level_5_2
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_5_2
        add     r0, r0, #128

        load_zeta
        movw    r4, #32
inv_sch_level_5_3
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_5_3
        add     r0, r0, #128

        load_zeta
        movw    r4, #32
inv_sch_level_5_4
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_5_4
        sub     r0, r0, #896

        ; level 6 (two groups of 64)
        load_zeta
        movw    r4, #64
inv_sch_level_6_1
        wrap_butterfly 256, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_6_1
        add     r0, r0, #256

        load_zeta
        movw    r4, #64
inv_sch_level_6_2
        wrap_butterfly 256, 0
        subs.n  r4, #1
        bne.n   inv_sch_level_6_2
        sub     r0, r0, #768

        ; level 7 — after this load, ptr_zeta (r1) is no longer needed
        ; and r1 gets reused below to hold the final-reduction constant f
        ; (= 41978 = 0xA3FA).  No armasm directive is needed for the
        ; rebind; inline-expansion means it's just "use r1 differently".
        load_zeta
        movw    r4, #128

        movw    r1, #41978                          ; r1 now holds f
inv_sch_level_7
        ldr.w   r5, [r0]                            ; pol0
        ldr.w   r6, [r0, #512]                      ; pol1 (p + 128*4)
        gs_butterfly_montg r5, r6, r11, r12, r3, r7, r2, r8, r9, r10, r14
        add     r10, r3, r7, lsl #16                ; stale in GNU original, preserved
        montg_red r1, r5, r3, r7, r2, r8, r9, r10, r14
        str.w   r5, [r0], #4
        str.w   r6, [r0, #508]
        subs.n  r4, #1
        bne.n   inv_sch_level_7

        pop     {r4-r11, pc}
        ENDP

; =============================================================================
; COUNTERMEASURE wrapper — first-order arithmetic masked inverse NTT
;
; void inv_ntt_masked_asm_schoolbook(
;          int32_t        s0[N],           ; r0 — share 0
;          int32_t        s1[N],           ; r1 — share 1
;          const uint32_t zetas_inv_asm[N]); r2 — twiddle table
;
; Exploits NTT linearity over Z_q: inv_ntt(s0 + s1) == inv_ntt(s0) +
; inv_ntt(s1) (mod q).  Dispatches the unmasked schoolbook inverse NTT
; on each share in turn, passing a *fresh* zetas pointer to the second
; call (the inner routine post-increments r1 as it consumes twiddle
; factors).  First-order side-channel security against DPA / CPA / EM
; on the secret polynomial: a single leakage trace reveals at most one
; share, which on its own is uniformly distributed and independent of
; the secret.
;
; Stack usage: 3 words (r4, r5, lr).  r4/r5 are callee-saved across the
; inner BL, so they can safely hold share1 and zetas across the first
; inv_ntt_asm_schoolbook invocation.
; =============================================================================
        EXPORT  inv_ntt_masked_asm_schoolbook

        ALIGN   4
inv_ntt_masked_asm_schoolbook PROC
        push.w  {r4-r5, lr}

        mov     r4, r1                              ; r4 <- share1 ptr
        mov     r5, r2                              ; r5 <- zetas ptr (canonical)

        ; --- inverse NTT on share 0 -----------------------------------------
        ; r0 already = s0 (arg1).  r1 must hold the zetas ptr per the inner
        ; routine's AAPCS signature.
        mov     r1, r5                              ; r1 <- zetas
        bl      inv_ntt_asm_schoolbook

        ; --- inverse NTT on share 1 -----------------------------------------
        ; Pass the *unmoved* zetas pointer so share 1 sees the same twiddle
        ; sequence as share 0.  Failing to restore r1 here would silently
        ; corrupt the second half of the computation.
        mov     r0, r4                              ; r0 <- share1
        mov     r1, r5                              ; r1 <- zetas (fresh copy)
        bl      inv_ntt_asm_schoolbook

        pop.w   {r4-r5, pc}
        ENDP

        END
