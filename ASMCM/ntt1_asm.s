; -----------------------------------------------------------------------------
; ntt1_asm.s   [ASMCM — side-channel countermeasure variant]
;
; Port of pqm3 crypto_sign/dilithium2/m3/ntt1_asm.S (GNU `as`, Thumb-2
; UAL) to ARM Compiler v5.06 `armasm` syntax, targeting an SC300
; (Cortex-M3 / ARMv7-M) core.  Dilithium forward NTT using schoolbook
; 32x32 multiplication built from MUL/MLA (no SMULL).
;
; Register binding (inline-expanded from the original .req table):
;   r0  = ptr_p     r1  = ptr_zeta   r2  = qinv     r3  = qh
;   r4  = cntr      r5  = pol0       r6  = pol1_h   r7  = pol1_l
;   r8  = ql        r9  = temp_h     r10 = temp_l
;   r11 = zeta_h    r12 = zeta_l     r14 = temp
;
; ===========================================================================
; COUNTERMEASURE — First-order arithmetic masked forward NTT
; ===========================================================================
;
; This file adds `ntt_masked_asm_schoolbook` alongside the original
; `ntt_asm_schoolbook`, providing first-order side-channel protection
; for secret polynomials fed into the forward NTT (for example, y and
; s1 during Dilithium signing when their NTT-domain forms are needed).
;
; Threat model
; ------------
; DPA / CPA / EM leakage during the unmasked forward NTT of a secret
; polynomial can be correlated with key-bit hypotheses to recover the
; secret.  Arithmetic masking in Z_q raises the attack from first- to
; second-order.
;
; Technique — same as ASMCM/intt_asm.s masking, applied to the forward
; map.  Split the input polynomial into two arithmetic shares:
;
;       p[i]  =  s0[i] + s1[i]   (mod q)      s1[i] uniformly random
;
; Because the NTT is a Z_q-linear map,
;
;       NTT(p)  =  NTT(s0) + NTT(s1)   (mod q)
;
; so the masked NTT is computed by running the unmasked
; `ntt_asm_schoolbook` independently on each share.  Caller keeps both
; output shares split throughout the downstream computation; they are
; only summed (mod q) at a public boundary.
;
; Implementation strategy
; -----------------------
; Thin assembly wrapper invoking the existing tested ntt_asm_schoolbook
; twice — once per share — with a fresh `zetas` pointer each time.  The
; inner routine does `add r1, #4` in its prologue and then post-
; increments r1 via `load_zeta`, so the second call MUST receive the
; unmoved original zetas pointer; otherwise the second share processes
; shifted twiddle factors and the sum-mod-q of the two outputs no
; longer equals NTT(p).
;
; Limitations (to be tightened in follow-up commits)
; --------------------------------------------------
; 1. Shares processed sequentially — second-order attacker combining
;    leakage across the two BL calls is not defeated here.
; 2. No operation shuffling / randomised coefficient ordering.
; 3. No refresh gadget between shares.
;
; External API
; ------------
;   void ntt_masked_asm_schoolbook(
;            int32_t        s0[N],       ; r0 — share 0 (standard domain, in/out)
;            int32_t        s1[N],       ; r1 — share 1 (standard domain, in/out)
;            const uint32_t zetas_asm[N]); r2 — twiddle table
;
; On return, s0[] and s1[] hold the two arithmetic shares of the NTT-
; domain polynomial; their sum mod q equals NTT(s0 + s1).
; ===========================================================================
;
; Source upstream: https://github.com/mupq/pqm3
; -----------------------------------------------------------------------------

        AREA    |.text|, CODE, READONLY
        THUMB
        PRESERVE8

; Global counter reused by each WHILE/WEND replacement of the original
; `.rept N` blocks (levels 2 and 3).
        GBLA    count

; -----------------------------------------------------------------------------
; Schoolbook 32x32 multiply with accumulate into {acc1:acc0}.
; -----------------------------------------------------------------------------
        MACRO
        const_mul32_acc $acc0, $acc1, $a0, $a1, $b0, $b1, $tmp
        mul     $tmp, $a0, $b0
        adds    $acc0, $acc0, $tmp
        mul     $tmp, $a1, $b1
        adc     $acc1, $acc1, $tmp
        mul     $tmp, $a1, $b0
        mla     $tmp, $a0, $b1, $tmp
        adds    $acc0, $acc0, $tmp, lsl #16
        adc    $acc1, $acc1, $tmp, asr #16
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
        adc    $c1, $c1, $tmp, asr #16
        MEND

; -----------------------------------------------------------------------------
; Constant-time Cooley-Tukey butterfly with Montgomery reduction using
; schoolbook multiplication.
; -----------------------------------------------------------------------------
        MACRO
        ct_butterfly_montg_const $pol0, $pol1_l, $pol1_h, $zeta_l, $zeta_h, $ql, $qh, $qinv, $th, $tl, $tmp
        const_mul32 $tl, $th, $pol1_l, $pol1_h, $zeta_l, $zeta_h, $tmp
        mul     $pol1_h, $tl, $qinv
        ubfx    $pol1_l, $pol1_h, #0, #16
        asr     $pol1_h, $pol1_h, #16
        const_mul32_acc $tl, $th, $pol1_l, $pol1_h, $ql, $qh, $tmp
        sub     $pol1_l, $pol0, $th
        add.w   $pol0, $pol0, $th
        MEND

; -----------------------------------------------------------------------------
; Load, butterfly, store one coefficient pair at stride `const`; advance
; ptr_p by 4 + `incr` after writing pol0 back.
; -----------------------------------------------------------------------------
        MACRO
        wrap_butterfly $const, $incr
        ldr.w   r5, [r0]                                 ; pol0
        ldrh.w  r7, [r0, #$const]                        ; pol1_l
        ldrsh.w r6, [r0, #($const)+2]                    ; pol1_h
        ct_butterfly_montg_const r5, r7, r6, r12, r11, r8, r3, r2, r9, r10, r14
        str.w   r5, [r0], #4+($incr)
        str.w   r7, [r0, #($const)-($incr)-4]
        MEND

; -----------------------------------------------------------------------------
; Load the next two zeta halves (low then high) from ptr_zeta.
; -----------------------------------------------------------------------------
        MACRO
        load_zeta
        ldrh.w  r12, [r1], #2                            ; zeta_l
        ldrh.w  r11, [r1], #2                            ; zeta_h
        MEND

; =============================================================================
; void ntt_asm_schoolbook(int32_t p[N], const uint32_t zetas_asm[N]);
; =============================================================================
        ALIGN   4
        EXPORT  ntt_asm_schoolbook
ntt_asm_schoolbook PROC
        push    {r4-r11, r14}

        ; qinv = 0xFC7FDFFF
        movw    r2, #0xDFFF
        movt    r2, #0xFC7F
        ; ql = 0xE001, qh = 0x7F  (q = 8380417 split as 16|16)
        movw    r8, #0xE001
        movw    r3, #0x7F

        add     r1, #4                                    ; &zeta[1]

        ; --------------------------------------------------------------
        ;  Level 7-4 iterate inside blocks
        ; --------------------------------------------------------------
        ; level 7
        movw    r4, #128
        load_zeta
ntt_sch_level_7
        wrap_butterfly 512, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_7
        sub     r0, #512

        ; level 6
        movw    r4, #64
        load_zeta
ntt_sch_level_6_1
        wrap_butterfly 256, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_6_1
        add     r0, #256

        movw    r4, #64
        load_zeta
ntt_sch_level_6_2
        wrap_butterfly 256, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_6_2
        sub     r0, #768

        ; level 5
        movw    r4, #32
        load_zeta
ntt_sch_level_5_1
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_5_1
        add     r0, #128

        movw    r4, #32
        load_zeta
ntt_sch_level_5_2
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_5_2
        add     r0, #128

        movw    r4, #32
        load_zeta
ntt_sch_level_5_3
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_5_3
        add     r0, #128

        movw    r4, #32
        load_zeta
ntt_sch_level_5_4
        wrap_butterfly 128, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_5_4
        sub     r0, #896

        ; level 4 (eight groups of 16)
        movw    r4, #16
        load_zeta
ntt_sch_level_4_1
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_1
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_2
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_2
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_3
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_3
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_4
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_4
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_5
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_5
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_6
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_6
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_7
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_7
        add     r0, #64

        movw    r4, #16
        load_zeta
ntt_sch_level_4_8
        wrap_butterfly 64, 0
        subs.n  r4, #1
        bne.n   ntt_sch_level_4_8
        sub     r0, #960

        ; --------------------------------------------------------------
        ;  Level 3-0 iterate over blocks
        ; --------------------------------------------------------------

        ; level 3 — unrolled 7 times, then one "+incr" to skip the block
        movw    r4, #16
ntt_sch_level_3
        load_zeta
count   SETA    0
        WHILE   count < 7
        wrap_butterfly 32, 0
count   SETA    count + 1
        WEND
        wrap_butterfly 32, 32
        subs.w  r4, #1
        bne.w   ntt_sch_level_3
        sub     r0, #1024

        ; level 2 — unrolled 3 times, then one "+incr"
        movw    r4, #32
ntt_sch_level_2
        load_zeta
count   SETA    0
        WHILE   count < 3
        wrap_butterfly 16, 0
count   SETA    count + 1
        WEND
        wrap_butterfly 16, 16
        subs.w  r4, #1
        bne.w   ntt_sch_level_2
        sub     r0, #1024

        ; level 1
        movw    r4, #64
ntt_sch_level_1
        load_zeta
        wrap_butterfly 8, 0
        wrap_butterfly 8, 8
        subs.n  r4, #1
        bne.n   ntt_sch_level_1
        sub     r0, #1024

        ; level 0
        movw    r4, #128
ntt_sch_level_0
        load_zeta
        wrap_butterfly 4, 4
        subs.n  r4, #1
        bne.n   ntt_sch_level_0

        pop     {r4-r11, pc}
        ENDP

; =============================================================================
; COUNTERMEASURE wrapper — first-order arithmetic masked forward NTT
;
; void ntt_masked_asm_schoolbook(
;          int32_t        s0[N],       ; r0 — share 0 (in/out)
;          int32_t        s1[N],       ; r1 — share 1 (in/out)
;          const uint32_t zetas_asm[N]); r2 — twiddle table
;
; NTT linearity over Z_q: NTT(s0 + s1) == NTT(s0) + NTT(s1) (mod q).
; Dispatch the unmasked schoolbook forward NTT on each share in turn,
; passing a *fresh* zetas pointer to the second call (the inner routine
; does `add r1, #4` plus post-incremented load_zeta).
;
; Stack usage: 3 words (r4, r5, lr).  r4/r5 are callee-saved across the
; inner BL, so they safely hold share1 and zetas across the first
; ntt_asm_schoolbook invocation.
; =============================================================================
        EXPORT  ntt_masked_asm_schoolbook

        ALIGN   4
ntt_masked_asm_schoolbook PROC
        push.w  {r4-r5, lr}

        mov     r4, r1                              ; r4 <- share1 ptr
        mov     r5, r2                              ; r5 <- zetas ptr (canonical)

        ; --- forward NTT on share 0 -----------------------------------------
        ; r0 already = s0 (arg1).  r1 must hold the zetas ptr per
        ; ntt_asm_schoolbook's AAPCS signature.
        mov     r1, r5                              ; r1 <- zetas
        bl      ntt_asm_schoolbook

        ; --- forward NTT on share 1 -----------------------------------------
        ; Pass the *unmoved* zetas pointer so share 1 sees the same twiddle
        ; sequence as share 0.  The inner routine's prologue `add r1, #4`
        ; and subsequent load_zeta post-increments have trashed r1 by now.
        mov     r0, r4                              ; r0 <- share1
        mov     r1, r5                              ; r1 <- zetas (fresh copy)
        bl      ntt_asm_schoolbook

        pop.w   {r4-r5, pc}
        ENDP

        END
