; -----------------------------------------------------------------------------
; pointwise_mul.s
;
; Port of pqm3 crypto_sign/dilithium2/m3/pointwise_mul.S (GNU `as`,
; Thumb-2 UAL) to ARM Compiler v5.06 `armasm` syntax, targeting an SC300
; (Cortex-M3 / ARMv7-M) core.  Implements coefficient-wise Montgomery
; multiplication for the Dilithium NTT domain using schoolbook 32x32→32+
; (via MUL/MLA pairs rather than UMULL/SMULL).
;
; Source upstream: https://github.com/mupq/pqm3
; -----------------------------------------------------------------------------

        AREA    |.text|, CODE, READONLY
        THUMB
        PRESERVE8

; -----------------------------------------------------------------------------
; Schoolbook 32x32 multiply with accumulation using MUL/MLA only.
;   {acc1,acc0} += (a1:a0) * (b1:b0)
; -----------------------------------------------------------------------------
        MACRO
        const_mul32_acc $acc0, $acc1, $a0, $a1, $b0, $b1, $tmp
        mul     $tmp, $a0, $b0
        adds.w  $acc0, $acc0, $tmp
        mul     $tmp, $a1, $b1
        adc.w   $acc1, $acc1, $tmp
        mul     $tmp, $a1, $b0
        mla     $tmp, $a0, $b1, $tmp
        adds.w  $acc0, $acc0, $tmp, lsl #16
        adc.w   $acc1, $acc1, $tmp, asr #16
        MEND

; -----------------------------------------------------------------------------
; Schoolbook 32x32 multiply. Order permits c0 to alias a0.
;   {c1,c0} = (a1:a0) * (b1:b0)
; -----------------------------------------------------------------------------
        MACRO
        const_mul32 $c0, $c1, $a0, $a1, $b0, $b1, $tmp
        mul     $tmp, $a1, $b0
        mla     $tmp, $a0, $b1, $tmp
        mul     $c0, $a0, $b0
        mul     $c1, $a1, $b1
        adds.w  $c0, $c0, $tmp, lsl #16
        adc.w   $c1, $c1, $tmp, asr #16
        MEND

; -----------------------------------------------------------------------------
; Montgomery multiplication (res = pah allowed).
; -----------------------------------------------------------------------------
        MACRO
        montgomery_multiplication_m3 $res, $pal, $pah, $pbl, $pbh, $tmp0, $qinv, $ql, $qh
        const_mul32  $pal, $res, $pal, $pah, $pbl, $pbh, $tmp0
        mul     $pbh, $pal, $qinv
        ubfx    $pbl, $pbh, #0, #16
        asr.w   $pbh, $pbh, #16
        const_mul32_acc $pal, $res, $pbl, $pbh, $ql, $qh, $tmp0
        MEND

; =============================================================================
; poly_pointwise_invmontgomery_asm_mul
;   c[i] = a[i] * b[i] * 2^-32 mod q   (Dilithium q = 8380417)
; Register binding (inline-expanded from original .req table):
;   r0=c_ptr r1=a_ptr r2=b_ptr r3=qinv r4=ql r5=qh
;   r6=pal r7=pah r8=pbl r9=pbh r12=ctr r14=tmp0
; =============================================================================
        ALIGN   4
        EXPORT  poly_pointwise_invmontgomery_asm_mul
poly_pointwise_invmontgomery_asm_mul PROC
        push.w  {r4-r9, r14}

        movw    r4, #0xE001                 ; ql
        movw    r5, #0x7F                   ; qh
        movw    r12, #256                   ; ctr
        ; qinv = 0xFC7FDFFF = 4236238847
        movw    r3, #0xDFFF
        movt    r3, #0xFC7F

pp_mul_L1
        ldrsh.w r7, [r1, #2]                ; pah
        ldrh    r6, [r1], #4                ; pal
        ldrsh.w r9, [r2, #2]                ; pbh
        ldrh    r8, [r2], #4                ; pbl

        montgomery_multiplication_m3 r7, r6, r7, r8, r9, r14, r3, r4, r5

        str     r7, [r0], #4

        subs.w  r12, r12, #1
        bne.w   pp_mul_L1
        pop.w   {r4-r9, pc}
        ENDP

; =============================================================================
; poly_pointwise_acc_invmontgomery_asm_mul
;   c[i] += a[i] * b[i] * 2^-32 mod q
; Extra register r10 holds the accumulator load.
; =============================================================================
        ALIGN   4
        EXPORT  poly_pointwise_acc_invmontgomery_asm_mul
poly_pointwise_acc_invmontgomery_asm_mul PROC
        push.w  {r4-r10, r14}

        movw    r4, #0xE001                 ; ql
        movw    r5, #0x7F                   ; qh
        movw    r12, #256                   ; ctr
        ; qinv = 0xFC7FDFFF = 4236238847
        movw    r3, #0xDFFF
        movt    r3, #0xFC7F

pp_mul_acc_L1
        ldrsh.w r7, [r1, #2]                ; pah
        ldrh    r6, [r1], #4                ; pal
        ldrsh.w r9, [r2, #2]                ; pbh
        ldrh    r8, [r2], #4                ; pbl
        ldr.w   r10, [r0]                   ; pcc

        montgomery_multiplication_m3 r7, r6, r7, r8, r9, r14, r3, r4, r5

        add.w   r7, r7, r10
        str     r7, [r0], #4

        subs.w  r12, r12, #1
        bne.w   pp_mul_acc_L1
        pop.w   {r4-r10, pc}
        ENDP

        END
