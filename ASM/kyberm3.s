; -----------------------------------------------------------------------------
; kyberm3.s
;
; Port of pqm3 crypto_kem/kyber768/m3/kyberm3.S (GNU `as`, Thumb-2 UAL) to
; ARM Compiler v5.06 `armasm` syntax, targeting an SC300 (Cortex-M3 / ARMv7-M)
; core.  Instruction set and semantics are unchanged; only directives, macro
; syntax, label style and register-alias handling have been converted.
;
; Source upstream: https://github.com/mupq/pqm3  (public-domain / CC0)
; -----------------------------------------------------------------------------

        PRESERVE8
        THUMB

        AREA    |.text|, CODE, READONLY

; -----------------------------------------------------------------------------
; Macro: barrettm3
;   Unsigned Barrett reduction.
;   $a  : value to reduce (in/out)
;   $tmp: scratch register
;   $q  : modulus q (in)
;   $barrettconst : Barrett multiplier (in)
; -----------------------------------------------------------------------------
        MACRO
        barrettm3 $a, $tmp, $q, $barrettconst
        mul.w   $tmp, $a, $barrettconst
        asr.w   $tmp, $tmp, #26
        mul.w   $tmp, $tmp, $q
        sub.w   $a, $a, $tmp
        MEND

; -----------------------------------------------------------------------------
; Macro: montgomerym3
;   Signed Montgomery reduction of a 32-bit value.
;   $q   : modulus q (in)
;   $qinv: q^{-1} mod 2^16 (in)
;   $a   : value to reduce (in/out)
;   $tmp : scratch register
; -----------------------------------------------------------------------------
        MACRO
        montgomerym3 $q, $qinv, $a, $tmp
        mul.w   $tmp, $a, $qinv
        sxth.w  $tmp, $tmp
        mla.w   $a, $tmp, $q, $a
        asr.w   $a, $a, #16
        MEND

; =============================================================================
; pointwise_sub_m3 : polynomial subtraction
; r0 = result ptr, r1 = a ptr, r2 = b ptr (256 int16 each)
; =============================================================================
        ALIGN   4
        EXPORT  pointwise_sub_m3
pointwise_sub_m3 PROC
        push.w  {r4-r11, lr}

        movw    r14, #51
psub_L1
        ldrsh.w r4, [r1, #2]
        ldrsh.w r5, [r1, #4]
        ldrsh.w r6, [r1, #6]
        ldrsh.w r7, [r1, #8]
        ldrsh.w r3, [r1], #10
        ldrsh.w r9, [r2, #2]
        ldrsh.w r10, [r2, #4]
        ldrsh.w r11, [r2, #6]
        ldrsh.w r12, [r2, #8]
        ldrsh.w r8, [r2], #10

        sub.w   r3, r3, r8
        sub.w   r4, r4, r9
        sub.w   r5, r5, r10
        sub.w   r6, r6, r11
        sub.w   r7, r7, r12

        strh.w  r4, [r0, #2]
        strh.w  r5, [r0, #4]
        strh.w  r6, [r0, #6]
        strh.w  r7, [r0, #8]
        strh.w  r3, [r0], #10
        subs.w  r14, #1
        bne.w   psub_L1

        ldrsh.w r3, [r1]
        ldrsh.w r4, [r2]
        sub.w   r3, r3, r4
        strh.w  r3, [r0]

        pop.w   {r4-r11, pc}
        ENDP

; =============================================================================
; pointwise_add_m3 : polynomial addition
; r0 = result ptr, r1 = a ptr, r2 = b ptr (256 int16 each)
; =============================================================================
        ALIGN   4
        EXPORT  pointwise_add_m3
pointwise_add_m3 PROC
        push.w  {r4-r11, lr}

        movw    r14, #51
padd_L1
        ldrsh.w r4, [r1, #2]
        ldrsh.w r5, [r1, #4]
        ldrsh.w r6, [r1, #6]
        ldrsh.w r7, [r1, #8]
        ldrsh.w r3, [r1], #10
        ldrsh.w r9, [r2, #2]
        ldrsh.w r10, [r2, #4]
        ldrsh.w r11, [r2, #6]
        ldrsh.w r12, [r2, #8]
        ldrsh.w r8, [r2], #10

        add.w   r3, r3, r8
        add.w   r4, r4, r9
        add.w   r5, r5, r10
        add.w   r6, r6, r11
        add.w   r7, r7, r12

        strh.w  r4, [r0, #2]
        strh.w  r5, [r0, #4]
        strh.w  r6, [r0, #6]
        strh.w  r7, [r0, #8]
        strh.w  r3, [r0], #10
        subs.w  r14, #1
        bne.w   padd_L1

        ldrsh.w r3, [r1]
        ldrsh.w r4, [r2]
        add.w   r3, r3, r4
        strh.w  r3, [r0]

        pop.w   {r4-r11, pc}
        ENDP

; =============================================================================
; asm_barrett_reduce_m3 : in-place Barrett reduction of 256 int16 coeffs
; Register mapping (inline-expanded from original .req table):
;   r0 = poly          r1..r8 = poly0..poly7          r14 = poly8
;   r9 = loop          r10 = barrettconst             r11 = q
;   r12 = tmp
; =============================================================================
        ALIGN   4
        EXPORT  asm_barrett_reduce_m3
asm_barrett_reduce_m3 PROC
        push.w  {r4-r11, r14}

        movw    r10, #20159         ; barrettconst
        movw    r11, #3329          ; q

        movw    r9, #28             ; loop
barred_L1
        ldrsh.w r1,  [r0, #0]
        ldrsh.w r2,  [r0, #2]
        ldrsh.w r3,  [r0, #4]
        ldrsh.w r4,  [r0, #6]
        ldrsh.w r5,  [r0, #8]
        ldrsh.w r6,  [r0, #10]
        ldrsh.w r7,  [r0, #12]
        ldrsh.w r8,  [r0, #14]
        ldrsh.w r14, [r0, #16]

        barrettm3 r1,  r12, r11, r10
        barrettm3 r2,  r12, r11, r10
        barrettm3 r3,  r12, r11, r10
        barrettm3 r4,  r12, r11, r10
        barrettm3 r5,  r12, r11, r10
        barrettm3 r6,  r12, r11, r10
        barrettm3 r7,  r12, r11, r10
        barrettm3 r8,  r12, r11, r10
        barrettm3 r14, r12, r11, r10

        strh.w  r2,  [r0, #2]
        strh.w  r3,  [r0, #4]
        strh.w  r4,  [r0, #6]
        strh.w  r5,  [r0, #8]
        strh.w  r6,  [r0, #10]
        strh.w  r7,  [r0, #12]
        strh.w  r8,  [r0, #14]
        strh.w  r14, [r0, #16]
        strh.w  r1,  [r0], #18
        subs.w  r9, #1
        bne.w   barred_L1

        ; Tail: remaining 4 coefficients (28*9 + 4 = 256).
        ldrsh.w r1, [r0, #0]
        ldrsh.w r2, [r0, #2]
        ldrsh.w r3, [r0, #4]
        ldrsh.w r4, [r0, #6]
        barrettm3 r1, r12, r11, r10
        barrettm3 r2, r12, r11, r10
        barrettm3 r3, r12, r11, r10
        barrettm3 r4, r12, r11, r10
        strh.w  r1, [r0, #0]
        strh.w  r2, [r0, #2]
        strh.w  r3, [r0, #4]
        strh.w  r4, [r0, #6]

        pop.w   {r4-r11, pc}
        ENDP

; =============================================================================
; asm_frommont_m3 : convert 256 int16 coeffs out of Montgomery form
; Register mapping:
;   r0 = poly          r1..r8 = poly0..poly7
;   r9 = loop          r10 = constant (1353)
;   r11 = q            r12 = tmp          r14 = qinv
; =============================================================================
        ALIGN   4
        EXPORT  asm_frommont_m3
asm_frommont_m3 PROC
        push.w  {r4-r11, r14}

        movw    r11, #3329          ; q
        movw    r14, #3327          ; qinv
        movw    r10, #1353          ; constant

        movw    r9, #32             ; loop
frommont_L1
        ldrsh.w r1, [r0, #0]
        ldrsh.w r2, [r0, #2]
        ldrsh.w r3, [r0, #4]
        ldrsh.w r4, [r0, #6]
        ldrsh.w r5, [r0, #8]
        ldrsh.w r6, [r0, #10]
        ldrsh.w r7, [r0, #12]
        ldrsh.w r8, [r0, #14]

        mul.w   r1, r1, r10
        mul.w   r2, r2, r10
        mul.w   r3, r3, r10
        mul.w   r4, r4, r10
        mul.w   r5, r5, r10
        mul.w   r6, r6, r10
        mul.w   r7, r7, r10
        mul.w   r8, r8, r10
        montgomerym3 r11, r14, r1, r12
        montgomerym3 r11, r14, r2, r12
        montgomerym3 r11, r14, r3, r12
        montgomerym3 r11, r14, r4, r12
        montgomerym3 r11, r14, r5, r12
        montgomerym3 r11, r14, r6, r12
        montgomerym3 r11, r14, r7, r12
        montgomerym3 r11, r14, r8, r12

        strh.w  r2, [r0, #2]
        strh.w  r3, [r0, #4]
        strh.w  r4, [r0, #6]
        strh.w  r5, [r0, #8]
        strh.w  r6, [r0, #10]
        strh.w  r7, [r0, #12]
        strh.w  r8, [r0, #14]
        strh.w  r1, [r0], #16

        subs.w  r9, #1
        bne.w   frommont_L1

        pop.w   {r4-r11, pc}
        ENDP

; =============================================================================
; doublebasemul_asm_m3 : compute two 2-coeff base multiplications with zeta
; Register mapping:
;   r0=rptr r1=aptr r2=bptr r3=zeta
;   r4=poly0 r5=poly2 r6=poly1 r7=poly3   (ordering preserved from source)
;   r8=q r9=tmp r10=tmp2 r14=qinv
; =============================================================================
        ALIGN   4
        EXPORT  doublebasemul_asm_m3
doublebasemul_asm_m3 PROC
        push.w  {r4-r11, lr}

        movw    r8,  #3329          ; q
        movw    r14, #3327          ; qinv

        ldrsh.w r4, [r1, #0]        ; poly0
        ldrsh.w r6, [r1, #2]        ; poly1
        ldrsh.w r5, [r2, #0]        ; poly2
        ldrsh.w r7, [r2, #2]        ; poly3

        mul.w   r9, r6, r7
        montgomerym3 r8, r14, r9, r10
        mul.w   r9, r9, r3
        mla.w   r9, r4, r5, r9
        montgomerym3 r8, r14, r9, r10
        strh.w  r9, [r0, #0]

        mul.w   r9, r4, r7
        mla.w   r9, r6, r5, r9
        montgomerym3 r8, r14, r9, r10
        strh.w  r9, [r0, #2]

        neg.w   r3, r3

        ldrsh.w r4, [r1, #4]
        ldrsh.w r6, [r1, #6]
        ldrsh.w r5, [r2, #4]
        ldrsh.w r7, [r2, #6]

        mul.w   r9, r6, r7
        montgomerym3 r8, r14, r9, r10
        mul.w   r9, r9, r3
        mla.w   r9, r4, r5, r9
        montgomerym3 r8, r14, r9, r10
        strh.w  r9, [r0, #4]

        mul.w   r9, r4, r7
        mla.w   r9, r6, r5, r9
        montgomerym3 r8, r14, r9, r10
        strh.w  r9, [r0, #6]

        pop.w   {r4-r11, pc}
        ENDP

; =============================================================================
; doublebasemul_asm_acc_m3 : accumulating variant of doublebasemul_asm_m3
; Register mapping (note qinv moves to r11 here):
;   r0=rptr r1=aptr r2=bptr r3=zeta
;   r4=poly0 r5=poly2 r6=poly1 r7=poly3
;   r8=q r9=tmp r10=tmp2 r11=qinv r12=res0 r14=res1
; =============================================================================
        ALIGN   4
        EXPORT  doublebasemul_asm_acc_m3
doublebasemul_asm_acc_m3 PROC
        push.w  {r4-r11, lr}

        movw    r8,  #3329          ; q
        movw    r11, #3327          ; qinv

        ldrsh.w r4,  [r1, #0]
        ldrsh.w r6,  [r1, #2]
        ldrsh.w r5,  [r2, #0]
        ldrsh.w r7,  [r2, #2]
        ldrsh.w r12, [r0, #0]
        ldrsh.w r14, [r0, #2]

        mul.w   r9, r6, r7
        montgomerym3 r8, r11, r9, r10
        mul.w   r9, r9, r3
        mla.w   r9, r4, r5, r9
        montgomerym3 r8, r11, r9, r10
        add.w   r12, r12, r9
        strh.w  r12, [r0, #0]

        mul.w   r9, r4, r7
        mla.w   r9, r6, r5, r9
        montgomerym3 r8, r11, r9, r10
        add.w   r14, r14, r9
        strh.w  r14, [r0, #2]

        neg.w   r3, r3

        ldrsh.w r4,  [r1, #4]
        ldrsh.w r6,  [r1, #6]
        ldrsh.w r5,  [r2, #4]
        ldrsh.w r7,  [r2, #6]
        ldrsh.w r12, [r0, #4]
        ldrsh.w r14, [r0, #6]

        mul.w   r9, r6, r7
        montgomerym3 r8, r11, r9, r10
        mul.w   r9, r9, r3
        mla.w   r9, r4, r5, r9
        montgomerym3 r8, r11, r9, r10
        add.w   r12, r12, r9
        strh.w  r12, [r0, #4]

        mul.w   r9, r4, r7
        mla.w   r9, r6, r5, r9
        montgomerym3 r8, r11, r9, r10
        add.w   r14, r14, r9
        strh.w  r14, [r0, #6]

        pop.w   {r4-r11, pc}
        ENDP

; =============================================================================
; basemul_asm_m3 : 64-iteration loop over doublebasemul pattern with zetaptr
; Register mapping:
;   r0=rptr r1=aptr r2=bptr r3=zetaptr
;   r4=poly0 r5=poly2 r6=poly1 r7=poly3
;   r8=q r9=tmp r10=tmp2 r11=qinv r12=zeta r14=loop
; =============================================================================
        ALIGN   4
        EXPORT  basemul_asm_m3
basemul_asm_m3 PROC
        push.w  {r4-r11, lr}

        movw    r8,  #3329          ; q
        movw    r11, #3327          ; qinv

        movw    r14, #64            ; loop
bmul_L1
        ldrsh.w r12, [r3], #2       ; zeta

        ldrsh.w r6, [r1,  #2]
        ldrsh.w r4, [r1], #4
        ldrsh.w r7, [r2,  #2]
        ldrsh.w r5, [r2], #4

        mul.w   r9, r6, r7
        montgomerym3 r8, r11, r9, r10
        mul.w   r9, r9, r12
        mla.w   r9, r4, r5, r9
        montgomerym3 r8, r11, r9, r10
        strh.w  r9, [r0], #2

        mul.w   r9, r4, r7
        mla.w   r9, r6, r5, r9
        montgomerym3 r8, r11, r9, r10
        strh.w  r9, [r0], #2

        neg.w   r12, r12

        ldrsh.w r6, [r1,  #2]
        ldrsh.w r4, [r1], #4
        ldrsh.w r7, [r2,  #2]
        ldrsh.w r5, [r2], #4

        mul.w   r9, r6, r7
        montgomerym3 r8, r11, r9, r10
        mul.w   r9, r9, r12
        mla.w   r9, r4, r5, r9
        montgomerym3 r8, r11, r9, r10
        strh.w  r9, [r0], #2

        mul.w   r9, r4, r7
        mla.w   r9, r6, r5, r9
        montgomerym3 r8, r11, r9, r10
        strh.w  r9, [r0], #2

        subs.w  r14, #1
        bne.w   bmul_L1

        pop.w   {r4-r11, pc}
        ENDP

; =============================================================================
; basemul_asm_acc_m3 : accumulating 64-iteration base-multiply
; Same register mapping as basemul_asm_m3 above.
; =============================================================================
        ALIGN   4
        EXPORT  basemul_asm_acc_m3
basemul_asm_acc_m3 PROC
        push.w  {r4-r11, lr}

        movw    r8,  #3329          ; q
        movw    r11, #3327          ; qinv

        movw    r14, #64            ; loop
bmul_acc_L1
        ldrsh.w r12, [r3], #2       ; zeta

        ldrsh.w r6, [r1,  #2]
        ldrsh.w r4, [r1], #4
        ldrsh.w r7, [r2,  #2]
        ldrsh.w r5, [r2], #4

        mul.w   r9, r6, r7
        montgomerym3 r8, r11, r9, r10
        mul.w   r9, r9, r12
        mla.w   r9, r4, r5, r9
        montgomerym3 r8, r11, r9, r10
        ldrsh.w r10, [r0]
        add.w   r9, r9, r10
        strh.w  r9, [r0], #2

        mul.w   r9, r4, r7
        mla.w   r9, r6, r5, r9
        montgomerym3 r8, r11, r9, r10
        ldrsh.w r10, [r0]
        add.w   r9, r9, r10
        strh.w  r9, [r0], #2

        neg.w   r12, r12

        ldrsh.w r6, [r1,  #2]
        ldrsh.w r4, [r1], #4
        ldrsh.w r7, [r2,  #2]
        ldrsh.w r5, [r2], #4

        mul.w   r9, r6, r7
        montgomerym3 r8, r11, r9, r10
        mul.w   r9, r9, r12
        mla.w   r9, r4, r5, r9
        montgomerym3 r8, r11, r9, r10
        ldrsh.w r10, [r0]
        add.w   r9, r9, r10
        strh.w  r9, [r0], #2

        mul.w   r9, r4, r7
        mla.w   r9, r6, r5, r9
        montgomerym3 r8, r11, r9, r10
        ldrsh.w r10, [r0]
        add.w   r9, r9, r10
        strh.w  r9, [r0], #2

        subs.w  r14, #1
        bne.w   bmul_acc_L1

        pop.w   {r4-r11, pc}
        ENDP

        END
