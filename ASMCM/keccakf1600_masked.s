;
; ============================================================================
; ASMCM/keccakf1600_masked.s
;
; Keccak-f[1600] with 1st-order Boolean masking countermeasure.
;
; Toolchain : ARM Compiler 5.06 (armasm), legacy syntax.
; Target    : ARM Cortex-M3 / SC300, Thumb-2, little-endian, no DSP, no FP.
;
; ----------------------------------------------------------------------------
; Masking model
; ----------------------------------------------------------------------------
;   The 1600-bit state is sharded into two Boolean shares:
;       state0[0..49] (share 0), state1[0..49] (share 1)
;   such that each lane (x,y) satisfies
;       lane_joint = state0[i] XOR state1[i]   for i = (x*5 + y) * 2 + {0,1}
;
;   Theta, Rho, Pi, Iota are linear under XOR — applied per share.
;   Iota XORs the round constant into share 0 only (share 1 unchanged).
;
;   Chi  is non-linear:
;       a[x][y] ^= ((NOT a[x+1 mod 5][y]) AND a[x+2 mod 5][y])
;   We use the ISW (Ishai–Sahai–Wagner) secure AND gadget.  NOT is folded
;   into share 0 only:  NOT(a) = (NOT a0) XOR a1.
;
;       SecAND_32(a0,a1, b0,b1)  ->  (c0, c1)        ; c0^c1 = (a0^a1) ∧ (b0^b1)
;           r   = random32()
;           c0  = (a0 AND b0) XOR r
;           t   = (a0 AND b1) XOR r        ; r masks before any cross-share fold
;           t   = t XOR (a1 AND b0)
;           c1  = t XOR (a1 AND b1)
;
;   Per Keccak-f[1600] permutation we consume:
;       24 rounds × 25 SecAND-64 cells × 2 (lo, hi) × 4 bytes  =  4800 bytes
;   of fresh randomness, sourced from masked_fresh_rand32().
;
; ----------------------------------------------------------------------------
; Public C API
; ----------------------------------------------------------------------------
;   void KeccakF1600_StatePermute_Masked(uint32_t *state0,    ; 50 words
;                                        uint32_t *state1);   ; 50 words
;
;   Permutes the masked 1600-bit state in place.
;
; ----------------------------------------------------------------------------
; Stack frame
; ----------------------------------------------------------------------------
;   On entry, after PUSH {r4-r11, lr}:
;       SF_C0    [40]   : theta C[5] for share 0           (sp + 0)
;       SF_C1    [40]   : theta C[5] for share 1           (sp + 40)
;       SF_TMP0 [200]   : rho/pi destination, share 0      (sp + 80)
;       SF_TMP1 [200]   : rho/pi destination, share 1      (sp + 280)
;       SF_ROW0  [40]   : chi row snapshot, share 0        (sp + 480)
;       SF_ROW1  [40]   : chi row snapshot, share 1        (sp + 520)
;       SF_ROUND  [4]   : current round counter            (sp + 560)
;       SF_S0PTR  [4]   : saved state0 ptr                 (sp + 564)
;       SF_S1PTR  [4]   : saved state1 ptr                 (sp + 568)
;       SF_RES_LO [4]   : SecAND lo result spill (b0_lo)   (sp + 572)
;       SF_RES_LO1 [4]  : SecAND lo result spill (b1_lo)   (sp + 576)
;       align     [4]                                       (sp + 580 -> 584)
;   Total: 584 bytes + 36 (push) = 620 bytes.  Within 11 KB budget.
; ============================================================================

        PRESERVE8
        AREA    |.text|, CODE, READONLY
        THUMB

        EXPORT  KeccakF1600_StatePermute_Masked
        EXTERN  masked_fresh_rand32

SF_C0           EQU     0
SF_C1           EQU     SF_C0      + 40
SF_TMP0         EQU     SF_C1      + 40
SF_TMP1         EQU     SF_TMP0    + 200
SF_ROW0         EQU     SF_TMP1    + 200
SF_ROW1         EQU     SF_ROW0    + 40
SF_ROUND        EQU     SF_ROW1    + 40
SF_S0PTR        EQU     SF_ROUND   + 4
SF_S1PTR        EQU     SF_S0PTR   + 4
SF_RES_LO0      EQU     SF_S1PTR   + 4
SF_RES_LO1      EQU     SF_RES_LO0 + 4
SF_END          EQU     SF_RES_LO1 + 4
SF_TOTAL        EQU     ((SF_END + 7) :AND: :NOT: 7)


; ============================================================================
; Macros
; ============================================================================

; ----------------------------------------------------------------- ;
; ROL64 a 64-bit value (lo,hi) by an immediate amount n in [0..63]. ;
; Output (tlo, thi); scratch sc; all 5 regs distinct from inputs.   ;
; ----------------------------------------------------------------- ;
        MACRO
        ROL64_IMM   $tlo, $thi, $lo, $hi, $sc, $n
        IF $n = 0
        MOV     $tlo, $lo
        MOV     $thi, $hi
        ELIF $n = 32
        MOV     $tlo, $hi
        MOV     $thi, $lo
        ELIF $n < 32
        LSL     $tlo, $lo, #$n
        LSR     $sc,  $hi, #(32 - $n)
        ORR     $tlo, $tlo, $sc
        LSL     $thi, $hi, #$n
        LSR     $sc,  $lo, #(32 - $n)
        ORR     $thi, $thi, $sc
        ELSE
        LSL     $thi, $lo, #($n - 32)
        LSR     $sc,  $hi, #(64 - $n)
        ORR     $thi, $thi, $sc
        LSL     $tlo, $hi, #($n - 32)
        LSR     $sc,  $lo, #(64 - $n)
        ORR     $tlo, $tlo, $sc
        ENDIF
        MEND

; ----------------------------------------------------------------- ;
; ISW SecAND (1st-order, 32-bit), 7-register variant.                ;
;   Inputs:                                                          ;
;       a0, a1, b0, b1   shares of A and B (each XOR-pair)            ;
;       r                fresh uniform 32-bit randomness              ;
;   Outputs:                                                          ;
;       o0, o1           shares of (A AND B)                          ;
;   CLOBBERS:                                                         ;
;       b0  (reused as scratch after its last input use; the caller   ;
;            must not need b0 to survive this macro)                  ;
; All 7 registers must be distinct.                                  ;
;                                                                    ;
; The transcript is constructed so that EVERY intermediate that       ;
; mentions both a-shares or both b-shares is XOR-masked with r BEFORE ;
; any further fold; isolated terms a1∧b0 and a1∧b1 only mix one       ;
; a-share with one b-share, which is independent of the joint values  ;
; under the sharing assumption — safe at 1st-order.                   ;
; ----------------------------------------------------------------- ;
        MACRO
        SEC_AND_32  $o0, $o1, $a0, $a1, $b0, $b1, $r
        AND     $o0, $a0, $b0           ; o0 = a0 AND b0
        EOR     $o0, $o0, $r            ; o0 = (a0 AND b0) XOR r       — final c0
        AND     $o1, $a1, $b0           ; o1 = a1 AND b0  (independent intermediate)
        AND     $b0, $a0, $b1           ; reuse b0 as scratch; b0 = a0 AND b1
        EOR     $b0, $b0, $r            ; mask BEFORE any cross-share fold
        EOR     $b0, $b0, $o1           ; b0 = (a0∧b1) XOR r XOR (a1∧b0)
        AND     $o1, $a1, $b1           ; o1 = a1 AND b1  (independent intermediate)
        EOR     $o1, $o1, $b0           ; o1 = (a1∧b1) XOR (a0∧b1) XOR r XOR (a1∧b0)
        MEND


; ============================================================================
; KeccakF1600_StatePermute_Masked
; ============================================================================
KeccakF1600_StatePermute_Masked     PROC
        PUSH    {r4-r11, lr}
        SUB     sp, sp, #SF_TOTAL

        STR     r0, [sp, #SF_S0PTR]
        STR     r1, [sp, #SF_S1PTR]

        MOV     r2, #0
        STR     r2, [sp, #SF_ROUND]

RoundLoop
        BL      Theta_Step          ; in-place per share
        BL      RhoPi_Step          ; state -> tmp -> state, per share
        BL      Chi_Step            ; in-place, masked SecAND, per (x,y)
        BL      Iota_Step           ; XOR RC into share 0 lane[0,0]

        LDR     r2, [sp, #SF_ROUND]
        ADD     r2, r2, #1
        STR     r2, [sp, #SF_ROUND]
        CMP     r2, #24
        BNE     RoundLoop

        ADD     sp, sp, #SF_TOTAL
        POP     {r4-r11, pc}
        ENDP


; ============================================================================
; Theta_Step
;
;   1. C0[x] = state0[x*5+0..4]    (5 lanes XORed together), x = 0..4
;      C1[x] = state1[x*5+0..4]    likewise
;   2. D0[x] = C0[(x+4)%5] XOR ROL64(C0[(x+1)%5], 1)
;      D1[x] same for share 1
;   3. state0[x*5+y] ^= D0[x] for all (x,y)
;      state1[x*5+y] ^= D1[x] for all (x,y)
; ============================================================================
Theta_Step      PROC
        PUSH    {r4-r11, lr}

        ; ---- Step 1: column accumulators ----------------------------- ;
        LDR     r0, [sp, #(36 + SF_S0PTR)]
        ADD     r1, sp, #(36 + SF_C0)
        BL      Theta_ComputeColumns

        LDR     r0, [sp, #(36 + SF_S1PTR)]
        ADD     r1, sp, #(36 + SF_C1)
        BL      Theta_ComputeColumns

        ; ---- Steps 2+3: D[x] and apply --------------------------------;
        LDR     r0, [sp, #(36 + SF_S0PTR)]
        ADD     r1, sp, #(36 + SF_C0)
        BL      Theta_ApplyD

        LDR     r0, [sp, #(36 + SF_S1PTR)]
        ADD     r1, sp, #(36 + SF_C1)
        BL      Theta_ApplyD

        POP     {r4-r11, pc}
        ENDP

; ----------------------------------------------------------------- ;
; Theta_ComputeColumns:                                              ;
;   r0 -> state (50 words: 25 lanes × {lo, hi})                       ;
;   r1 -> C[5] destination buffer (40 bytes)                          ;
;   For each x in 0..4: C[x] = lane[x*5+0] XOR ... XOR lane[x*5+4]    ;
; ----------------------------------------------------------------- ;
Theta_ComputeColumns    PROC
        PUSH    {r4-r9, lr}
        MOV     r2, #5                  ; x counter
ColLp
        LDMIA   r0!, {r4, r5}           ; lane y=0
        LDMIA   r0!, {r6, r7}           ; lane y=1
        EOR     r4, r4, r6
        EOR     r5, r5, r7
        LDMIA   r0!, {r6, r7}           ; lane y=2
        EOR     r4, r4, r6
        EOR     r5, r5, r7
        LDMIA   r0!, {r6, r7}           ; lane y=3
        EOR     r4, r4, r6
        EOR     r5, r5, r7
        LDMIA   r0!, {r6, r7}           ; lane y=4
        EOR     r4, r4, r6
        EOR     r5, r5, r7
        STMIA   r1!, {r4, r5}
        SUBS    r2, r2, #1
        BNE     ColLp
        POP     {r4-r9, pc}
        ENDP

; ----------------------------------------------------------------- ;
; Theta_ApplyD:                                                      ;
;   r0 -> state, r1 -> C[5]                                            ;
;   For x in 0..4:                                                     ;
;       D = C[(x+4)%5] XOR ROL64(C[(x+1)%5], 1)                        ;
;       state[x*5+y] ^= D for y in 0..4                                ;
; ----------------------------------------------------------------- ;
Theta_ApplyD    PROC
        PUSH    {r4-r11, lr}
        MOV     r10, r0                 ; preserve state ptr
        MOV     r11, r1                 ; preserve C base ptr
        MOV     r12, #0                 ; x = 0

ThxLp
        ; (x+4)%5: if (x==0) -> 4, else x-1
        CMP     r12, #0
        BNE     %F1
        MOV     r0, #4
        B       %F2
1
        SUB     r0, r12, #1
2
        ; load C[(x+4)%5] into (r4, r5)
        ADD     r1, r11, r0, LSL #3
        LDMIA   r1, {r4, r5}

        ; (x+1)%5: if (x==4) -> 0, else x+1
        CMP     r12, #4
        BNE     %F3
        MOV     r0, #0
        B       %F4
3
        ADD     r0, r12, #1
4
        ; load C[(x+1)%5] into (r6, r7)
        ADD     r1, r11, r0, LSL #3
        LDMIA   r1, {r6, r7}
        ; ROL64((r6, r7), 1) into (r8, r9)
        ;   tlo = (r6 << 1) | (r7 >> 31)
        ;   thi = (r7 << 1) | (r6 >> 31)
        LSL     r8, r6, #1
        LSR     r1, r7, #31
        ORR     r8, r8, r1
        LSL     r9, r7, #1
        LSR     r1, r6, #31
        ORR     r9, r9, r1
        ; D = (r4 ^ r8, r5 ^ r9) in (r4, r5)
        EOR     r4, r4, r8
        EOR     r5, r5, r9

        ; Apply D to lane[x*5+y] for y=0..4
        ADD     r6, r12, r12, LSL #2    ; r6 = x*5
        ADD     r6, r10, r6, LSL #3     ; r6 -> &lane[x][0]
        MOV     r0, #5
ThyLp
        LDMIA   r6, {r7, r8}
        EOR     r7, r7, r4
        EOR     r8, r8, r5
        STMIA   r6!, {r7, r8}
        SUBS    r0, r0, #1
        BNE     ThyLp

        ADD     r12, r12, #1
        CMP     r12, #5
        BNE     ThxLp
        POP     {r4-r11, pc}
        ENDP


; ============================================================================
; RhoPi_Step
;   For each share independently:
;       For i in 0..24 (source lane index):
;           tmp_pi[ pi(i) ] = ROL64( state[i], rho[i] )
;       Copy tmp_pi back to state.
;
;   The (pi, rho) lookup is the packed RhoPiTab table.
;   Rotation amounts in [0..63] are dispatched to the correct ROL64
;   variant by a small switch on rho.
; ============================================================================
RhoPi_Step      PROC
        PUSH    {lr}

        LDR     r0, [sp, #(4 + SF_S0PTR)]
        ADD     r1, sp, #(4 + SF_TMP0)
        BL      RhoPi_OneShare

        LDR     r0, [sp, #(4 + SF_S1PTR)]
        ADD     r1, sp, #(4 + SF_TMP1)
        BL      RhoPi_OneShare

        LDR     r0, [sp, #(4 + SF_S0PTR)]
        ADD     r1, sp, #(4 + SF_TMP0)
        BL      Copy50Words

        LDR     r0, [sp, #(4 + SF_S1PTR)]
        ADD     r1, sp, #(4 + SF_TMP1)
        BL      Copy50Words

        POP     {pc}
        ENDP

; ----------------------------------------------------------------- ;
; RhoPi_OneShare:                                                    ;
;   r0 -> source state (50 words)                                    ;
;   r1 -> destination tmp (50 words)                                  ;
; ----------------------------------------------------------------- ;
RhoPi_OneShare      PROC
        PUSH    {r4-r11, lr}
        LDR     r2, =RhoPiTab           ; r2 -> packed (target_idx, rho_amt)
        MOV     r3, #25
RPLp
        LDMIA   r0!, {r4, r5}           ; (lo, hi) of source lane i
        LDRB    r6, [r2], #1            ; target lane index
        LDRB    r7, [r2], #1            ; rho rotation amount

        ; Dispatch on r7 (rho amount in [0..63]).
        CMP     r7, #0
        BEQ     RPstore
        CMP     r7, #32
        BEQ     RPswap
        CMP     r7, #32
        BHI     RPhigh

        ; rho < 32 :  out_lo = (lo<<r7) | (hi>>(32-r7))
        ;             out_hi = (hi<<r7) | (lo>>(32-r7))
        RSB     r9, r7, #32             ; r9 = 32 - r7
        LSL     r8, r4, r7
        LSR     r10, r5, r9
        ORR     r8, r8, r10             ; r8 = out_lo
        LSL     r10, r5, r7
        LSR     r11, r4, r9
        ORR     r9, r10, r11            ; r9 = out_hi
        B       RPstore_R

RPswap
        MOV     r8, r5
        MOV     r9, r4
        B       RPstore_R

RPhigh
        ; rho > 32 : let n2 = rho - 32
        ;   out_hi = (lo<<n2) | (hi>>(32-n2))
        ;   out_lo = (hi<<n2) | (lo>>(32-n2))
        SUB     r7, r7, #32
        RSB     r10, r7, #32
        LSL     r9, r4, r7
        LSR     r11, r5, r10
        ORR     r9, r9, r11             ; r9 = out_hi
        LSL     r8, r5, r7
        LSR     r11, r4, r10
        ORR     r8, r8, r11             ; r8 = out_lo
        B       RPstore_R

RPstore
        MOV     r8, r4
        MOV     r9, r5

RPstore_R
        ADD     r10, r1, r6, LSL #3     ; tmp + target_idx*8
        STMIA   r10, {r8, r9}

        SUBS    r3, r3, #1
        BNE     RPLp

        POP     {r4-r11, pc}
        ENDP

; ----------------------------------------------------------------- ;
; Copy50Words: copy 50 × uint32_t (200 bytes) from r1 to r0.         ;
;   25 iterations of 2-word LDMIA/STMIA.                             ;
; ----------------------------------------------------------------- ;
Copy50Words     PROC
        PUSH    {r4-r5, lr}
        MOV     r2, #25
CpL
        LDMIA   r1!, {r4, r5}
        STMIA   r0!, {r4, r5}
        SUBS    r2, r2, #1
        BNE     CpL
        POP     {r4-r5, pc}
        ENDP


; ============================================================================
; Chi_Step
;
;   For y = 0..4:
;       Snapshot row[*][y] into row_a0[5] (share 0) and row_a1[5] (share 1)
;       For x = 0..4:
;           x1 = (x+1) % 5,  x2 = (x+2) % 5
;           NOT_a0_x1 = NOT row_a0[x1]
;           a1_x1     = row_a1[x1]
;           a0_x2     = row_a0[x2]
;           a1_x2     = row_a1[x2]
;           # SecAND on each 32-bit half (lo, hi)
;           r_lo = masked_fresh_rand32()
;           (b0_lo, b1_lo) = SecAND_32(NOT_a0_x1.lo, a1_x1.lo,
;                                      a0_x2.lo,    a1_x2.lo,
;                                      r_lo)
;           r_hi = masked_fresh_rand32()
;           (b0_hi, b1_hi) = SecAND_32(NOT_a0_x1.hi, a1_x1.hi,
;                                      a0_x2.hi,    a1_x2.hi,
;                                      r_hi)
;           state0[x*5+y] ^= (b0_lo, b0_hi)
;           state1[x*5+y] ^= (b1_lo, b1_hi)
; ============================================================================
Chi_Step        PROC
        PUSH    {r4-r11, lr}
        ; Register allocation across BLs:
        ;   r10 = y       (callee-saved -> survives BL)
        ;   r11 = x       (callee-saved -> survives BL)
        ;   r4  = &row_a0[x1]   (callee-saved)
        ;   r5  = &row_a1[x1]   (callee-saved)
        ;   r6  = &row_a0[x2]   (callee-saved)
        ;   r7  = &row_a1[x2]   (callee-saved)
        ;   r8  = fresh rand    (callee-saved; reloaded after each BL)
        ;   r9  = SecAND output o0 (callee-saved; survives between LO and HI)
        ;   r12 = SecAND output o1 (caller-saved; spilled to RES_LO1 after LO)
        ; All BLs are bracketed entirely within this register-allocation scheme;
        ; nothing caller-saved (r0..r3, r12, lr) needs to survive masked_fresh_rand32.
        MOV     r10, #0

ChiYLp
        ; ---- snapshot row of share 0 -------------------------------- ;
        LDR     r0, [sp, #(36 + SF_S0PTR)]
        ADD     r0, r0, r10, LSL #3     ; -> &state0[0*5+y]
        ADD     r1, sp, #(36 + SF_ROW0)
        MOV     r2, #5
ChiSnap0
        LDMIA   r0, {r3, r12}           ; lane (lo, hi)
        STMIA   r1!, {r3, r12}
        ADD     r0, r0, #(5*8)
        SUBS    r2, r2, #1
        BNE     ChiSnap0

        ; ---- snapshot row of share 1 -------------------------------- ;
        LDR     r0, [sp, #(36 + SF_S1PTR)]
        ADD     r0, r0, r10, LSL #3
        ADD     r1, sp, #(36 + SF_ROW1)
        MOV     r2, #5
ChiSnap1
        LDMIA   r0, {r3, r12}
        STMIA   r1!, {r3, r12}
        ADD     r0, r0, #(5*8)
        SUBS    r2, r2, #1
        BNE     ChiSnap1

        ; ---- per-x SecAND-and-XOR ----------------------------------- ;
        MOV     r11, #0
ChiXLp
        ; Compute x1 = (x+1) % 5  -> r0
        ADD     r0, r11, #1
        CMP     r0, #5
        IT      EQ
        MOVEQ   r0, #0
        ADD     r4, sp, #(36 + SF_ROW0)
        ADD     r4, r4, r0, LSL #3      ; r4 = &row_a0[x1]
        ADD     r5, sp, #(36 + SF_ROW1)
        ADD     r5, r5, r0, LSL #3      ; r5 = &row_a1[x1]

        ; Compute x2 = (x+2) % 5  -> r0
        ADD     r0, r11, #2
        CMP     r0, #5
        IT      GE
        SUBGE   r0, r0, #5
        ADD     r6, sp, #(36 + SF_ROW0)
        ADD     r6, r6, r0, LSL #3      ; r6 = &row_a0[x2]
        ADD     r7, sp, #(36 + SF_ROW1)
        ADD     r7, r7, r0, LSL #3      ; r7 = &row_a1[x2]

        ; ---- LO half SecAND -----------------------------------------;
        BL      masked_fresh_rand32
        MOV     r8, r0                  ; r8 = rand_lo

        LDR     r0, [r4, #0]            ; row_a0[x1].lo
        MVN     r0, r0                  ; NOT
        LDR     r1, [r5, #0]            ; row_a1[x1].lo
        LDR     r2, [r6, #0]            ; row_a0[x2].lo
        LDR     r3, [r7, #0]            ; row_a1[x2].lo
        SEC_AND_32  r9, r12, r0, r1, r2, r3, r8
        ;   r9  = b0_lo  (kept in callee-saved across HI BL)
        ;   r12 = b1_lo  (caller-saved, spill)
        STR     r12, [sp, #(36 + SF_RES_LO1)]

        ; ---- HI half SecAND -----------------------------------------;
        BL      masked_fresh_rand32
        MOV     r8, r0                  ; r8 = rand_hi

        LDR     r0, [r4, #4]            ; row_a0[x1].hi
        MVN     r0, r0
        LDR     r1, [r5, #4]
        LDR     r2, [r6, #4]
        LDR     r3, [r7, #4]
        ; Note: r9 currently holds b0_lo; we want b0_hi to land somewhere
        ; non-conflicting.  Use r0 (caller-saved, free after the LDRs).
        ; Actually: SEC_AND_32 needs distinct $o0, $o1 from $a0..$b1, $r.
        ; Free callee-saved here: none other than r9 (in use).
        ; Reuse r0 (a0/MVN'd, but we can let it be overwritten as o0 result)
        ; — but $a0 must remain valid through the macro.  Look at macro:
        ;     line 1: AND $o0, $a0, $b0   ← $a0 read; if $o0==$a0, $a0 destroyed.
        ;     line 4: AND $b0, $a0, $b1   ← $a0 read again.  Conflict if $o0==$a0.
        ; So $o0 must be distinct from $a0.  Use a temp register: spill r9 to
        ; a stack slot, then use r9 as $o0 again.
        STR     r9, [sp, #(36 + SF_RES_LO0)]    ; save b0_lo
        SEC_AND_32  r9, r12, r0, r1, r2, r3, r8
        ;   r9  = b0_hi
        ;   r12 = b1_hi

        ; ---- XOR (b0_lo, b0_hi, b1_lo, b1_hi) into state shares ----- ;
        ; lane byte offset = (x*5 + y) * 8
        ADD     r0, r10, r11, LSL #2    ; r0 = y + x*4
        ADD     r0, r0, r11             ; r0 = y + x*5
        LSL     r0, r0, #3              ; byte offset

        LDR     r1, [sp, #(36 + SF_S0PTR)]
        ADD     r1, r1, r0
        LDR     r2, [r1, #0]
        LDR     r3, [sp, #(36 + SF_RES_LO0)]    ; b0_lo
        EOR     r2, r2, r3
        STR     r2, [r1, #0]
        LDR     r2, [r1, #4]
        EOR     r2, r2, r9              ; r9 = b0_hi
        STR     r2, [r1, #4]

        LDR     r1, [sp, #(36 + SF_S1PTR)]
        ADD     r1, r1, r0
        LDR     r2, [r1, #0]
        LDR     r3, [sp, #(36 + SF_RES_LO1)]    ; b1_lo
        EOR     r2, r2, r3
        STR     r2, [r1, #0]
        LDR     r2, [r1, #4]
        EOR     r2, r2, r12             ; r12 = b1_hi
        STR     r2, [r1, #4]

        ADD     r11, r11, #1
        CMP     r11, #5
        BNE     ChiXLp

        ADD     r10, r10, #1
        CMP     r10, #5
        BNE     ChiYLp

        POP     {r4-r11, pc}
        ENDP


; ============================================================================
; Iota_Step:  state0[lane 0] ^= RC[round]
; ============================================================================
Iota_Step       PROC
        PUSH    {r4-r5, lr}
        LDR     r0, [sp, #(12 + SF_S0PTR)]      ; share 0 base; +12 for PUSH
        LDR     r1, [sp, #(12 + SF_ROUND)]
        LDR     r2, =KeccakRoundConstants
        ADD     r2, r2, r1, LSL #3
        LDMIA   r2, {r3, r4}                    ; RC.lo, RC.hi
        LDR     r5, [r0, #0]
        EOR     r5, r5, r3
        STR     r5, [r0, #0]
        LDR     r5, [r0, #4]
        EOR     r5, r5, r4
        STR     r5, [r0, #4]
        POP     {r4-r5, pc}
        ENDP


; ============================================================================
; Read-only data
; ============================================================================
        AREA    |.rodata|, DATA, READONLY
        ALIGN   4

; --------------------------------------------------------------------------- ;
; RhoPiTab:  25 entries, each 2 bytes:   target_lane_index | rho_rotation     ;
;   Index i = source lane (0..24)                                              ;
;   pi mapping:    B[y][(2x + 3y) mod 5] = A[x][y]                            ;
; --------------------------------------------------------------------------- ;
RhoPiTab
        DCB      0,  0      ; lane 0:  (0,0)  pi=0,  rho=0
        DCB      8,  1      ; lane 1:  (0,1)  pi=8,  rho=1
        DCB     11, 62      ; lane 2:  (0,2)  pi=11, rho=62
        DCB     19, 28      ; lane 3:  (0,3)  pi=19, rho=28
        DCB     22, 27      ; lane 4:  (0,4)  pi=22, rho=27
        DCB      2, 36      ; lane 5:  (1,0)  pi=2,  rho=36
        DCB      5, 44      ; lane 6:  (1,1)  pi=5,  rho=44
        DCB     13,  6      ; lane 7:  (1,2)  pi=13, rho=6
        DCB     16, 55      ; lane 8:  (1,3)  pi=16, rho=55
        DCB     24, 20      ; lane 9:  (1,4)  pi=24, rho=20
        DCB      4,  3      ; lane 10: (2,0)  pi=4,  rho=3
        DCB      7, 10      ; lane 11: (2,1)  pi=7,  rho=10
        DCB     10, 43      ; lane 12: (2,2)  pi=10, rho=43
        DCB     18, 25      ; lane 13: (2,3)  pi=18, rho=25
        DCB     21, 39      ; lane 14: (2,4)  pi=21, rho=39
        DCB      1, 41      ; lane 15: (3,0)  pi=1,  rho=41
        DCB      9, 45      ; lane 16: (3,1)  pi=9,  rho=45
        DCB     12, 15      ; lane 17: (3,2)  pi=12, rho=15
        DCB     15, 21      ; lane 18: (3,3)  pi=15, rho=21
        DCB     23,  8      ; lane 19: (3,4)  pi=23, rho=8
        DCB      3, 18      ; lane 20: (4,0)  pi=3,  rho=18
        DCB      6,  2      ; lane 21: (4,1)  pi=6,  rho=2
        DCB     14, 61      ; lane 22: (4,2)  pi=14, rho=61
        DCB     17, 56      ; lane 23: (4,3)  pi=17, rho=56
        DCB     20, 14      ; lane 24: (4,4)  pi=20, rho=14
        ALIGN   4

; --------------------------------------------------------------------------- ;
; Keccak-f[1600] round constants.  24 × 64-bit, little-endian (lo, hi).        ;
; --------------------------------------------------------------------------- ;
KeccakRoundConstants
        DCD     0x00000001, 0x00000000      ; RC[ 0]
        DCD     0x00008082, 0x00000000      ; RC[ 1]
        DCD     0x0000808a, 0x80000000      ; RC[ 2]
        DCD     0x80008000, 0x80000000      ; RC[ 3]
        DCD     0x0000808b, 0x00000000      ; RC[ 4]
        DCD     0x80000001, 0x00000000      ; RC[ 5]
        DCD     0x80008081, 0x80000000      ; RC[ 6]
        DCD     0x00008009, 0x80000000      ; RC[ 7]
        DCD     0x0000008a, 0x00000000      ; RC[ 8]
        DCD     0x00000088, 0x00000000      ; RC[ 9]
        DCD     0x80008009, 0x00000000      ; RC[10]
        DCD     0x8000000a, 0x00000000      ; RC[11]
        DCD     0x8000808b, 0x00000000      ; RC[12]
        DCD     0x0000008b, 0x80000000      ; RC[13]
        DCD     0x00008089, 0x80000000      ; RC[14]
        DCD     0x00008003, 0x80000000      ; RC[15]
        DCD     0x00008002, 0x80000000      ; RC[16]
        DCD     0x00000080, 0x80000000      ; RC[17]
        DCD     0x0000800a, 0x00000000      ; RC[18]
        DCD     0x8000000a, 0x80000000      ; RC[19]
        DCD     0x80008081, 0x80000000      ; RC[20]
        DCD     0x00008080, 0x80000000      ; RC[21]
        DCD     0x80000001, 0x00000000      ; RC[22]
        DCD     0x80008008, 0x80000000      ; RC[23]

        END
