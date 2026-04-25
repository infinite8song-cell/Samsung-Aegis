; Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
; Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
; denoted as "the implementer".
;
; For more information, feedback or questions, please refer to our websites:
; http://keccak.noekeon.org/
; http://keyak.noekeon.org/
; http://ketje.noekeon.org/
;
; To the extent possible under law, the implementer has waived all copyright
; and related or neighboring rights to the source code in this file.
; http://creativecommons.org/publicdomain/zero/1.0/
;
; Ported to ARM Compiler v5 armasm (armcc --asm) for SC300 (Cortex-M3)
; by conversion from GNU AS (GAS) syntax.
;
; WARNING: These functions work only on little endian CPU with
;          ARMv7-M architecture (ARM Cortex-M3 / SC300).
;
; Key differences from GNU AS:
;  - Comments use ';' instead of '@'
;  - .thumb  -> THUMB directive (must appear INSIDE or AFTER AREA, not before)
;  - .syntax unified -> unified syntax enabled by default under THUMB2
;  - .text   -> AREA |.text|, CODE, READONLY  (followed by THUMB / PRESERVE8)
;  - .macro/.endm -> MACRO/MEND
;  - .equ    -> EQU
;  - .align N -> ALIGN 2^N  (armasm ALIGN takes byte count, not log2)
;  - .global  -> EXPORT
;  - .long    -> DCD
;  - ldrd/strd with post-increment not directly supported in Thumb2 -> use
;    explicit offset form + ADD
;  - eors with shifted operand second form (eors Rd, Rn, Rm, LSR #n) is valid
;    in unified Thumb-2 syntax under armasm v5
;  - THUMB directive MUST come AFTER AREA declaration to ensure the AREA is
;    correctly marked as Thumb (ARM Compiler v5 bug/limitation)

; ---------------------------------------------------------------------------
; AREA / THUMB / PRESERVE8 in this exact order. Placing THUMB before AREA
; causes armasm v5 to silently mis-mark the section, and omitting PRESERVE8
; trips armlink L6218E when this object is linked against PRESERVE8 callers.
; ---------------------------------------------------------------------------

    AREA    |.text|, CODE, READONLY
    THUMB
    PRESERVE8

; ---------------------------------------------------------------------------
; Equates – state lane offsets (byte offsets into the 200-byte state array)
; ---------------------------------------------------------------------------

Aba0    EQU  0*4
Aba1    EQU  1*4
Abe0    EQU  2*4
Abe1    EQU  3*4
Abi0    EQU  4*4
Abi1    EQU  5*4
Abo0    EQU  6*4
Abo1    EQU  7*4
Abu0    EQU  8*4
Abu1    EQU  9*4
Aga0    EQU 10*4
Aga1    EQU 11*4
Age0    EQU 12*4
Age1    EQU 13*4
Agi0    EQU 14*4
Agi1    EQU 15*4
Ago0    EQU 16*4
Ago1    EQU 17*4
Agu0    EQU 18*4
Agu1    EQU 19*4
Aka0    EQU 20*4
Aka1    EQU 21*4
Ake0    EQU 22*4
Ake1    EQU 23*4
Aki0    EQU 24*4
Aki1    EQU 25*4
Ako0    EQU 26*4
Ako1    EQU 27*4
Aku0    EQU 28*4
Aku1    EQU 29*4
Ama0    EQU 30*4
Ama1    EQU 31*4
Ame0    EQU 32*4
Ame1    EQU 33*4
Ami0    EQU 34*4
Ami1    EQU 35*4
Amo0    EQU 36*4
Amo1    EQU 37*4
Amu0    EQU 38*4
Amu1    EQU 39*4
Asa0    EQU 40*4
Asa1    EQU 41*4
Ase0    EQU 42*4
Ase1    EQU 43*4
Asi0    EQU 44*4
Asi1    EQU 45*4
Aso0    EQU 46*4
Aso1    EQU 47*4
Asu0    EQU 48*4
Asu1    EQU 49*4

; Stack-frame offsets used during KeccakF1600_StatePermute
mDa0    EQU 0*4
mDa1    EQU 1*4
mDo0    EQU 2*4
mDo1    EQU 3*4
mDi0    EQU 4*4
mRC     EQU 5*4
mSize   EQU 6*4

; ===========================================================================
; Macro: toBitInterleaving  x0, x1, s0, s1, t, over
;
;   Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002
;
;   Parameters (all registers):
;     $x0, $x1  – input words (even/odd)
;     $s0, $s1  – output/accumulate words
;     $t        – scratch register
;     $over     – literal 0 or 1  (1 = overwrite s0/s1, 0 = XOR into s0/s1)
; ===========================================================================
    MACRO
    toBitInterleaving $x0, $x1, $s0, $s1, $t, $over
    AND     $t,  $x0, #0x55555555
    ORR     $t,  $t,  $t,  LSR #1
    AND     $t,  $t,  #0x33333333
    ORR     $t,  $t,  $t,  LSR #2
    AND     $t,  $t,  #0x0F0F0F0F
    ORR     $t,  $t,  $t,  LSR #4
    AND     $t,  $t,  #0x00FF00FF
    BFI     $t,  $t,  #8, #8
    IF $over != 0
    LSR     $s0, $t,  #8
    ELSE
    EOR     $s0, $s0, $t,  LSR #8
    ENDIF
    AND     $t,  $x1, #0x55555555
    ORR     $t,  $t,  $t,  LSR #1
    AND     $t,  $t,  #0x33333333
    ORR     $t,  $t,  $t,  LSR #2
    AND     $t,  $t,  #0x0F0F0F0F
    ORR     $t,  $t,  $t,  LSR #4
    AND     $t,  $t,  #0x00FF00FF
    ORR     $t,  $t,  $t,  LSR #8
    EOR     $s0, $s0, $t,  LSL #16
    AND     $t,  $x0, #0xAAAAAAAA
    ORR     $t,  $t,  $t,  LSL #1
    AND     $t,  $t,  #0xCCCCCCCC
    ORR     $t,  $t,  $t,  LSL #2
    AND     $t,  $t,  #0xF0F0F0F0
    ORR     $t,  $t,  $t,  LSL #4
    AND     $t,  $t,  #0xFF00FF00
    ORR     $t,  $t,  $t,  LSL #8
    IF $over != 0
    LSR     $s1, $t,  #16
    ELSE
    EOR     $s1, $s1, $t,  LSR #16
    ENDIF
    AND     $t,  $x1, #0xAAAAAAAA
    ORR     $t,  $t,  $t,  LSL #1
    AND     $t,  $t,  #0xCCCCCCCC
    ORR     $t,  $t,  $t,  LSL #2
    AND     $t,  $t,  #0xF0F0F0F0
    ORR     $t,  $t,  $t,  LSL #4
    AND     $t,  $t,  #0xFF00FF00
    ORR     $t,  $t,  $t,  LSL #8
    BFC     $t,  #0, #16
    EORS    $s1, $s1, $t
    MEND

; ===========================================================================
; Macro: fromBitInterleaving  x0, x1, t
; ===========================================================================
    MACRO
    fromBitInterleaving $x0, $x1, $t
    MOVS    $t,  $x0                      ; t  = x0
    BFI     $x0, $x1, #16, #16            ; x0 = (x0 & 0x0000FFFF) | (x1<<16)
    BFC     $x1, #0,  #16                 ; x1 = x1 & 0xFFFF0000
    ORR     $x1, $x1, $t, LSR #16         ; x1 = x1 | (t >> 16)
    EOR     $t,  $x0, $x0, LSR #8
    AND     $t,  $t,  #0x0000FF00
    EORS    $x0, $x0, $t
    EOR     $x0, $x0, $t, LSL #8
    EOR     $t,  $x0, $x0, LSR #4
    AND     $t,  $t,  #0x00F000F0
    EORS    $x0, $x0, $t
    EOR     $x0, $x0, $t, LSL #4
    EOR     $t,  $x0, $x0, LSR #2
    AND     $t,  $t,  #0x0C0C0C0C
    EORS    $x0, $x0, $t
    EOR     $x0, $x0, $t, LSL #2
    EOR     $t,  $x0, $x0, LSR #1
    AND     $t,  $t,  #0x22222222
    EORS    $x0, $x0, $t
    EOR     $x0, $x0, $t, LSL #1
    EOR     $t,  $x1, $x1, LSR #8
    AND     $t,  $t,  #0x0000FF00
    EORS    $x1, $x1, $t
    EOR     $x1, $x1, $t, LSL #8
    EOR     $t,  $x1, $x1, LSR #4
    AND     $t,  $t,  #0x00F000F0
    EORS    $x1, $x1, $t
    EOR     $x1, $x1, $t, LSL #4
    EOR     $t,  $x1, $x1, LSR #2
    AND     $t,  $t,  #0x0C0C0C0C
    EORS    $x1, $x1, $t
    EOR     $x1, $x1, $t, LSL #2
    EOR     $t,  $x1, $x1, LSR #1
    AND     $t,  $t,  #0x22222222
    EORS    $x1, $x1, $t
    EOR     $x1, $x1, $t, LSL #1
    MEND

; ===========================================================================
; Macro: xor5  result, b, g, k, m, s
;   XORs five lane words from state (r0-based) into $result; uses r1 as temp.
; ===========================================================================
    MACRO
    xor5 $result, $b, $g, $k, $m, $s
    LDR     $result, [r0, #$b]
    LDR     r1,      [r0, #$g]
    EORS    $result, $result, r1
    LDR     r1,      [r0, #$k]
    EORS    $result, $result, r1
    LDR     r1,      [r0, #$m]
    EORS    $result, $result, r1
    LDR     r1,      [r0, #$s]
    EORS    $result, $result, r1
    MEND

; ===========================================================================
; Macro: xorrol  result, aa, bb
;   result = aa EOR (bb ROR 31)  i.e. aa EOR ROL(bb,1)
; ===========================================================================
    MACRO
    xorrol $result, $aa, $bb
    EOR     $result, $aa, $bb, ROR #31
    MEND

; ===========================================================================
; Macro: xandnot  resofs, aa, bb, cc
;   mem[r0 + resofs] = aa EOR (NOT(bb) AND cc)
;   Uses r1 as scratch.
; ===========================================================================
    MACRO
    xandnot $resofs, $aa, $bb, $cc
    BIC     r1,  $cc, $bb
    EORS    r1,  r1,  $aa
    STR     r1,  [r0, #$resofs]
    MEND

; ===========================================================================
; Macro: KeccakThetaRhoPiChiIota
; ===========================================================================
    MACRO
    KeccakThetaRhoPiChiIota $aA1, $aDax, $aA2, $aDex, $rot2, $aA3, $aDix, $rot3, $aA4, $aDox, $rot4, $aA5, $aDux, $rot5, $offset, $last
    LDR     r3,  [r0, #$aA1]
    LDR     r4,  [r0, #$aA2]
    LDR     r5,  [r0, #$aA3]
    LDR     r6,  [r0, #$aA4]
    LDR     r7,  [r0, #$aA5]
    EORS    r3,  r3,  $aDax
    EORS    r5,  r5,  $aDix
    EORS    r4,  r4,  $aDex
    EORS    r6,  r6,  $aDox
    EORS    r7,  r7,  $aDux
    ROR     r4,  r4,  #(32-$rot2)
    ROR     r5,  r5,  #(32-$rot3)
    ROR     r6,  r6,  #(32-$rot4)
    ROR     r7,  r7,  #(32-$rot5)
    xandnot $aA2, r4, r5, r6
    xandnot $aA3, r5, r6, r7
    xandnot $aA4, r6, r7, r3
    xandnot $aA5, r7, r3, r4
    LDR     r1,  [sp, #mRC]
    BIC     r5,  r5,  r4
    LDR     r4,  [r1, #$offset]
    EORS    r3,  r3,  r5
    EORS    r3,  r3,  r4
    IF $last == 1
    LDR     r4,  [r1, #32]!
    STR     r1,  [sp, #mRC]
    CMP     r4,  #0xFF
    ENDIF
    STR     r3,  [r0, #$aA1]
    MEND

; ===========================================================================
; Macro: KeccakThetaRhoPiChi
; ===========================================================================
    MACRO
    KeccakThetaRhoPiChi $aB1, $aA1, $aDax, $rot1, $aB2, $aA2, $aDex, $rot2, $aB3, $aA3, $aDix, $rot3, $aB4, $aA4, $aDox, $rot4, $aB5, $aA5, $aDux, $rot5
    LDR     $aB1, [r0, #$aA1]
    LDR     $aB2, [r0, #$aA2]
    LDR     $aB3, [r0, #$aA3]
    LDR     $aB4, [r0, #$aA4]
    LDR     $aB5, [r0, #$aA5]
    EORS    $aB1, $aB1, $aDax
    EORS    $aB3, $aB3, $aDix
    EORS    $aB2, $aB2, $aDex
    EORS    $aB4, $aB4, $aDox
    EORS    $aB5, $aB5, $aDux
    ROR     $aB1, $aB1, #(32-$rot1)
    IF $rot2 > 0
    ROR     $aB2, $aB2, #(32-$rot2)
    ENDIF
    ROR     $aB3, $aB3, #(32-$rot3)
    ROR     $aB4, $aB4, #(32-$rot4)
    ROR     $aB5, $aB5, #(32-$rot5)
    xandnot $aA1, r3, r4, r5
    xandnot $aA2, r4, r5, r6
    xandnot $aA3, r5, r6, r7
    xandnot $aA4, r6, r7, r3
    xandnot $aA5, r7, r3, r4
    MEND

; ===========================================================================
; Macro: KeccakRound0
; ===========================================================================
    MACRO
    KeccakRound0
    xor5    r3,  Abu0, Agu0, Aku0, Amu0, Asu0
    xor5    r7,  Abe1, Age1, Ake1, Ame1, Ase1
    xorrol  r6,  r3,   r7
    STR     r6,  [sp, #mDa0]
    xor5    r6,  Abu1, Agu1, Aku1, Amu1, Asu1
    xor5    lr,  Abe0, Age0, Ake0, Ame0, Ase0
    EORS    r8,  r6,   lr
    STR     r8,  [sp, #mDa1]
    xor5    r5,  Abi0, Agi0, Aki0, Ami0, Asi0
    xorrol  r9,  r5,   r6
    STR     r9,  [sp, #mDo0]
    xor5    r4,  Abi1, Agi1, Aki1, Ami1, Asi1
    EORS    r3,  r3,   r4
    STR     r3,  [sp, #mDo1]
    xor5    r3,  Aba0, Aga0, Aka0, Ama0, Asa0
    xorrol  r10, r3,   r4
    xor5    r6,  Aba1, Aga1, Aka1, Ama1, Asa1
    EORS    r11, r6,   r5
    xor5    r4,  Abo1, Ago1, Ako1, Amo1, Aso1
    xorrol  r5,  lr,   r4
    STR     r5,  [sp, #mDi0]
    xor5    r5,  Abo0, Ago0, Ako0, Amo0, Aso0
    EORS    r2,  r7,   r5
    xorrol  r12, r5,   r6
    EORS    lr,  r4,   r3
    KeccakThetaRhoPiChi r5, Aka1, r8,  2,  r6, Ame1, r11, 23, r7, Asi1, r2,  31, r3, Abo0,  r9,  14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Asa1, r8,  9,  r3, Abe0, r10,  0, r4, Agi1, r2,   3, r5, Ako0,  r9,  12, r6, Amu1,  lr,  4
    LDR     r8,  [sp, #mDa0]
    KeccakThetaRhoPiChi r4, Aga0, r8,  18, r5, Ake0, r10,  5, r6, Ami1, r2,   8, r7, Aso0,  r9,  28, r3, Abu1,  lr, 14
    KeccakThetaRhoPiChi r6, Ama0, r8,  20, r7, Ase1, r11,  1, r3, Abi1, r2,  31, r4, Ago0,  r9,  27, r5, Aku0, r12, 19
    LDR     r9,  [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, Age0, r10, 22, Aki1, r2, 22, Amo1, r9, 11, Asu0, r12, 7, 0, 0
    LDR     r2,  [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Aka0, r8,   1, r6, Ame0, r10, 22, r7, Asi0,  r2, 30, r3, Abo1,  r9, 14, r4, Agu1,  lr, 10
    KeccakThetaRhoPiChi r7, Asa0, r8,   9, r3, Abe1, r11,  1, r4, Agi0,  r2,  3, r5, Ako1,  r9, 13, r6, Amu0, r12,  4
    LDR     r8,  [sp, #mDa1]
    KeccakThetaRhoPiChi r4, Aga1, r8,  18, r5, Ake1, r11,  5, r6, Ami0,  r2,  7, r7, Aso1,  r9, 28, r3, Abu0, r12, 13
    KeccakThetaRhoPiChi r6, Ama1, r8,  21, r7, Ase0, r10,  1, r3, Abi0,  r2, 31, r4, Ago1,  r9, 28, r5, Aku1,  lr, 20
    LDR     r9,  [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, Age1, r11, 22, Aki0, r2, 21, Amo0, r9, 10, Asu1,  lr, 7, 4, 0
    MEND

; ===========================================================================
; Macro: KeccakRound1
; ===========================================================================
    MACRO
    KeccakRound1
    xor5    r3,  Asu0, Agu0, Amu0, Abu1, Aku1
    xor5    r7,  Age1, Ame0, Abe0, Ake1, Ase1
    xorrol  r6,  r3,   r7
    STR     r6,  [sp, #mDa0]
    xor5    r6,  Asu1, Agu1, Amu1, Abu0, Aku0
    xor5    lr,  Age0, Ame1, Abe1, Ake0, Ase0
    EORS    r8,  r6,   lr
    STR     r8,  [sp, #mDa1]
    xor5    r5,  Aki1, Asi1, Agi0, Ami1, Abi0
    xorrol  r9,  r5,   r6
    STR     r9,  [sp, #mDo0]
    xor5    r4,  Aki0, Asi0, Agi1, Ami0, Abi1
    EORS    r3,  r3,   r4
    STR     r3,  [sp, #mDo1]
    xor5    r3,  Aba0, Aka1, Asa0, Aga0, Ama1
    xorrol  r10, r3,   r4
    xor5    r6,  Aba1, Aka0, Asa1, Aga1, Ama0
    EORS    r11, r6,   r5
    xor5    r4,  Amo0, Abo1, Ako0, Aso1, Ago0
    xorrol  r5,  lr,   r4
    STR     r5,  [sp, #mDi0]
    xor5    r5,  Amo1, Abo0, Ako1, Aso0, Ago1
    EORS    r2,  r7,   r5
    xorrol  r12, r5,   r6
    EORS    lr,  r4,   r3
    KeccakThetaRhoPiChi r5, Asa1, r8,  2,  r6, Ake1, r11, 23, r7, Abi1, r2,  31, r3, Amo1,  r9, 14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Ama0, r8,  9,  r3, Age0, r10,  0, r4, Asi0, r2,   3, r5, Ako1,  r9, 12, r6, Abu0,  lr,  4
    LDR     r8,  [sp, #mDa0]
    KeccakThetaRhoPiChi r4, Aka1, r8,  18, r5, Abe1, r10,  5, r6, Ami0, r2,   8, r7, Ago1,  r9, 28, r3, Asu1,  lr, 14
    KeccakThetaRhoPiChi r6, Aga0, r8,  20, r7, Ase1, r11,  1, r3, Aki0, r2,  31, r4, Abo0,  r9, 27, r5, Amu0, r12, 19
    LDR     r9,  [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, Ame1, r10, 22, Agi1, r2, 22, Aso1, r9, 11, Aku1, r12, 7, 8, 0
    LDR     r2,  [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Asa0, r8,   1, r6, Ake0, r10, 22, r7, Abi0,  r2, 30, r3, Amo0,  r9, 14, r4, Agu1,  lr, 10
    KeccakThetaRhoPiChi r7, Ama1, r8,   9, r3, Age1, r11,  1, r4, Asi1,  r2,  3, r5, Ako0,  r9, 13, r6, Abu1, r12,  4
    LDR     r8,  [sp, #mDa1]
    KeccakThetaRhoPiChi r4, Aka0, r8,  18, r5, Abe0, r11,  5, r6, Ami1,  r2,  7, r7, Ago0,  r9, 28, r3, Asu0, r12, 13
    KeccakThetaRhoPiChi r6, Aga1, r8,  21, r7, Ase0, r10,  1, r3, Aki1,  r2, 31, r4, Abo1,  r9, 28, r5, Amu1,  lr, 20
    LDR     r9,  [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, Ame0, r11, 22, Agi0, r2, 21, Aso0, r9, 10, Aku0,  lr, 7, 12, 0
    MEND

; ===========================================================================
; Macro: KeccakRound2
; ===========================================================================
    MACRO
    KeccakRound2
    xor5    r3,  Aku1, Agu0, Abu1, Asu1, Amu1
    xor5    r7,  Ame0, Ake0, Age0, Abe0, Ase1
    xorrol  r6,  r3,   r7
    STR     r6,  [sp, #mDa0]
    xor5    r6,  Aku0, Agu1, Abu0, Asu0, Amu0
    xor5    lr,  Ame1, Ake1, Age1, Abe1, Ase0
    EORS    r8,  r6,   lr
    STR     r8,  [sp, #mDa1]
    xor5    r5,  Agi1, Abi1, Asi1, Ami0, Aki1
    xorrol  r9,  r5,   r6
    STR     r9,  [sp, #mDo0]
    xor5    r4,  Agi0, Abi0, Asi0, Ami1, Aki0
    EORS    r3,  r3,   r4
    STR     r3,  [sp, #mDo1]
    xor5    r3,  Aba0, Asa1, Ama1, Aka1, Aga1
    xorrol  r10, r3,   r4
    xor5    r6,  Aba1, Asa0, Ama0, Aka0, Aga0
    EORS    r11, r6,   r5
    xor5    r4,  Aso0, Amo0, Ako1, Ago0, Abo0
    xorrol  r5,  lr,   r4
    STR     r5,  [sp, #mDi0]
    xor5    r5,  Aso1, Amo1, Ako0, Ago1, Abo1
    EORS    r2,  r7,   r5
    xorrol  r12, r5,   r6
    EORS    lr,  r4,   r3
    KeccakThetaRhoPiChi r5, Ama0, r8,  2,  r6, Abe0, r11, 23, r7, Aki0, r2,  31, r3, Aso1,  r9, 14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Aga0, r8,  9,  r3, Ame1, r10,  0, r4, Abi0, r2,   3, r5, Ako0,  r9, 12, r6, Asu0,  lr,  4
    LDR     r8,  [sp, #mDa0]
    KeccakThetaRhoPiChi r4, Asa1, r8,  18, r5, Age1, r10,  5, r6, Ami1, r2,   8, r7, Abo1,  r9, 28, r3, Aku0,  lr, 14
    KeccakThetaRhoPiChi r6, Aka1, r8,  20, r7, Ase1, r11,  1, r3, Agi0, r2,  31, r4, Amo1,  r9, 27, r5, Abu1, r12, 19
    LDR     r9,  [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, Ake1, r10, 22, Asi0, r2, 22, Ago0, r9, 11, Amu1, r12, 7, 16, 0
    LDR     r2,  [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Ama1, r8,   1, r6, Abe1, r10, 22, r7, Aki1,  r2, 30, r3, Aso0,  r9, 14, r4, Agu1,  lr, 10
    KeccakThetaRhoPiChi r7, Aga1, r8,   9, r3, Ame0, r11,  1, r4, Abi1,  r2,  3, r5, Ako1,  r9, 13, r6, Asu1, r12,  4
    LDR     r8,  [sp, #mDa1]
    KeccakThetaRhoPiChi r4, Asa0, r8,  18, r5, Age0, r11,  5, r6, Ami0,  r2,  7, r7, Abo0,  r9, 28, r3, Aku1, r12, 13
    KeccakThetaRhoPiChi r6, Aka0, r8,  21, r7, Ase0, r10,  1, r3, Agi1,  r2, 31, r4, Amo0,  r9, 28, r5, Abu0,  lr, 20
    LDR     r9,  [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, Ake0, r11, 22, Asi1, r2, 21, Ago1, r9, 10, Amu0,  lr, 7, 20, 0
    MEND

; ===========================================================================
; Macro: KeccakRound3
; ===========================================================================
    MACRO
    KeccakRound3
    xor5    r3,  Amu1, Agu0, Asu1, Aku0, Abu0
    xor5    r7,  Ake0, Abe1, Ame1, Age0, Ase1
    xorrol  r6,  r3,   r7
    STR     r6,  [sp, #mDa0]
    xor5    r6,  Amu0, Agu1, Asu0, Aku1, Abu1
    xor5    lr,  Ake1, Abe0, Ame0, Age1, Ase0
    EORS    r8,  r6,   lr
    STR     r8,  [sp, #mDa1]
    xor5    r5,  Asi0, Aki0, Abi1, Ami1, Agi1
    xorrol  r9,  r5,   r6
    STR     r9,  [sp, #mDo0]
    xor5    r4,  Asi1, Aki1, Abi0, Ami0, Agi0
    EORS    r3,  r3,   r4
    STR     r3,  [sp, #mDo1]
    xor5    r3,  Aba0, Ama0, Aga1, Asa1, Aka0
    xorrol  r10, r3,   r4
    xor5    r6,  Aba1, Ama1, Aga0, Asa0, Aka1
    EORS    r11, r6,   r5
    xor5    r4,  Ago1, Aso0, Ako0, Abo0, Amo1
    xorrol  r5,  lr,   r4
    STR     r5,  [sp, #mDi0]
    xor5    r5,  Ago0, Aso1, Ako1, Abo1, Amo0
    EORS    r2,  r7,   r5
    xorrol  r12, r5,   r6
    EORS    lr,  r4,   r3
    KeccakThetaRhoPiChi r5, Aga0, r8,  2,  r6, Age0, r11, 23, r7, Agi0, r2,  31, r3, Ago0,  r9, 14, r4, Agu0, r12, 10
    KeccakThetaRhoPiChi r7, Aka1, r8,  9,  r3, Ake1, r10,  0, r4, Aki1, r2,   3, r5, Ako1,  r9, 12, r6, Aku1,  lr,  4
    LDR     r8,  [sp, #mDa0]
    KeccakThetaRhoPiChi r4, Ama0, r8,  18, r5, Ame0, r10,  5, r6, Ami0, r2,   8, r7, Amo0,  r9, 28, r3, Amu0,  lr, 14
    KeccakThetaRhoPiChi r6, Asa1, r8,  20, r7, Ase1, r11,  1, r3, Asi1, r2,  31, r4, Aso1,  r9, 27, r5, Asu1, r12, 19
    LDR     r9,  [sp, #mDo1]
    KeccakThetaRhoPiChiIota Aba0, r8, Abe0, r10, 22, Abi0, r2, 22, Abo0, r9, 11, Abu0, r12, 7, 24, 0
    LDR     r2,  [sp, #mDi0]
    KeccakThetaRhoPiChi r5, Aga1, r8,   1, r6, Age1, r10, 22, r7, Agi1,  r2, 30, r3, Ago1,  r9, 14, r4, Agu1,  lr, 10
    KeccakThetaRhoPiChi r7, Aka0, r8,   9, r3, Ake0, r11,  1, r4, Aki0,  r2,  3, r5, Ako0,  r9, 13, r6, Aku0, r12,  4
    LDR     r8,  [sp, #mDa1]
    KeccakThetaRhoPiChi r4, Ama1, r8,  18, r5, Ame1, r11,  5, r6, Ami1,  r2,  7, r7, Amo1,  r9, 28, r3, Amu1, r12, 13
    KeccakThetaRhoPiChi r6, Asa0, r8,  21, r7, Ase0, r10,  1, r3, Asi0,  r2, 31, r4, Aso0,  r9, 28, r5, Asu0,  lr, 20
    LDR     r9,  [sp, #mDo0]
    KeccakThetaRhoPiChiIota Aba1, r8, Abe1, r11, 22, Abi1, r2, 21, Abo1, r9, 10, Abu1,  lr, 7, 28, 1
    MEND

; ===========================================================================
;
; void KeccakF1600_Initialize( void )
;
; ===========================================================================
    ALIGN   4
    EXPORT  KeccakF1600_Initialize
KeccakF1600_Initialize
    BX      lr

; ===========================================================================
;
; void KeccakF1600_StateXORBytes(void *state, const unsigned char *data,
;                                unsigned int offset, unsigned int length)
;
; ===========================================================================
    ALIGN   4
    EXPORT  KeccakF1600_StateXORBytes
KeccakF1600_StateXORBytes
    CBZ     r3, KeccakF1600_StateXORBytes_Exit1
    PUSH    {r4-r8, lr}
    BIC     r4, r2, #7              ; round down offset to lane boundary
    ADDS    r0, r0, r4
    ANDS    r2, r2, #7              ; byte offset within lane
    BEQ     KeccakF1600_StateXORBytes_CheckLanes
    MOVS    r4, r3
    RSB     r5, r2, #8
    CMP     r4, r5
    BLE     KeccakF1600_StateXORBytes_BytesAlign
    MOVS    r4, r5
KeccakF1600_StateXORBytes_BytesAlign
    SUB     r8, r3, r4
    MOVS    r3, r4
    BL      __KeccakF1600_StateXORBytesInLane
    MOV     r3, r8
KeccakF1600_StateXORBytes_CheckLanes
    LSRS    r2, r3, #3
    BEQ     KeccakF1600_StateXORBytes_Bytes
    MOV     r8, r3
    BL      __KeccakF1600_StateXORLanes
    AND     r3, r8, #7
KeccakF1600_StateXORBytes_Bytes
    CBZ     r3, KeccakF1600_StateXORBytes_Exit
    MOVS    r2, #0
    BL      __KeccakF1600_StateXORBytesInLane
KeccakF1600_StateXORBytes_Exit
    POP     {r4-r8, pc}
KeccakF1600_StateXORBytes_Exit1
    BX      lr

; ---------------------------------------------------------------------------
; __KeccakF1600_StateXORLanes
;   r0 – state pointer (updated)
;   r1 – data pointer  (updated)
;   r2 – laneCount
;   Changed: r2-r7
; ---------------------------------------------------------------------------
    ALIGN   4
__KeccakF1600_StateXORLanes
__KeccakF1600_StateXORLanes_LoopAligned
    LDR     r4, [r1], #4
    LDR     r5, [r1], #4
    ; LDRD with post-increment: armasm v5 Thumb-2 form
    LDRD    r6, r7, [r0]
    toBitInterleaving r4, r5, r6, r7, r3, 0
    STRD    r6, r7, [r0]
    ADD     r0, r0, #8
    SUBS    r2, r2, #1
    BNE     __KeccakF1600_StateXORLanes_LoopAligned
    BX      lr

; ---------------------------------------------------------------------------
; __KeccakF1600_StateXORBytesInLane
;   r0 – state pointer (updated to next lane)
;   r1 – data pointer  (updated)
;   r2 – offset in lane
;   r3 – length
;   Changed: r2-r7
; ---------------------------------------------------------------------------
    ALIGN   4
__KeccakF1600_StateXORBytesInLane
    MOVS    r4, #0
    MOVS    r5, #0
    PUSH    {r4-r5}
    ADD     r2, r2, sp
__KeccakF1600_StateXORBytesInLane_Loop
    LDRB    r5, [r1], #1
    STRB    r5, [r2], #1
    SUBS    r3, r3, #1
    BNE     __KeccakF1600_StateXORBytesInLane_Loop
    POP     {r4-r5}
    LDRD    r6, r7, [r0]
    toBitInterleaving r4, r5, r6, r7, r3, 0
    STRD    r6, r7, [r0]
    ADD     r0, r0, #8
    BX      lr

; ===========================================================================
;
; void KeccakF1600_StateExtractBytes(void *state, const unsigned char *data,
;                                    unsigned int offset, unsigned int length)
;
; ===========================================================================
    ALIGN   4
    EXPORT  KeccakF1600_StateExtractBytes
KeccakF1600_StateExtractBytes
    CBZ     r3, KeccakF1600_StateExtractBytes_Exit1
    PUSH    {r4-r8, lr}
    BIC     r4, r2, #7
    ADDS    r0, r0, r4
    ANDS    r2, r2, #7
    BEQ     KeccakF1600_StateExtractBytes_CheckLanes
    MOVS    r4, r3
    RSB     r5, r2, #8
    CMP     r4, r5
    BLE     KeccakF1600_StateExtractBytes_BytesAlign
    MOVS    r4, r5
KeccakF1600_StateExtractBytes_BytesAlign
    SUB     r8, r3, r4
    MOVS    r3, r4
    BL      __KeccakF1600_StateExtractBytesInLane
    MOV     r3, r8
KeccakF1600_StateExtractBytes_CheckLanes
    LSRS    r2, r3, #3
    BEQ     KeccakF1600_StateExtractBytes_Bytes
    MOV     r8, r3
    BL      __KeccakF1600_StateExtractLanes
    AND     r3, r8, #7
KeccakF1600_StateExtractBytes_Bytes
    CBZ     r3, KeccakF1600_StateExtractBytes_Exit
    MOVS    r2, #0
    BL      __KeccakF1600_StateExtractBytesInLane
KeccakF1600_StateExtractBytes_Exit
    POP     {r4-r8, pc}
KeccakF1600_StateExtractBytes_Exit1
    BX      lr

; ---------------------------------------------------------------------------
; __KeccakF1600_StateExtractLanes
;   r0 – state pointer (updated)
;   r1 – data pointer  (updated)
;   r2 – laneCount
;   Changed: r2-r5
; ---------------------------------------------------------------------------
    ALIGN   4
__KeccakF1600_StateExtractLanes
__KeccakF1600_StateExtractLanes_LoopAligned
    LDRD    r4, r5, [r0]
    ADD     r0, r0, #8
    fromBitInterleaving r4, r5, r3
    STR     r4, [r1], #4
    SUBS    r2, r2, #1
    STR     r5, [r1], #4
    BNE     __KeccakF1600_StateExtractLanes_LoopAligned
    BX      lr

; ---------------------------------------------------------------------------
; __KeccakF1600_StateExtractBytesInLane
;   r0 – state pointer (updated to next lane)
;   r1 – data pointer  (updated)
;   r2 – offset in lane
;   r3 – length
;   Changed: r2-r6
; ---------------------------------------------------------------------------
    ALIGN   4
__KeccakF1600_StateExtractBytesInLane
    LDRD    r4, r5, [r0]
    ADD     r0, r0, #8
    fromBitInterleaving r4, r5, r6
    PUSH    {r4, r5}
    ADD     r2, sp, r2
__KeccakF1600_StateExtractBytesInLane_Loop
    LDRB    r4, [r2], #1
    SUBS    r3, r3, #1
    STRB    r4, [r1], #1
    BNE     __KeccakF1600_StateExtractBytesInLane_Loop
    ADD     sp, sp, #8
    BX      lr

; ===========================================================================
; Round constants table (24 rounds × 2 words, plus 0xFF terminator)
; Address loaded via MOVW/MOVT :LOWER16:/:UPPER16: at the top of
; KeccakF1600_StatePermute (avoids armasm v5.06 LDR-literal range issues
; that bit ASM/intt_asm.s; see commit 88ea349).
; ===========================================================================
    ALIGN   4
KeccakF1600_StatePermute_RoundConstantsWithTerminator
    ; word0 (even interleaved),  word1 (odd interleaved)
    DCD     0x00000001, 0x00000000   ; RC[ 0]
    DCD     0x00000000, 0x00000089   ; RC[ 1]
    DCD     0x00000000, 0x8000008B   ; RC[ 2]
    DCD     0x00000000, 0x80008080   ; RC[ 3]
    DCD     0x00000001, 0x0000008B   ; RC[ 4]
    DCD     0x00000001, 0x00008000   ; RC[ 5]
    DCD     0x00000001, 0x80008088   ; RC[ 6]
    DCD     0x00000001, 0x80000082   ; RC[ 7]
    DCD     0x00000000, 0x0000000B   ; RC[ 8]
    DCD     0x00000000, 0x0000000A   ; RC[ 9]
    DCD     0x00000001, 0x00008082   ; RC[10]
    DCD     0x00000000, 0x00008003   ; RC[11]
    DCD     0x00000001, 0x0000808B   ; RC[12]
    DCD     0x00000001, 0x8000000B   ; RC[13]
    DCD     0x00000001, 0x8000008A   ; RC[14]
    DCD     0x00000001, 0x80000081   ; RC[15]
    DCD     0x00000000, 0x80000081   ; RC[16]
    DCD     0x00000000, 0x80000008   ; RC[17]
    DCD     0x00000000, 0x00000083   ; RC[18]
    DCD     0x00000000, 0x80008003   ; RC[19]
    DCD     0x00000001, 0x80008088   ; RC[20]
    DCD     0x00000000, 0x80000088   ; RC[21]
    DCD     0x00000001, 0x00008000   ; RC[22]
    DCD     0x00000000, 0x80008082   ; RC[23]
    DCD     0x000000FF               ; terminator

; ===========================================================================
;
; void KeccakF1600_StatePermute( void *state )
;
; ===========================================================================
    ALIGN   4
    EXPORT  KeccakF1600_StatePermute
KeccakF1600_StatePermute
    MOVW    r1, #:LOWER16:KeccakF1600_StatePermute_RoundConstantsWithTerminator
    MOVT    r1, #:UPPER16:KeccakF1600_StatePermute_RoundConstantsWithTerminator
    PUSH    {r4-r12, lr}
    SUB     sp, sp, #mSize
    STR     r1, [sp, #mRC]
KeccakF1600_StatePermute_RoundLoop
    KeccakRound0
    KeccakRound1
    KeccakRound2
    KeccakRound3
    BNE     KeccakF1600_StatePermute_RoundLoop
    ADD     sp, sp, #mSize
    POP     {r4-r12, pc}

    END
