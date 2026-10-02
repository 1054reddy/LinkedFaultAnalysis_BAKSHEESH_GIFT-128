# ===================================================================
# baksheesh_round1.s
#
# BAKSHEESH block cipher -- ROUND 1 ONLY, implemented in plain RV32I
# assembly (no pseudo-crypto instructions, just add/xor/shift/load).
#
# Matches the reference Python model (src/baksheesh.py in the
# baksheesh_lfa research repo) step for step:
#   x        = plaintext XOR k[1]                (initial whitening)
#   y        = SubCells(x)                        (32 parallel 4-bit S-boxes)
#   z        = PermBits(y)                        (128-bit wire permutation)
#   z        = AddConstants(z, round=1)           (XOR 6-bit round constant)
#   state    = z XOR k[2]                          (AddRoundKey, round 1)
#
# STATE / KEY REPRESENTATION
#   The 128-bit cipher state is split into four 32-bit words held in
#   registers x10..x13 (S0 = least-significant 32 bits .. S3 = most
#   significant 32 bits), matching the assignment's "S0,S1,S2,S3 in
#   x10-x13".
#
#   *** TWO REAL RISC-V ABI GOTCHAS, BOTH HIT AND FIXED WHILE WRITING
#       THIS FILE -- WORTH UNDERSTANDING BEFORE YOU EXTEND IT ***
#
#   1) x10-x13 are ALSO the standard argument registers a0-a3. Any
#      subroutine call (including ecall-based print routines) wants
#      to use a0-a3 for its own arguments, which will silently
#      clobber the cipher state if you're not careful. print_state
#      below handles this by saving S0-S3 to the stack the instant
#      it's entered and restoring them right before it returns.
#
#   2) The RISC-V "call" pseudo-instruction expands to an
#      auipc+jalr pair and uses t1 (x6) internally as a scratch
#      register to hold the computed jump target. If you stash a
#      value in t1 and then execute "call somewhere", that value is
#      gone before the callee even starts -- this file originally
#      passed each print header's string address in t1 and it got
#      silently destroyed by the very next "call print_state". Fixed
#      here two ways: (a) using t3 instead of t1 to carry the header
#      pointer across a call, and (b) using plain "jal ra, label"
#      (a single real instruction, no scratch register needed) instead
#      of the "call" pseudo-op everywhere in this file.
#
#   Key words k1 (master key) live in x18-x21, k2 = ror128(k1, 1)
#   (the round-2 subkey used by round 1's AddRoundKey) lives in
#   x22-x25. Both are loaded once at start and never touched again.
#
# TEST VECTOR
#   key       = 76543210032032032032032032032032
#   plaintext = 789a789a789a789a789a789a789a789a
#   (vector #6 of BAKSHEESH's own Table 14 test vectors, also used by
#   the baksheesh_lfa repo's own test_fault_sim.py)
#
#   Expected output after this program (computed independently with
#   the reference Python implementation, src/baksheesh.py):
#     after initial whitening (x):        0ece4a8a 7bba4a99 58a87bba 4a9958a8
#     after SubCells (y):                 3747b9c9 e229b9ff 5c9ce229 b9ff5c9c
#     after PermBits + AddConstants:      28e9de9d 7b2fc2fc 7d0f90f9 59bb6bb4
#     after AddRoundKey (round 1 output): 13c3c795 7abfdbfd ed169169 40bafbad
#   (each line printed as S3 S2 S1 S0, most-significant word first)
#
# HOW TO RUN
#   GUI (recommended for stepping/visualizing):
#     java -jar rars.jar
#     File -> Open -> baksheesh_round1.s -> Assemble (F3) -> Step (F7)
#     Watch the "Registers" tab (x10-x13, x18-x25) update each step,
#     and the Run I/O console tab for the printed hex dumps.
#   Command line (just run it and see the printed output):
#     java -jar rars.jar nc baksheesh_round1.s
# ===================================================================

.data
sbox:        .byte 3,0,6,13,11,5,8,14,12,15,9,2,4,10,7,1

p128:        .byte 0,33,66,99,96,1,34,67,64,97,2,35,32,65,98,3
             .byte 4,37,70,103,100,5,38,71,68,101,6,39,36,69,102,7
             .byte 8,41,74,107,104,9,42,75,72,105,10,43,40,73,106,11
             .byte 12,45,78,111,108,13,46,79,76,109,14,47,44,77,110,15
             .byte 16,49,82,115,112,17,50,83,80,113,18,51,48,81,114,19
             .byte 20,53,86,119,116,21,54,87,84,117,22,55,52,85,118,23
             .byte 24,57,90,123,120,25,58,91,88,121,26,59,56,89,122,27
             .byte 28,61,94,127,124,29,62,95,92,125,30,63,60,93,126,31

taps:        .byte 8,13,19,35,67,106      # BAKSHEESH's AddConstants tap positions
round_const: .byte 2                       # 6-bit round constant for round 1 (binary 000010)

# key1 = master key = 0x76543210032032032032032032032032 (word0 = least-significant 32 bits)
key1:        .word 0x32032032, 0x20320320, 0x03203203, 0x76543210
# key2 = ror128(key1, 1) -- the subkey AddRoundKey uses at the end of round 1
key2:        .word 0x19019019, 0x90190190, 0x01901901, 0x3b2a1908
# plaintext = 0x789a789a789a789a789a789a789a789a
plaintext:   .word 0x789a789a, 0x789a789a, 0x789a789a, 0x789a789a

hexdigits:   .asciz "0123456789abcdef"
sp_sep:      .asciz " "
nl:          .asciz "\n"
msg_pre:     .asciz "\n[round 1] x  (after initial whitening, input to SubCells), S3..S0:\n"
msg_y:       .asciz "[round 1] y  (after SubCells),                              S3..S0:\n"
msg_z:       .asciz "[round 1] z  (after PermBits + AddConstants),               S3..S0:\n"
msg_post:    .asciz "[round 1] state (after AddRoundKey w/ k2) -- ROUND 1 OUTPUT, S3..S0:\n"

.text
.globl main

main:
    # ---- load plaintext into the state registers x10..x13 (S0..S3) ----
    la   t0, plaintext
    lw   x10, 0(t0)
    lw   x11, 4(t0)
    lw   x12, 8(t0)
    lw   x13, 12(t0)

    # ---- load key1 (master key) into x18..x21 ----
    la   t0, key1
    lw   x18, 0(t0)
    lw   x19, 4(t0)
    lw   x20, 8(t0)
    lw   x21, 12(t0)

    # ---- load key2 (= ror128(key1,1), round-1's AddRoundKey subkey) into x22..x25 ----
    la   t0, key2
    lw   x22, 0(t0)
    lw   x23, 4(t0)
    lw   x24, 8(t0)
    lw   x25, 12(t0)

    # ---- initial whitening: state ^= k1 ----
    xor  x10, x10, x18
    xor  x11, x11, x19
    xor  x12, x12, x20
    xor  x13, x13, x21

    la   t3, msg_pre
    jal ra, print_state

    # ---- SubCells ----
    jal ra, sub_cells
    la   t3, msg_y
    jal ra, print_state

    # ---- PermBits ----
    jal ra, perm_bits

    # ---- AddConstants (round 1) ----
    jal ra, add_constants_round1

    la   t3, msg_z
    jal ra, print_state

    # ---- AddRoundKey (k2) ----
    xor  x10, x10, x22
    xor  x11, x11, x23
    xor  x12, x12, x24
    xor  x13, x13, x25

    la   t3, msg_post
    jal ra, print_state

    li   a7, 10
    ecall

# ===================================================================
# sub_cells: applies the 4-bit BAKSHEESH S-box to each of the 32
# nibbles of the 128-bit state held in x10..x13 (x10 = least-
# significant word .. x13 = most-significant word). Result overwrites
# x10..x13. Clobbers x5..x9, x14..x17, x28..x31.
# ===================================================================
sub_cells:
    addi sp, sp, -4
    sw   ra, 0(sp)

    li   x14, 0          # Y0 accumulator (output word 0)
    li   x15, 0          # Y1
    li   x16, 0          # Y2
    li   x17, 0          # Y3
    la   x28, sbox
    li   x5, 0           # i = 0 .. 31 (nibble index)

sc_loop:
    li   x6, 32
    bge  x5, x6, sc_done

    srli x7, x5, 3            # word index  = i / 8   (0..3)
    andi x29, x5, 7            # nibble-in-word index (0..7)
    slli x29, x29, 2           # bit offset  = nibble_idx * 4

    li   x6, 0
    beq  x7, x6, sc_src0
    li   x6, 1
    beq  x7, x6, sc_src1
    li   x6, 2
    beq  x7, x6, sc_src2
    j    sc_src3
sc_src0: mv x30, x10
    j    sc_have_src
sc_src1: mv x30, x11
    j    sc_have_src
sc_src2: mv x30, x12
    j    sc_have_src
sc_src3: mv x30, x13
sc_have_src:
    srl  x30, x30, x29
    andi x30, x30, 0xF         # extract nibble value

    add  x31, x28, x30
    lbu  x31, 0(x31)           # sbox[nibble]
    sll  x31, x31, x29         # shift substituted nibble back into place

    li   x6, 0
    beq  x7, x6, sc_dst0
    li   x6, 1
    beq  x7, x6, sc_dst1
    li   x6, 2
    beq  x7, x6, sc_dst2
    j    sc_dst3
sc_dst0: or x14, x14, x31
    j    sc_next
sc_dst1: or x15, x15, x31
    j    sc_next
sc_dst2: or x16, x16, x31
    j    sc_next
sc_dst3: or x17, x17, x31
sc_next:
    addi x5, x5, 1
    j    sc_loop
sc_done:
    mv   x10, x14
    mv   x11, x15
    mv   x12, x16
    mv   x13, x17

    lw   ra, 0(sp)
    addi sp, sp, 4
    ret

# ===================================================================
# perm_bits: BAKSHEESH's 128-bit wire permutation. For each input bit
# t = 0..127, output bit P128[t] = input bit t. Input/output is
# x10..x13. Clobbers x5..x9, x14..x17, x28..x31.
# ===================================================================
perm_bits:
    addi sp, sp, -4
    sw   ra, 0(sp)

    li   x14, 0
    li   x15, 0
    li   x16, 0
    li   x17, 0
    la   x28, p128
    li   x5, 0                 # t = 0 .. 127

pb_loop:
    li   x6, 128
    bge  x5, x6, pb_done

    srli x7, x5, 5              # input word index  = t / 32
    andi x8, x5, 31              # input bit index within word

    li   x6, 0
    beq  x7, x6, pb_src0
    li   x6, 1
    beq  x7, x6, pb_src1
    li   x6, 2
    beq  x7, x6, pb_src2
    j    pb_src3
pb_src0: mv x30, x10
    j    pb_have_src
pb_src1: mv x30, x11
    j    pb_have_src
pb_src2: mv x30, x12
    j    pb_have_src
pb_src3: mv x30, x13
pb_have_src:
    srl  x30, x30, x8
    andi x30, x30, 1
    beqz x30, pb_next            # bit not set -> nothing to do

    add  x31, x28, x5
    lbu  x31, 0(x31)             # p128[t] -> destination bit position (0..127)
    srli x9, x31, 5               # destination word index
    andi x31, x31, 31             # destination bit index within word
    li   x30, 1
    sll  x30, x30, x31            # bit mask

    li   x6, 0
    beq  x9, x6, pb_dst0
    li   x6, 1
    beq  x9, x6, pb_dst1
    li   x6, 2
    beq  x9, x6, pb_dst2
    j    pb_dst3
pb_dst0: or x14, x14, x30
    j    pb_next
pb_dst1: or x15, x15, x30
    j    pb_next
pb_dst2: or x16, x16, x30
    j    pb_next
pb_dst3: or x17, x17, x30
pb_next:
    addi x5, x5, 1
    j    pb_loop
pb_done:
    mv   x10, x14
    mv   x11, x15
    mv   x12, x16
    mv   x13, x17

    lw   ra, 0(sp)
    addi sp, sp, 4
    ret

# ===================================================================
# add_constants_round1: XORs round 1's 6-bit round constant (2, i.e.
# binary 000010) into the TAPS bit positions of the state (x10..x13).
# Written as a general loop over the 6 taps so it's easy to reuse for
# other rounds later (just change round_const). Clobbers x5..x9,
# x28..x31.
# ===================================================================
add_constants_round1:
    la   x28, taps
    lb   x29, round_const        # 6-bit constant value for this round
    li   x5, 0                   # c = 0 .. 5

ac_loop:
    li   x6, 6
    bge  x5, x6, ac_done

    srl  x30, x29, x5
    andi x30, x30, 1
    beqz x30, ac_next

    add  x31, x28, x5
    lbu  x31, 0(x31)             # taps[c] -> absolute bit position 0..127
    srli x7, x31, 5               # word index
    andi x31, x31, 31             # bit index within word
    li   x30, 1
    sll  x30, x30, x31

    li   x6, 0
    beq  x7, x6, ac_w0
    li   x6, 1
    beq  x7, x6, ac_w1
    li   x6, 2
    beq  x7, x6, ac_w2
    j    ac_w3
ac_w0: xor x10, x10, x30
    j    ac_next
ac_w1: xor x11, x11, x30
    j    ac_next
ac_w2: xor x12, x12, x30
    j    ac_next
ac_w3: xor x13, x13, x30
ac_next:
    addi x5, x5, 1
    j    ac_loop
ac_done:
    ret

# ===================================================================
# print_state: prints "S3.. S2.. S1.. S0..\n" using the CURRENT values
# of x13,x12,x11,x10. Saves x10-x13 to the stack on entry and restores
# them right before returning, because print_hex_word/print_string
# necessarily use a0-a3 (== x10-x13!) for their own arguments -- see
# the ABI note at the top of this file.
# ===================================================================
print_state:
    addi sp, sp, -20
    sw   ra, 16(sp)
    sw   x10, 0(sp)
    sw   x11, 4(sp)
    sw   x12, 8(sp)
    sw   x13, 12(sp)

    mv   a0, t3                  # header string pointer, passed in by caller
    jal ra, print_string

    lw   a0, 12(sp)              # S3
    jal ra, print_hex_word
    la   a0, sp_sep
    jal ra, print_string
    lw   a0, 8(sp)               # S2
    jal ra, print_hex_word
    la   a0, sp_sep
    jal ra, print_string
    lw   a0, 4(sp)               # S1
    jal ra, print_hex_word
    la   a0, sp_sep
    jal ra, print_string
    lw   a0, 0(sp)               # S0
    jal ra, print_hex_word
    la   a0, nl
    jal ra, print_string

    # restore the real cipher-state registers (clobbered above via a0-a3)
    lw   x10, 0(sp)
    lw   x11, 4(sp)
    lw   x12, 8(sp)
    lw   x13, 12(sp)
    lw   ra, 16(sp)
    addi sp, sp, 20
    ret

# ===================================================================
# print_hex_word: prints the 32-bit value in a0 as 8 lowercase hex
# digits, most-significant nibble first. Clobbers a0-a3.
# ===================================================================
print_hex_word:
    addi sp, sp, -8
    sw   ra, 0(sp)
    sw   s0, 4(sp)
    mv   s0, a0
    la   a1, hexdigits
    li   a2, 28                  # start at nibble 7 (bit offset 28), down to 0

phw_loop:
    srl  a3, s0, a2
    andi a3, a3, 0xF
    add  a3, a1, a3
    lbu  a0, 0(a3)
    li   a7, 11
    ecall

    addi a2, a2, -4
    bgez a2, phw_loop

    lw   ra, 0(sp)
    lw   s0, 4(sp)
    addi sp, sp, 8
    ret

# ===================================================================
# print_string: thin wrapper around syscall 4 (print null-terminated
# string at address a0).
# ===================================================================
print_string:
    li   a7, 4
    ecall
    ret
