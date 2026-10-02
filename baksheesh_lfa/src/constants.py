"""
BAKSHEESH cipher constants, taken directly from:
Baksi et al., "BAKSHEESH: Similar Yet Different From GIFT", 2023.
"""

# SubCells S-box: S = 306DB58ECF924A71 (hex string, S(0)=3, S(1)=0, ...)
SBOX = [int(c, 16) for c in "306DB58ECF924A71"]

# Inverse S-box: 1FB0C52E6AD48379
INV_SBOX = [int(c, 16) for c in "1FB0C52E6AD48379"]

assert all(SBOX[INV_SBOX[i]] == i for i in range(16)), "sbox/invsbox mismatch"

# PermBits: P128, identical to GIFT-128's permutation.
# bit i of input state -> bit P128[i] of output state
P128 = [
    0, 33, 66, 99, 96, 1, 34, 67, 64, 97, 2, 35, 32, 65, 98, 3,
    4, 37, 70, 103, 100, 5, 38, 71, 68, 101, 6, 39, 36, 69, 102, 7,
    8, 41, 74, 107, 104, 9, 42, 75, 72, 105, 10, 43, 40, 73, 106, 11,
    12, 45, 78, 111, 108, 13, 46, 79, 76, 109, 14, 47, 44, 77, 110, 15,
    16, 49, 82, 115, 112, 17, 50, 83, 80, 113, 18, 51, 48, 81, 114, 19,
    20, 53, 86, 119, 116, 21, 54, 87, 84, 117, 22, 55, 52, 85, 118, 23,
    24, 57, 90, 123, 120, 25, 58, 91, 88, 121, 26, 59, 56, 89, 122, 27,
    28, 61, 94, 127, 124, 29, 62, 95, 92, 125, 30, 63, 60, 93, 126, 31,
]
assert len(P128) == 128 and sorted(P128) == list(range(128))

INV_P128 = [0] * 128
for i, p in enumerate(P128):
    INV_P128[p] = i

# AddConstants tap positions (6 bit positions XORed each round)
TAPS = [8, 13, 19, 35, 67, 106]

# Full 6-bit round constant sequence, rounds 1..35 (decimal, from the paper, Section 3.3)
ROUND_CONSTANTS_6BIT = [
    2, 33, 16, 9, 36, 19, 40, 53, 26, 13, 38, 51, 56, 61, 62, 31, 14, 7,
    34, 49, 24, 45, 54, 59, 28, 47, 22, 43, 20, 11, 4, 3, 32, 17, 8,
]
assert len(ROUND_CONSTANTS_6BIT) == 35

# Official test vectors, Table 14 of the paper: (key_hex, plaintext_hex, ciphertext_hex)
TEST_VECTORS = [
    ("00000000000000000000000000000000", "00000000000000000000000000000000", "c002be5e64c78a72ab9a3439518352aa"),
    ("00000000000000000000000000000000", "00000000000000000000000000000007", "6f7d7746eaf0d97a154079f6bd846438"),
    ("00000000000000000000000000000000", "70000000000000000000000000000000", "1ba3363734c09a29f67c23bbb2cccc05"),
    ("00000000000000000000000000000000", "44444444444444444444444444444444", "7ad3303667b2af6deef434dd110d7fb8"),
    ("ffffffffffffffffffffffffffffffff", "11111111111111111111111111111111", "806f0cf45b94f0370206975fe78ac10f"),
    ("76543210032032032032032032032032", "789a789a789a789a789a789a789a789a", "ae654b5333b876584f8e8dd54f4e490a"),
    ("23023023023023023023023001234567", "b6e4789ab6e4789ab6e4789ab6e4789a", "3dbbdf7fe254cc0be396a753442dccad"),
    ("5920effb52bc61e33a98425321e76915", "e6517531abf63f3d7805e126943a081c", "fc7e61fee3d587308ca7bc594ebf3244"),
]