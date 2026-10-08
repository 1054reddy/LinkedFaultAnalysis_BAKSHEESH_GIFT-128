"""
Reference (integer-based) implementation of GIFT-128 encryption.
Everything is represented as a single Python int for the 128-bit state,
which avoids array-index bugs and lets us use native XOR/shift -- mirrors
the style of ../baksheesh_lfa/src/baksheesh.py.

IMPORTANT STRUCTURAL DIFFERENCE FROM BAKSHEESH (this matters for the fault
attacks in fault_sim.py / lifa_attack.py / ldfa_attack.py):

BAKSHEESH's AddRoundKey XORs a full 128-bit subkey into the *entire*
permuted state every round. GIFT-128's AddRoundKey only ever injects 64
key bits (two 32-bit words U, V) into two fixed bit positions of every
4-bit nibble (bit offsets 1 and 2, i.e. the "middle" two bits -- the
nibble's LSB and MSB are never touched by the key). Concretely, for
b = 0..31: state bit (4b+1) ^= V_b, state bit (4b+2) ^= U_b.

This means a single round of GIFT-128 only ever "spends" 64 of the
128-bit key schedule state on the ciphertext. To recover the *full*
128-bit master key via a last-round fault attack, you have to attack the
last two rounds (see lifa_attack.py / ldfa_attack.py for how the two
rounds' worth of leaked material get stitched back together through the
key schedule).
"""

from .constants import (
    SBOX, INV_SBOX, P128, INV_P128, CONST_TAPS, CONST_FIXED_BIT,
    ROUND_CONSTANTS_6BIT, NUM_ROUNDS,
)

MASK128 = (1 << 128) - 1
MASK16 = 0xFFFF


def hex_to_int(s: str) -> int:
    return int(s, 16)


def int_to_hex(x: int) -> str:
    return format(x & MASK128, "032x")


def get_nibble(state: int, i: int) -> int:
    return (state >> (4 * i)) & 0xF


def set_nibble(state: int, i: int, val: int) -> int:
    state &= ~(0xF << (4 * i)) & MASK128
    state |= (val & 0xF) << (4 * i)
    return state


def sub_cells(state: int) -> int:
    out = 0
    for i in range(32):
        out |= SBOX[get_nibble(state, i)] << (4 * i)
    return out


def inv_sub_cells(state: int) -> int:
    out = 0
    for i in range(32):
        out |= INV_SBOX[get_nibble(state, i)] << (4 * i)
    return out


def perm_bits(state: int) -> int:
    out = 0
    for i in range(128):
        if (state >> i) & 1:
            out |= 1 << P128[i]
    return out


def inv_perm_bits(state: int) -> int:
    out = 0
    for i in range(128):
        if (state >> i) & 1:
            out |= 1 << INV_P128[i]
    return out


def round_constant_word(round_idx_1based: int) -> int:
    """The 128-bit word XORed in for AddRoundConstant this round: the fixed
    MSB bit plus the 6-bit round constant spread across the nibble-MSB taps."""
    rc = ROUND_CONSTANTS_6BIT[round_idx_1based - 1]
    word = 1 << CONST_FIXED_BIT
    for c in range(6):
        if (rc >> c) & 1:
            word |= 1 << CONST_TAPS[c]
    return word


def ror16(x: int, n: int) -> int:
    x &= MASK16
    n %= 16
    return ((x >> n) | (x << (16 - n))) & MASK16


def rol16(x: int, n: int) -> int:
    return ror16(x, 16 - (n % 16))


def key_words(master_key: int):
    """Split the 128-bit key into 8 16-bit words [k0, k1, ..., k7] (k0 = LSBs)."""
    return [(master_key >> (16 * i)) & MASK16 for i in range(8)]


def words_to_key(words) -> int:
    return sum((w & MASK16) << (16 * i) for i, w in enumerate(words)) & MASK128


def extract_UV(words):
    """RK = U || V, the 64-bit round key extracted from the key state.
    U <- k5||k4 (32-bit), V <- k1||k0 (32-bit)."""
    k0, k1, k2, k3, k4, k5, k6, k7 = words
    U = (k5 << 16) | k4
    V = (k1 << 16) | k0
    return U, V


def key_update(words):
    """One step of the GIFT key schedule:
    k7||k6||...||k1||k0 <- (k1>>>2)||(k0>>>12)||k7||k6||k5||k4||k3||k2
    """
    k0, k1, k2, k3, k4, k5, k6, k7 = words
    return [k2, k3, k4, k5, k6, k7, ror16(k0, 12), ror16(k1, 2)]


def key_update_inverse(words):
    """Inverse of key_update(): recovers the key state one round earlier."""
    k0, k1, k2, k3, k4, k5, k6, k7 = words
    return [rol16(k6, 12), rol16(k7, 2), k0, k1, k2, k3, k4, k5]


def build_round_key_word(U: int, V: int) -> int:
    """Spreads the 64-bit round key RK = U||V into the 128-bit state word
    that AddRoundKey XORs in: bit (4b+1) <- V_b, bit (4b+2) <- U_b."""
    word = 0
    for b in range(32):
        if (V >> b) & 1:
            word |= 1 << (4 * b + 1)
        if (U >> b) & 1:
            word |= 1 << (4 * b + 2)
    return word


def peel_back_round(state_after_round: int, U: int, V: int, round_idx_1based: int) -> int:
    """Given the state right after round `round_idx_1based` (e.g. a
    ciphertext, if that was the last round) and that round's (U, V), inverts
    AddRoundKey+AddRoundConstant, PermBits, and SubCells to recover the state
    that round started from (i.e. the input to that round's SubCells)."""
    rkword = build_round_key_word(U, V)
    rcword = round_constant_word(round_idx_1based)
    z = state_after_round ^ rcword ^ rkword
    y = inv_perm_bits(z)
    x = inv_sub_cells(y)
    return x


def encrypt(plaintext: int, master_key: int, num_rounds: int = NUM_ROUNDS, return_trace=False):
    """
    Full GIFT-128 encryption.
    If return_trace=True, also returns a round-by-round trace and the full
    sequence of key-schedule states -- useful for fault-injection experiments.
    """
    words = key_words(master_key)
    state = plaintext & MASK128
    trace = []
    key_states = [list(words)]        # key_states[r-1] = words used by round r

    for r in range(1, num_rounds + 1):
        x = state                      # input to SubCells this round
        y = sub_cells(x)               # output of SubCells this round
        z = perm_bits(y)               # output of PermBits this round
        U, V = extract_UV(words)
        rcword = round_constant_word(r)
        rkword = build_round_key_word(U, V)
        state = z ^ rcword ^ rkword

        if return_trace:
            trace.append({
                "round": r, "x": x, "y": y, "z": z,
                "U": U, "V": V, "rcword": rcword, "rkword": rkword,
                "key_words_before": list(words),
            })

        words = key_update(words)
        key_states.append(list(words))

    if return_trace:
        return state, trace, key_states
    return state
