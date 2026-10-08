"""
Reference (bit-sliced-free, integer-based) implementation of BAKSHEESH encryption.
Everything is represented as a single Python int for the 128-bit state / key,
which avoids array-index bugs and lets us use native XOR/shift.
"""

from .constants import SBOX, INV_SBOX, P128, INV_P128, TAPS, ROUND_CONSTANTS_6BIT

MASK128 = (1 << 128) - 1
NUM_ROUNDS = 35


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
    """
    Return the 128-bit word with the 6 constant bits XORed at TAPS for this round.
    bit b (0=LSB..5=MSB) of the 6-bit round constant maps directly, in order, to
    TAPS[b] (TAPS[5]=106 is the 'last tap', matching the paper's note that this
    bit toggles each round).
    """
    c6 = ROUND_CONSTANTS_6BIT[round_idx_1based - 1]
    word = 0
    for b in range(6):
        if (c6 >> b) & 1:
            word |= 1 << TAPS[b]
    return word


def add_constants(state: int, round_idx_1based: int) -> int:
    return state ^ round_constant_word(round_idx_1based)


def ror128(x: int, n: int) -> int:
    n %= 128
    return ((x >> n) | (x << (128 - n))) & MASK128


def key_schedule(master_key: int, num_keys: int = NUM_ROUNDS + 1):
    """Returns dict k[1..num_keys], k[1] = master key, each subsequent = 1-bit right rotation."""
    k = {1: master_key & MASK128}
    for j in range(2, num_keys + 1):
        k[j] = ror128(k[j - 1], 1)
    return k


def encrypt(plaintext: int, master_key: int, num_rounds: int = NUM_ROUNDS, return_trace=False):
    """
    Full BAKSHEESH encryption.
    If return_trace=True, also returns a round-by-round trace and the key dict --
    useful for fault-injection experiments later.
    """
    k = key_schedule(master_key, num_rounds + 1)
    state = plaintext ^ k[1]           # initial whitening uses the raw master key
    trace = []
    for r in range(1, num_rounds + 1):
        x = state                      # input to SubCells this round
        y = sub_cells(x)               # output of SubCells this round
        state = perm_bits(y)
        state = add_constants(state, r)
        pre_addkey = state             # state right before AddRoundKey
        state = state ^ k[r + 1]       # round r's AddRoundKey uses k[r+1]
        trace.append({"round": r, "x": x, "y": y, "pre_addkey": pre_addkey, "key": k[r + 1]})
    if return_trace:
        return state, trace, k
    return state