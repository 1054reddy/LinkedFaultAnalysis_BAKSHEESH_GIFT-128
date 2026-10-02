"""
Linked Differential Fault Attack (LDFA) on BAKSHEESH's last round.

leak_delta_esk():
    Given ONLY a faulty ciphertext (no correct one, no plaintext), recovers
    esk[i] XOR esk[j] for the nibble pair the fault linked. This is Phase 3's
    algebra, but now used "for real" -- no peeking at the actual key.

recover_esk_from_adjacent_faults():
    Given the chain of 31 adjacent-pair differences and a guess for esk[0],
    reconstructs the full 128-bit equivalent subkey.

recover_master_key_candidates():
    Tries all 16 candidates for esk[0], returns 16 master-key candidates.
"""

from .baksheesh import get_nibble, set_nibble, inv_perm_bits, perm_bits, add_constants, ror128, MASK128


def leak_delta_esk(faulty_ciphertext: int, i: int, j: int, num_rounds: int = 35) -> int:
    """Algorithm 1: requires ONLY the faulty ciphertext + the public round constant."""
    ac = add_constants(0, num_rounds)          # just the constant word for this round
    w_faulty = inv_perm_bits(faulty_ciphertext ^ ac)
    return get_nibble(w_faulty, i) ^ get_nibble(w_faulty, j)


def recover_esk_from_adjacent_faults(delta_esk_chain: list, esk0_guess: int) -> int:
    """delta_esk_chain[l] = esk[l] XOR esk[l+1], for l = 0..L-2. Reconstructs full esk."""
    L = len(delta_esk_chain) + 1
    esk_nibbles = [0] * L
    esk_nibbles[0] = esk0_guess
    running = esk0_guess
    for l in range(L - 1):
        running ^= delta_esk_chain[l]
        esk_nibbles[l + 1] = running
    esk = 0
    for idx, val in enumerate(esk_nibbles):
        esk = set_nibble(esk, idx, val)
    return esk


def recover_master_key_candidates(delta_esk_chain: list, num_rounds: int = 35):
    """Try all 16 candidates for esk[0], return list of (esk0_guess, master_key_candidate)."""
    candidates = []
    for esk0 in range(16):
        esk_R = recover_esk_from_adjacent_faults(delta_esk_chain, esk0)
        sk_R = perm_bits(esk_R)                              # = k[num_rounds+1]
        master_key_candidate = ror128(sk_R, -num_rounds) & MASK128  # left-rotate by num_rounds
        candidates.append((esk0, master_key_candidate))
    return candidates