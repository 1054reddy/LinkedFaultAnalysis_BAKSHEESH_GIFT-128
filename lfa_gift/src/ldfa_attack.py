"""
Linked Differential Fault Attack (LDFA) on GIFT-128's last two rounds.
Mirrors ../baksheesh_lfa/src/ldfa_attack.py, adapted the same way as
lifa_attack.py for GIFT-128's 64-bit-per-round AddRoundKey (see that
module's docstring for the full explanation of why two rounds are needed).

Unlike LIFA, LDFA targets an *unprotected* device: the attacker gets the
faulty ciphertext directly for every injected fault, regardless of whether
it was "effective" or not. The leak works unconditionally because the
linked-fault model guarantees y'_R[j] = S(x_R[i]) = y_R[i], so the y-terms
always cancel in the leak equation -- no redundancy-bypass event needed.

leak_delta_esk():
    Given ONLY a faulty state-after-round (the ciphertext itself, if that
    round is the last one; a peeled-back reconstruction otherwise), recovers
    ESK[i] XOR ESK[j] for the nibble pair the fault linked.

attack_round_ldfa():
    Runs the 31-adjacent-pair sub-attack against one round, optionally
    peeling back a later round first (phase 2).

recover_master_key_ldfa():
    Combines the last-round and second-to-last-round recoveries into full
    128-bit master-key candidates and disambiguates them with one known
    (plaintext, ciphertext) pair.
"""

from typing import List, Tuple
from .gift import (
    get_nibble, set_nibble, inv_perm_bits, perm_bits, round_constant_word,
    peel_back_round, ror16, key_update_inverse, words_to_key, encrypt,
    NUM_ROUNDS,
)
from .fault_sim import encrypt_with_linked_fault_at_round

L = 32


def leak_delta_esk(state_after_round: int, i: int, j: int, num_rounds: int) -> int:
    """Requires only the (possibly peeled-back) state after round `num_rounds`
    plus the public round constant for that round."""
    rc = round_constant_word(num_rounds)
    w = inv_perm_bits(state_after_round ^ rc)
    return get_nibble(w, i) ^ get_nibble(w, j)


def recover_esk_from_adjacent_faults(delta_esk_chain: list, esk0_guess: int) -> int:
    """delta_esk_chain[l] = ESK[l] XOR ESK[l+1], for l = 0..L-2. Reconstructs full ESK."""
    Lc = len(delta_esk_chain) + 1
    esk_nibbles = [0] * Lc
    esk_nibbles[0] = esk0_guess
    running = esk0_guess
    for l in range(Lc - 1):
        running ^= delta_esk_chain[l]
        esk_nibbles[l + 1] = running
    esk = 0
    for idx, val in enumerate(esk_nibbles):
        esk = set_nibble(esk, idx, val)
    return esk


def esk_to_UV(esk: int):
    """Recovers a round's (U, V) by re-applying PermBits to ESK."""
    rkword = perm_bits(esk)
    U = 0
    V = 0
    for b in range(32):
        if (rkword >> (4 * b + 1)) & 1:
            V |= 1 << b
        if (rkword >> (4 * b + 2)) & 1:
            U |= 1 << b
    return U, V


def recover_round_UV_candidates(delta_esk_chain: list) -> List[Tuple[int, int, int]]:
    """Try all 16 candidates for ESK[0], return list of (esk0_guess, U, V)."""
    candidates = []
    for esk0 in range(16):
        esk = recover_esk_from_adjacent_faults(delta_esk_chain, esk0)
        U, V = esk_to_UV(esk)
        candidates.append((esk0, U, V))
    return candidates


def attack_round_ldfa(plaintext: int, master_key: int, target_round: int,
                       peel_UV=None, num_rounds: int = NUM_ROUNDS) -> List[Tuple[int, int, int]]:
    """
    Runs the 31-adjacent-pair LDFA sub-attack against `target_round` using a
    single plaintext (each of the 31 faults is injected independently against
    the same plaintext -- this is the unprotected-device analogue of
    lifa_attack.attack_round_lifa). If `peel_UV` is given (a candidate
    (U, V) for the round right after target_round), each faulty ciphertext
    is peeled back through that round first.
    """
    chain = []
    for i in range(L - 1):
        j = i + 1
        ct_faulty, _ = encrypt_with_linked_fault_at_round(
            plaintext, master_key, i, j, target_round=target_round, num_rounds=num_rounds
        )
        if peel_UV is not None:
            state_after = peel_back_round(ct_faulty, peel_UV[0], peel_UV[1], target_round + 1)
        else:
            state_after = ct_faulty
        chain.append(leak_delta_esk(state_after, i, j, target_round))
    return recover_round_UV_candidates(chain)


def stitch_master_key_candidates(
    cand_last: List[Tuple[int, int, int]], cand_prev: List[Tuple[int, int, int]],
    num_rounds: int = NUM_ROUNDS
) -> List[int]:
    """Identical stitching procedure to lifa_attack.stitch_master_key_candidates."""
    out = []
    for _, U_last, V_last in cand_last:
        k0 = V_last & 0xFFFF
        k1 = (V_last >> 16) & 0xFFFF
        k4 = U_last & 0xFFFF
        k5 = (U_last >> 16) & 0xFFFF
        for _, U_prev, V_prev in cand_prev:
            k0p = V_prev & 0xFFFF
            k1p = (V_prev >> 16) & 0xFFFF
            k4p = U_prev & 0xFFFF
            k5p = (U_prev >> 16) & 0xFFFF

            words = [k0, k1, k4p, k5p, k4, k5, ror16(k0p, 12), ror16(k1p, 2)]
            for _ in range(num_rounds - 1):
                words = key_update_inverse(words)
            out.append(words_to_key(words))
    return out


def recover_master_key_ldfa(plaintext: int, master_key_unknown_to_attacker: int,
                             verify_plaintext: int, verify_ciphertext: int,
                             num_rounds: int = NUM_ROUNDS):
    """
    Full two-phase LDFA pipeline against an unprotected device. The
    `master_key_unknown_to_attacker` argument is only used to *simulate* the
    device issuing faulty ciphertexts for chosen (plaintext, i, j) triples --
    exactly like fault_sim.encrypt_with_linked_fault_at_round is used
    elsewhere; the recovery logic below never reads it directly.
    Returns (unique_key_or_None, num_candidates_tested).
    """
    mk = master_key_unknown_to_attacker
    cand_last = attack_round_ldfa(plaintext, mk, num_rounds, num_rounds=num_rounds)

    all_candidates = []
    for _, U_last, V_last in cand_last:
        cand_prev = attack_round_ldfa(
            plaintext, mk, num_rounds - 1, peel_UV=(U_last, V_last), num_rounds=num_rounds
        )
        all_candidates.extend(
            stitch_master_key_candidates([(_, U_last, V_last)], cand_prev, num_rounds)
        )

    matches = [k for k in all_candidates if encrypt(verify_plaintext, k) == verify_ciphertext]
    unique = matches[0] if len(set(matches)) == 1 else None
    return unique, len(all_candidates)
