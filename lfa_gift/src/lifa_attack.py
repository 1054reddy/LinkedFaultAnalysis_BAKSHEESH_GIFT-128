"""
Linked Ineffective Fault Attack (LIFA) on GIFT-128, targeting a device
protected by a redundancy-based (duplicate-and-compare) countermeasure.
Mirrors ../baksheesh_lfa/src/lifa_attack.py's attack model:
  1. An attacker injects a linked fault on nibble pair (i, j) in some round's
     SubCells.
  2. Effective faults are caught by the countermeasure and suppressed
     (device returns None).
  3. Ineffective faults (x_R[i] == x_R[j]) cause zero state deviation, so
     the device emits the ordinary, fault-free ciphertext.
  4. From that ciphertext, an equivalent-subkey (ESK) difference for the
     targeted round is leaked (see leak_delta_esk_ineffective).
  5. 31 adjacent-pair observations recover a chain that pins the round's
     ESK down to a small residual ambiguity.

WHY GIFT-128 NEEDS *TWO* ATTACKED ROUNDS (unlike BAKSHEESH's one):
BAKSHEESH XORs a full 128-bit subkey into the whole permuted state, so one
round's ESK directly determines the entire 128-bit master key. GIFT-128's
AddRoundKey only ever injects 64 real key bits (U, V) into fixed "middle"
bit positions of each nibble (see gift.py's module docstring) -- so one
round's ESK only pins down 64 of the 128 key-schedule bits (empirically,
only a 4-way, not 16-way, ambiguity survives per round -- see
recover_round_UV_candidates_lifa).

To recover the full master key we run this same attack twice:
  - PHASE 1 attacks the LAST round directly, exactly like BAKSHEESH.
  - PHASE 2 attacks the SECOND-TO-LAST round. Because the fault there still
    has to propagate through the (unfaulted) last round before reaching the
    ciphertext, phase 2 first *peels back* the last round using each
    candidate (U, V) from phase 1 (gift.peel_back_round), then applies the
    exact same ESK-chain leak to what should be the state right after the
    second-to-last round.
Combining both rounds' recovered key-schedule words and inverting the key
schedule yields full master-key candidates, which -- exactly as in
BAKSHEESH -- are disambiguated with one known (plaintext, ciphertext) pair.
"""

import random
from typing import List, Tuple
from .gift import (
    get_nibble, set_nibble, inv_perm_bits, perm_bits, round_constant_word,
    peel_back_round, ror16, key_update_inverse, words_to_key, encrypt,
    MASK128, NUM_ROUNDS,
)
from .countermeasure import RedundantGiftDevice

L = 32  # 32 nibbles in the 128-bit state


def leak_delta_esk_ineffective(state_after_round: int, i: int, j: int,
                                num_rounds: int) -> int:
    """
    Given the (correct) state right after round `num_rounds` -- e.g. the
    ciphertext directly, if that round is the actual last round, or a
    peeled-back reconstruction if it isn't -- from an INEFFECTIVE fault
    linking nibbles i, j in that round's SubCells:
        w = PermBits^-1(state_after_round ^ round_constant_word)
        w[i] ^ w[j] = (y[i] ^ ESK[i]) ^ (y[j] ^ ESK[j])
    where ESK = PermBits^-1(round_key_word) is that round's "equivalent
    subkey" in the pre-permutation nibble domain. Since the fault was
    ineffective, y[i] == y[j], so the y terms cancel:
        w[i] ^ w[j] = ESK[i] ^ ESK[j]
    """
    rc = round_constant_word(num_rounds)
    w = inv_perm_bits(state_after_round ^ rc)
    return get_nibble(w, i) ^ get_nibble(w, j)


def collect_ineffective_ciphertext_and_leak(
    device: RedundantGiftDevice, i: int, j: int, target_round: int,
    max_attempts: int = 2000
) -> Tuple[int, int, int]:
    """
    Sends random plaintexts to the protected device under a linked fault
    (i, j) in round `target_round` until an ineffective fault occurs
    (countermeasure bypassed). Returns (ciphertext, plaintext, query_count)
    -- the leak itself is computed later, once the last round has been
    peeled back (for target_round < num_rounds).
    """
    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        plaintext = random.getrandbits(128)
        ct, is_ineffective = device.encrypt_with_redundancy_and_fault(
            plaintext, i, j, num_rounds=target_round
        )
        if is_ineffective and ct is not None:
            return ct, plaintext, attempts

    raise RuntimeError(f"Failed to observe an ineffective fault after {max_attempts} attempts.")


def recover_esk_from_adjacent_faults_lifa(delta_esk_chain: list, esk0_guess: int) -> int:
    """Reconstructs the full 128-bit ESK from the 31 adjacent-nibble differences."""
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
    """Recovers a round's 64-bit round key RK = U||V from its fully
    reconstructed ESK by re-applying PermBits."""
    rkword = perm_bits(esk)
    U = 0
    V = 0
    for b in range(32):
        if (rkword >> (4 * b + 1)) & 1:
            V |= 1 << b
        if (rkword >> (4 * b + 2)) & 1:
            U |= 1 << b
    return U, V


def recover_round_UV_candidates_lifa(delta_esk_chain: list) -> List[Tuple[int, int, int]]:
    """Tries all 16 candidates for ESK's nibble 0, returning (esk0_guess, U, V).
    In practice only 4 distinct (U, V) pairs occur across the 16 guesses,
    because 2 of ESK[0]'s 4 bits map (via PermBits) onto nibble positions
    that carry no key material at all."""
    candidates = []
    for esk0 in range(16):
        esk = recover_esk_from_adjacent_faults_lifa(delta_esk_chain, esk0)
        U, V = esk_to_UV(esk)
        candidates.append((esk0, U, V))
    return candidates


def attack_round_lifa(device: RedundantGiftDevice, target_round: int,
                       peel_UV=None) -> List[Tuple[int, int, int]]:
    """
    Runs the full 31-adjacent-pair LIFA sub-attack against `target_round`.
    If `peel_UV` is given (a candidate (U, V) for the round *after*
    target_round), each observed ciphertext is first peeled back through
    that later round before the ESK leak is computed -- this is how phase 2
    reaches back to the second-to-last round.
    Returns the list of (esk0_guess, U, V) candidates for `target_round`.
    """
    chain = []
    for i in range(L - 1):
        j = i + 1
        ct, pt, _ = collect_ineffective_ciphertext_and_leak(device, i, j, target_round)
        if peel_UV is not None:
            state_after = peel_back_round(ct, peel_UV[0], peel_UV[1], target_round + 1)
        else:
            state_after = ct
        chain.append(leak_delta_esk_ineffective(state_after, i, j, target_round))
    return recover_round_UV_candidates_lifa(chain)


def stitch_master_key_candidates(
    cand_last: List[Tuple[int, int, int]], cand_prev: List[Tuple[int, int, int]],
    num_rounds: int = NUM_ROUNDS
) -> List[int]:
    """Combines round-`num_rounds` candidates (k1,k0,k5,k4 of the key state
    feeding that round) with round-`num_rounds-1` candidates (the key state
    one step earlier) into full master-key candidates, by reconstructing the
    complete 8-word key state feeding the last round and inverting the
    schedule back to round 0."""
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

            # key_states[R-1] = key_update(key_states[R-2]):
            #   new_k2=old_k4, new_k3=old_k5, new_k6=ror16(old_k0,12), new_k7=ror16(old_k1,2)
            words_R_minus1 = [k0, k1, k4p, k5p, k4, k5, ror16(k0p, 12), ror16(k1p, 2)]
            words = words_R_minus1
            for _ in range(num_rounds - 1):
                words = key_update_inverse(words)
            out.append(words_to_key(words))
    return out


def recover_master_key_lifa(device: RedundantGiftDevice, verify_plaintext: int,
                             verify_ciphertext: int, num_rounds: int = NUM_ROUNDS):
    """
    Full two-phase LIFA pipeline: attacks the last round, then (peeling back
    through each last-round candidate) the second-to-last round, stitches
    the results into master-key candidates, and disambiguates with one
    known (plaintext, ciphertext) pair via a direct black-box encryption
    check. Returns (unique_key_or_None, num_candidates_tested).
    """
    cand_last = attack_round_lifa(device, num_rounds)
    all_candidates = []
    for _, U_last, V_last in cand_last:
        cand_prev = attack_round_lifa(device, num_rounds - 1, peel_UV=(U_last, V_last))
        all_candidates.extend(
            stitch_master_key_candidates([(_, U_last, V_last)], cand_prev, num_rounds)
        )

    matches = [k for k in all_candidates if encrypt(verify_plaintext, k) == verify_ciphertext]
    unique = matches[0] if len(set(matches)) == 1 else None
    return unique, len(all_candidates)
