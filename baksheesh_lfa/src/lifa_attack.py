"""
Linked Ineffective Fault Attack (LIFA) on BAKSHEESH.

Targets devices protected by redundancy-based countermeasures (duplicate-and-compare).
In this attack model:
  1. An attacker injects a linked fault on nibble pair (i, j) in round 35 SubCells.
  2. Effective faults cause internal state divergence, are caught by the countermeasure,
     and the device suppresses the ciphertext (returns None).
  3. Ineffective faults occur when x_R[i] == x_R[j] (equivalently y_R[i] == y_R[j]),
     meaning the fault produces zero state deviation. The device emits the fault-free ciphertext C.
  4. From the ineffective ciphertext alone:
       w = PermBits^-1(C ^ AddConstants)
       w[i] ^ w[j] = esk[i] ^ esk[j] = Delta-esk[i, j]
  5. By repeating this across 31 adjacent pairs (0,1), (1,2), ..., (30,31),
     the attacker recovers the 31-difference chain, reduces the key space
     from 2^128 to 16 candidates, and identifies the exact 128-bit key.
"""

import random
from typing import Tuple, List
from .baksheesh import (
    get_nibble, set_nibble, inv_perm_bits, perm_bits, add_constants,
    ror128, MASK128, NUM_ROUNDS
)
from .countermeasure import RedundantBaksheeshDevice


def leak_delta_esk_ineffective(ineffective_ciphertext: int, i: int, j: int,
                                num_rounds: int = NUM_ROUNDS) -> int:
    """
    Given an INEFFECTIVE ciphertext C from a linked fault linking nibbles i and j:
        w = PermBits^-1(C ^ round_constant)
        w[i] ^ w[j] = (y[i] ^ esk[i]) ^ (y[j] ^ esk[j])
    Since the fault was ineffective, y[i] == y[j], so the y terms cancel:
        w[i] ^ w[j] = esk[i] ^ esk[j]
    """
    ac = add_constants(0, num_rounds)
    w = inv_perm_bits(ineffective_ciphertext ^ ac)
    return get_nibble(w, i) ^ get_nibble(w, j)


def collect_ineffective_ciphertext_and_leak(
    device: RedundantBaksheeshDevice, i: int, j: int, max_attempts: int = 2000
) -> Tuple[int, int, int]:
    """
    Sends random/streaming plaintexts to the protected device under linked fault (i, j)
    until an ineffective fault occurs (countermeasure bypassed).

    Returns:
        (leaked_delta, query_count, ineffective_ciphertext)
    """
    attempts = 0
    while attempts < max_attempts:
        attempts += 1
        plaintext = random.getrandbits(128)
        ct, is_ineffective = device.encrypt_with_redundancy_and_fault(plaintext, i, j)
        if is_ineffective and ct is not None:
            delta = leak_delta_esk_ineffective(ct, i, j, num_rounds=device.num_rounds)
            return delta, attempts, ct

    raise RuntimeError(f"Failed to observe an ineffective fault after {max_attempts} attempts.")


def recover_esk_from_adjacent_faults_lifa(delta_esk_chain: list, esk0_guess: int) -> int:
    """Reconstructs the full 128-bit equivalent subkey from the 31 differences."""
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


def recover_master_key_candidates_lifa(delta_esk_chain: list, num_rounds: int = NUM_ROUNDS) -> List[Tuple[int, int]]:
    """Tries all 16 candidates for esk[0], returning (esk0_guess, master_key_candidate)."""
    candidates = []
    for esk0 in range(16):
        esk_R = recover_esk_from_adjacent_faults_lifa(delta_esk_chain, esk0)
        sk_R = perm_bits(esk_R)
        master_key_candidate = ror128(sk_R, -num_rounds) & MASK128
        candidates.append((esk0, master_key_candidate))
    return candidates
