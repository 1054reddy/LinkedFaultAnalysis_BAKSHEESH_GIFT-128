"""
Full Linked Ineffective Fault Analysis (LIFA) Pipeline against Protected BAKSHEESH:

Attack Scenario:
  - BAKSHEESH implementation protected with a Duplicate-and-Compare countermeasure.
  - The attacker cannot access faulty ciphertexts (they are suppressed/blocked by the countermeasure).
  - The attacker injects linked faults on adjacent nibble pairs (i, i+1) for i = 0..30 into round 35 SubCells.
  - Effective faults are suppressed (returns None).
  - When an ineffective fault occurs (x_R[i] == x_R[i+1]), the device outputs a valid ciphertext C.
  - From this single ineffective ciphertext, Algorithm 1 extracts Delta-esk[i, i+1].
  - 31 ineffective ciphertexts reduce the 2^128 key space to 16 master-key candidates.
  - 1 known (plaintext, ciphertext) pair uniquely recovers the secret 128-bit master key.
"""

import random
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.baksheesh import encrypt, hex_to_int, int_to_hex, NUM_ROUNDS
from src.countermeasure import RedundantBaksheeshDevice
from src.lifa_attack import (
    collect_ineffective_ciphertext_and_leak,
    recover_master_key_candidates_lifa
)


def main():
    random.seed(4321)
    master_key = random.getrandbits(128)
    plaintext_verify = random.getrandbits(128)
    print(f"[secret] master_key = {int_to_hex(master_key)}")
    print(f"[secret] verification plaintext = {int_to_hex(plaintext_verify)}\n")

    # Instantiate protected target device
    device = RedundantBaksheeshDevice(master_key, num_rounds=NUM_ROUNDS)
    correct_ciphertext = device.encrypt_normal(plaintext_verify)

    L = 32  # 32 nibbles in 128-bit state
    delta_chain = []
    pair_queries = []

    print("[attack] Querying protected device under linked faults (i, i+1)...")
    for i in range(L - 1):
        delta, queries, ineff_ct = collect_ineffective_ciphertext_and_leak(device, i, i + 1)
        delta_chain.append(delta)
        pair_queries.append(queries)

    total_injections = device.total_queries
    suppressed = device.suppressed_faults
    ineffective = device.ineffective_faults
    empirical_rate = (ineffective / total_injections) * 100

    print(f"[attack] Ineffective ciphertexts collected: {len(delta_chain)} (1 per adjacent pair)")
    print(f"[attack] Total fault injection queries: {total_injections}")
    print(f"[attack] Effective faults suppressed by countermeasure: {suppressed}")
    print(f"[attack] Ineffective faults bypassing countermeasure: {ineffective} ({empirical_rate:.2f}%)")
    print(f"[attack] Average queries per nibble pair: {sum(pair_queries)/len(pair_queries):.1f}\n")
    print(f"[attack] Leaked Delta-esk chain: {[hex(x) for x in delta_chain]}\n")

    candidates = recover_master_key_candidates_lifa(delta_chain, num_rounds=NUM_ROUNDS)
    print(f"[attack] {len(candidates)} master-key candidates after full key-space reduction "
          f"(2^128 -> 2^4) using ONLY ineffective ciphertexts:")
    for esk0, cand in candidates:
        print(f"   esk0={esk0:2d}  candidate={int_to_hex(cand)}")

    matches = [cand for _, cand in candidates
               if encrypt(plaintext_verify, cand) == correct_ciphertext]
    print(f"\n[attack] Candidates consistent with one known (plaintext, ciphertext) pair: "
          f"{[int_to_hex(m) for m in matches]}")

    success = (len(matches) == 1 and matches[0] == master_key)
    print(f"\n[result] Unique correct key recovered: {success}")
    if success:
        print(f"[result] Recovered key = {int_to_hex(matches[0])}")
        print(f"[result] Redundancy countermeasure successfully bypassed via LIFA!")
    return success


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
