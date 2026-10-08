"""
Full LDFA pipeline against BAKSHEESH:
  1. Pick a secret master key + plaintext (attacker knows neither).
  2. For i = 0..30, inject a linked fault linking nibble (i+1) to nibble i.
     Each fault produces ONE faulty ciphertext.
  3. From each faulty ciphertext alone, leak Delta-esk[i, i+1] (Algorithm 1).
  4. Brute-force the 16 candidates for esk[0], reconstruct 16 master-key
     candidates.
  5. Disambiguate the 16 candidates using ONE known (plaintext, ciphertext)
     pair.

Total data complexity: 31 faulty ciphertexts.
"""

import random
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.baksheesh import encrypt, hex_to_int, int_to_hex, NUM_ROUNDS
from src.fault_sim import encrypt_with_linked_fault_last_round
from src.ldfa_attack import leak_delta_esk, recover_master_key_candidates


def main():
    random.seed(1234)
    master_key = random.getrandbits(128)
    plaintext = random.getrandbits(128)
    print(f"[secret] master_key = {int_to_hex(master_key)}")
    print(f"[secret] plaintext  = {int_to_hex(plaintext)}\n")

    correct_ciphertext = encrypt(plaintext, master_key)

    L = 32  # number of nibbles in BAKSHEESH's 128-bit state
    delta_chain = []
    for i in range(L - 1):
        ct_faulty, _ = encrypt_with_linked_fault_last_round(plaintext, master_key, i, i + 1)
        d = leak_delta_esk(ct_faulty, i, i + 1, num_rounds=NUM_ROUNDS)
        delta_chain.append(d)
    print(f"[attack] collected {len(delta_chain)} faulty ciphertexts")
    print(f"[attack] leaked Delta-esk chain: {[hex(x) for x in delta_chain]}\n")

    candidates = recover_master_key_candidates(delta_chain, num_rounds=NUM_ROUNDS)
    print(f"[attack] {len(candidates)} master-key candidates after full-key-space reduction "
          f"(2^128 -> 2^4) using ONLY faulty ciphertexts:")
    for esk0, cand in candidates:
        print(f"   esk0={esk0:2d}  candidate={int_to_hex(cand)}")

    matches = [cand for _, cand in candidates
               if encrypt(plaintext, cand) == correct_ciphertext]
    print(f"\n[attack] candidates consistent with one known (plaintext, ciphertext) pair: "
          f"{[int_to_hex(m) for m in matches]}")

    success = (len(matches) == 1 and matches[0] == master_key)
    print(f"\n[result] unique correct key recovered: {success}")
    if success:
        print(f"[result] recovered key = {int_to_hex(matches[0])}")
    return success


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)