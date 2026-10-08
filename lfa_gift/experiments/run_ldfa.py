"""
Full two-phase LDFA pipeline against (unprotected) GIFT-128:
  1. Pick a secret master key + plaintext (attacker knows neither).
  2. PHASE 1: inject linked faults for i=0..30 in round 40's SubCells,
     leaking that round's (U, V) up to a small residual ambiguity.
  3. PHASE 2: inject linked faults in round 39's SubCells, peeling back
     round 40 (using each phase-1 candidate) before leaking round 39's
     (U, V).
  4. Stitch both rounds' key-schedule words into full master-key
     candidates and invert the key schedule.
  5. Disambiguate the candidates using ONE known (plaintext, ciphertext) pair.

Total data complexity: 31 + 31 = 62 faulty ciphertexts (plus 1 known
fault-free ciphertext for verification).
"""

import random
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.gift import encrypt, int_to_hex, NUM_ROUNDS
from src.ldfa_attack import recover_master_key_ldfa


def main():
    random.seed(1234)
    master_key = random.getrandbits(128)
    plaintext = random.getrandbits(128)
    verify_plaintext = random.getrandbits(128)
    print(f"[secret] master_key = {int_to_hex(master_key)}")
    print(f"[secret] attack plaintext = {int_to_hex(plaintext)}\n")

    verify_ciphertext = encrypt(verify_plaintext, master_key)

    print(f"[attack] Phase 1: 31 linked faults in round {NUM_ROUNDS}...")
    print(f"[attack] Phase 2: 31 linked faults in round {NUM_ROUNDS - 1} "
          f"(peeling back round {NUM_ROUNDS} per phase-1 candidate)...\n")

    key, num_candidates = recover_master_key_ldfa(
        plaintext, master_key, verify_plaintext, verify_ciphertext, num_rounds=NUM_ROUNDS
    )

    print(f"[attack] collected 62 faulty ciphertexts total (31 per round)")
    print(f"[attack] master-key candidates after stitching both rounds: {num_candidates}\n")

    success = (key == master_key)
    print(f"[result] unique correct key recovered: {success}")
    if success:
        print(f"[result] recovered key = {int_to_hex(key)}")
    return success


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
