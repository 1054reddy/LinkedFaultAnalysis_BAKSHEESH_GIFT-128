"""
Run: python3 tests/test_ldfa.py
(run from the project root, e.g. ~/gift_lfa)

Runs the full two-phase LDFA pipeline against N random (key, plaintext)
pairs targeting an unprotected GIFT-128 implementation, measuring key
recovery success rate.
"""

import random
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.gift import encrypt, int_to_hex, NUM_ROUNDS
from src.ldfa_attack import recover_master_key_ldfa

NUM_TRIALS = 10


def attack_once(master_key: int, attack_plaintext: int, verify_plaintext: int):
    verify_ciphertext = encrypt(verify_plaintext, master_key)
    key, num_candidates = recover_master_key_ldfa(
        attack_plaintext, master_key, verify_plaintext, verify_ciphertext, num_rounds=NUM_ROUNDS
    )
    return (key == master_key), num_candidates


def main():
    random.seed(1234)
    successes = 0

    print(f"Running {NUM_TRIALS} independent two-phase LDFA attack trials against unprotected GIFT-128...\n")
    for t in range(NUM_TRIALS):
        mk = random.getrandbits(128)
        pt_attack = random.getrandbits(128)
        pt_verify = random.getrandbits(128)
        ok, num_cand = attack_once(mk, pt_attack, pt_verify)
        successes += ok
        mark = "OK" if ok else "FAIL"
        print(f"trial {t+1:2d}/{NUM_TRIALS}: key={int_to_hex(mk)} | candidates={num_cand:3d}  [{mark}]")

    print(f"\n=======================================================")
    print(f"LDFA Reliability Results Summary (GIFT-128, two attacked rounds):")
    print(f"  Success rate: {successes}/{NUM_TRIALS} ({successes/NUM_TRIALS * 100:.1f}%)")
    print(f"  Data complexity per key: 62 faulty ciphertexts (31 per round) + 1 known pair")
    print(f"=======================================================")

    return successes == NUM_TRIALS


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
