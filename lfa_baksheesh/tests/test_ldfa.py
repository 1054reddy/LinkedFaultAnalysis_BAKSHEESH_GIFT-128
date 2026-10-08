"""
Run: python3 tests/test_ldfa.py
Runs the full LDFA key-recovery pipeline against 25 random (key, plaintext)
pairs and reports the success rate.
"""
import random
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.baksheesh import encrypt, int_to_hex, NUM_ROUNDS
from src.fault_sim import encrypt_with_linked_fault_last_round
from src.ldfa_attack import leak_delta_esk, recover_master_key_candidates

NUM_TRIALS = 25
L = 32


def attack_once(master_key: int, plaintext: int) -> bool:
    delta_chain = []
    for i in range(L - 1):
        ct_faulty, _ = encrypt_with_linked_fault_last_round(plaintext, master_key, i, i + 1)
        delta_chain.append(leak_delta_esk(ct_faulty, i, i + 1, num_rounds=NUM_ROUNDS))

    candidates = recover_master_key_candidates(delta_chain, num_rounds=NUM_ROUNDS)
    correct_ct = encrypt(plaintext, master_key)
    matches = [cand for _, cand in candidates if encrypt(plaintext, cand) == correct_ct]

    return len(matches) == 1 and matches[0] == master_key


def main():
    random.seed(42)
    successes = 0
    for t in range(NUM_TRIALS):
        mk = random.getrandbits(128)
        pt = random.getrandbits(128)
        ok = attack_once(mk, pt)
        successes += ok
        mark = "OK" if ok else "FAIL"
        print(f"trial {t+1:2d}/{NUM_TRIALS}: key={int_to_hex(mk)}  [{mark}]")
    print(f"\n{successes}/{NUM_TRIALS} trials fully recovered the correct 128-bit key")
    return successes == NUM_TRIALS


if __name__ == "__main__":
    sys.exit(0 if main() else 1)