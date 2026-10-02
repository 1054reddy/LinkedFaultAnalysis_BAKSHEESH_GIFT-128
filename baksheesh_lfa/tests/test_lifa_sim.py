"""
Run: python3 tests/test_lifa_sim.py
(run from the project root, e.g. ~/baksheesh_lfa)

Validates the simulation and algebra of Linked Ineffective Fault Analysis (LIFA):
  1. Checks that the redundancy countermeasure suppresses effective faults (returns None).
  2. Checks that when y_R[i] == y_R[j], the fault is ineffective and the device returns a valid ciphertext.
  3. Checks that the leaked Delta-esk computed from the ineffective ciphertext exactly matches
     the true esk difference for various nibble pairs.
  4. Empirically measures the ineffectiveness rate to confirm it aligns with theoretical 2^-4 = 6.25%.
"""

import sys, os
import random
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.baksheesh import (
    encrypt, hex_to_int, int_to_hex, get_nibble, inv_perm_bits, add_constants,
    NUM_ROUNDS
)
from src.countermeasure import RedundantBaksheeshDevice
from src.lifa_attack import leak_delta_esk_ineffective


def main():
    random.seed(999)
    key = hex_to_int("76543210032032032032032032032032")
    device = RedundantBaksheeshDevice(key, num_rounds=NUM_ROUNDS)

    # Reference / God-mode subkey for verification
    _, _, k = encrypt(0, key, return_trace=True)
    esk35 = inv_perm_bits(k[NUM_ROUNDS + 1])

    print("--- 1. Testing Countermeasure Suppression & Ineffective Leakage ---")
    all_ok = True
    test_pairs = [(0, 1), (5, 6), (0, 31), (10, 15), (20, 21)]

    for (i, j) in test_pairs:
        found_ineffective = False
        attempts = 0
        while not found_ineffective and attempts < 200:
            attempts += 1
            pt = random.getrandbits(128)
            ct, is_ineffective = device.encrypt_with_redundancy_and_fault(pt, i, j)
            if is_ineffective:
                found_ineffective = True
                assert ct is not None, "Ineffective ciphertext should not be None"
                leaked = leak_delta_esk_ineffective(ct, i, j, num_rounds=NUM_ROUNDS)
                expected = get_nibble(esk35, i) ^ get_nibble(esk35, j)
                status = "OK" if leaked == expected else "MISMATCH"
                if leaked != expected:
                    all_ok = False
                print(f"pair ({i:2d}, {j:2d}): ineffective found in {attempts:2d} attempts | "
                      f"leaked=0x{leaked:x}  expected=0x{expected:x}  [{status}]")
            else:
                assert ct is None, "Effective fault must be suppressed by redundancy countermeasure"

    print("\n--- 2. Empirical Ineffectiveness Rate Test (10,000 samples) ---")
    N = 10000
    ineffective_count = 0
    i_test, j_test = 0, 1
    for _ in range(N):
        pt = random.getrandbits(128)
        _, is_ineff = device.encrypt_with_redundancy_and_fault(pt, i_test, j_test)
        if is_ineff:
            ineffective_count += 1

    emp_rate = ineffective_count / N
    theo_rate = 1.0 / 16.0  # 2^-4 = 0.0625 for 4-bit nibbles
    print(f"Total injections: {N}")
    print(f"Ineffective events: {ineffective_count} ({emp_rate * 100:.2f}%)")
    print(f"Theoretical rate: 2^-4 = {theo_rate * 100:.2f}%")

    rate_ok = abs(emp_rate - theo_rate) < 0.01
    print(f"Ineffectiveness rate check: [{'OK' if rate_ok else 'FAIL'}]")
    if not rate_ok:
        all_ok = False

    print(f"\n{'ALL LIFA SIM CHECKS PASSED' if all_ok else 'SOME CHECKS FAILED'}")
    return all_ok


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
