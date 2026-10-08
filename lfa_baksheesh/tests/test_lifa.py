"""
Run: python3 tests/test_lifa.py
(run from the project root, e.g. ~/baksheesh_lfa)

Runs the full Linked Ineffective Fault Analysis (LIFA) pipeline against
25 random (key, plaintext) pairs targeting a protected BAKSHEESH device
(with duplicate-and-compare redundancy countermeasure).

Measures and reports:
  - Key recovery success rate across 25 random master keys.
  - Distribution of fault-injection attempts required per key.
"""

import random
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.baksheesh import encrypt, int_to_hex, NUM_ROUNDS
from src.countermeasure import RedundantBaksheeshDevice
from src.lifa_attack import (
    collect_ineffective_ciphertext_and_leak,
    recover_master_key_candidates_lifa
)

NUM_TRIALS = 25
L = 32


def attack_once(master_key: int, plaintext: int):
    device = RedundantBaksheeshDevice(master_key, num_rounds=NUM_ROUNDS)
    correct_ct = device.encrypt_normal(plaintext)

    delta_chain = []
    for i in range(L - 1):
        delta, _, _ = collect_ineffective_ciphertext_and_leak(device, i, i + 1)
        delta_chain.append(delta)

    candidates = recover_master_key_candidates_lifa(delta_chain, num_rounds=NUM_ROUNDS)
    matches = [cand for _, cand in candidates if encrypt(plaintext, cand) == correct_ct]

    success = (len(matches) == 1 and matches[0] == master_key)
    return success, device.total_queries, device.suppressed_faults, device.ineffective_faults


def main():
    random.seed(2024)
    successes = 0
    total_query_list = []

    print(f"Running {NUM_TRIALS} independent LIFA attack trials against protected BAKSHEESH...\n")
    for t in range(NUM_TRIALS):
        mk = random.getrandbits(128)
        pt = random.getrandbits(128)
        ok, queries, suppressed, ineff = attack_once(mk, pt)
        successes += ok
        total_query_list.append(queries)
        mark = "OK" if ok else "FAIL"
        print(f"trial {t+1:2d}/{NUM_TRIALS}: key={int_to_hex(mk)} | "
              f"queries={queries:3d} (suppressed={suppressed:3d}, ineff={ineff:2d})  [{mark}]")

    avg_queries = sum(total_query_list) / len(total_query_list)
    min_queries = min(total_query_list)
    max_queries = max(total_query_list)

    print(f"\n=======================================================")
    print(f"LIFA Reliability Results Summary:")
    print(f"  Success rate: {successes}/{NUM_TRIALS} ({successes/NUM_TRIALS * 100:.1f}%)")
    print(f"  Average queries per 128-bit key recovery: {avg_queries:.1f}")
    print(f"  Query range: min={min_queries}, max={max_queries}")
    print(f"  Theoretical expectation: 31 * 16 = 496 queries")
    print(f"=======================================================")

    return successes == NUM_TRIALS


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
