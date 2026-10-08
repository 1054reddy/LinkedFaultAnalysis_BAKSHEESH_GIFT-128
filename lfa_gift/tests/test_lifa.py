"""
Run: python3 tests/test_lifa.py
(run from the project root, e.g. ~/gift_lfa)

Runs the full two-phase Linked Ineffective Fault Analysis (LIFA) pipeline
against N random (key, plaintext) pairs targeting a protected GIFT-128
device (with duplicate-and-compare redundancy countermeasure).

Measures and reports:
  - Key recovery success rate across N random master keys.
  - Distribution of fault-injection queries required per key.
  - Master-key candidate count after stitching both attacked rounds.
"""

import random
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.gift import int_to_hex, NUM_ROUNDS
from src.countermeasure import RedundantGiftDevice
from src.lifa_attack import recover_master_key_lifa

NUM_TRIALS = 10


def attack_once(master_key: int, plaintext: int):
    device = RedundantGiftDevice(master_key, num_rounds=NUM_ROUNDS)
    correct_ct = device.encrypt_normal(plaintext)
    key, num_candidates = recover_master_key_lifa(device, plaintext, correct_ct, num_rounds=NUM_ROUNDS)
    success = (key == master_key)
    return success, device.total_queries, device.suppressed_faults, device.ineffective_faults, num_candidates


def main():
    random.seed(2024)
    successes = 0
    total_query_list = []

    print(f"Running {NUM_TRIALS} independent two-phase LIFA attack trials against protected GIFT-128...\n")
    for t in range(NUM_TRIALS):
        mk = random.getrandbits(128)
        pt = random.getrandbits(128)
        ok, queries, suppressed, ineff, num_cand = attack_once(mk, pt)
        successes += ok
        total_query_list.append(queries)
        mark = "OK" if ok else "FAIL"
        print(f"trial {t+1:2d}/{NUM_TRIALS}: key={int_to_hex(mk)} | "
              f"queries={queries:4d} (suppressed={suppressed:4d}, ineff={ineff:3d}), "
              f"candidates={num_cand:3d}  [{mark}]")

    avg_queries = sum(total_query_list) / len(total_query_list)
    min_queries = min(total_query_list)
    max_queries = max(total_query_list)

    print(f"\n=======================================================")
    print(f"LIFA Reliability Results Summary (GIFT-128, two attacked rounds):")
    print(f"  Success rate: {successes}/{NUM_TRIALS} ({successes/NUM_TRIALS * 100:.1f}%)")
    print(f"  Average queries per 128-bit key recovery: {avg_queries:.1f}")
    print(f"  Query range: min={min_queries}, max={max_queries}")
    print(f"  Theoretical expectation per round: 31 * 16 = 496 queries -> ~992 for both rounds")
    print(f"=======================================================")

    return successes == NUM_TRIALS


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
