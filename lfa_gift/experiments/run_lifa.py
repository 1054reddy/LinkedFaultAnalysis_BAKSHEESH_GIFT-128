"""
Full two-phase Linked Ineffective Fault Analysis (LIFA) pipeline against
Protected GIFT-128:

Attack Scenario:
  - GIFT-128 implementation protected with a Duplicate-and-Compare countermeasure.
  - The attacker cannot access faulty ciphertexts directly (suppressed by the
    countermeasure); only ineffective faults leak information.
  - PHASE 1 attacks round 40 (the last round) via 31 adjacent-nibble-pair
    linked faults, recovering that round's 64-bit round key (U, V) up to a
    small residual ambiguity.
  - PHASE 2 attacks round 39 (the second-to-last round) the same way, but
    first peels back round 40 using each PHASE 1 candidate.
  - The two rounds' recovered key-schedule words are stitched into full
    128-bit master-key candidates and the key schedule is inverted back to
    the master key.
  - 1 known (plaintext, ciphertext) pair disambiguates the candidates down
    to the unique correct master key.

See src/lifa_attack.py's module docstring for why GIFT-128 needs two
attacked rounds where BAKSHEESH (see ../baksheesh_lfa) only needs one.
"""

import random
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.gift import int_to_hex, NUM_ROUNDS
from src.countermeasure import RedundantGiftDevice
from src.lifa_attack import recover_master_key_lifa


def main():
    random.seed(4321)
    master_key = random.getrandbits(128)
    plaintext_verify = random.getrandbits(128)
    print(f"[secret] master_key = {int_to_hex(master_key)}")
    print(f"[secret] verification plaintext = {int_to_hex(plaintext_verify)}\n")

    device = RedundantGiftDevice(master_key, num_rounds=NUM_ROUNDS)
    correct_ciphertext = device.encrypt_normal(plaintext_verify)

    print(f"[attack] Phase 1: querying protected device under linked faults in round {NUM_ROUNDS}...")
    print(f"[attack] Phase 2: querying protected device under linked faults in round {NUM_ROUNDS - 1}"
          f" (peeling back round {NUM_ROUNDS} for each phase-1 candidate)...\n")

    key, num_candidates = recover_master_key_lifa(
        device, plaintext_verify, correct_ciphertext, num_rounds=NUM_ROUNDS
    )

    total_injections = device.total_queries
    suppressed = device.suppressed_faults
    ineffective = device.ineffective_faults
    empirical_rate = (ineffective / total_injections) * 100 if total_injections else 0.0

    print(f"[attack] Total fault injection queries: {total_injections}")
    print(f"[attack] Effective faults suppressed by countermeasure: {suppressed}")
    print(f"[attack] Ineffective faults bypassing countermeasure: {ineffective} ({empirical_rate:.2f}%)")
    print(f"[attack] Master-key candidates after stitching both rounds: {num_candidates} "
          f"(2^128 -> {num_candidates} via two 4-way-ambiguous round attacks)\n")

    success = (key == master_key)
    print(f"[result] Unique correct key recovered: {success}")
    if success:
        print(f"[result] Recovered key = {int_to_hex(key)}")
        print(f"[result] Redundancy countermeasure successfully bypassed via two-phase LIFA!")
    return success


if __name__ == "__main__":
    ok = main()
    sys.exit(0 if ok else 1)
