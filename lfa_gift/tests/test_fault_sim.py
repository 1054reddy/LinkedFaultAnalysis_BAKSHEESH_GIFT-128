"""
Run: python3 tests/test_fault_sim.py
(run from the project root, e.g. ~/gift_lfa)

Sanity-checks the fault simulator's underlying algebra for both the last
round and the second-to-last round (with peel-back): that a linked fault
linking nibble j to nibble i in round R really does make
    w'[i] XOR w'[j] == ESK[i] XOR ESK[j]
where ESK = PermBits^-1(round_key_word) for round R. We compute the
right-hand side directly from the (secret, but known to us as testers) key
and key schedule to confirm the fault simulator and peel-back logic behave
exactly as the theory in src/lifa_attack.py / src/ldfa_attack.py predicts.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.gift import (
    encrypt, hex_to_int, get_nibble, inv_perm_bits, round_constant_word,
    build_round_key_word, peel_back_round, NUM_ROUNDS,
)
from src.fault_sim import encrypt_with_linked_fault_at_round


def esk_for_round(trace, round_idx_1based):
    step = trace[round_idx_1based - 1]
    rkword = build_round_key_word(step["U"], step["V"])
    return inv_perm_bits(rkword)


def main():
    key = hex_to_int("76543210032032032032032032032032")
    plaintext = hex_to_int("789a789a789a789a789a789a789a789a")

    _, trace, _ = encrypt(plaintext, key, num_rounds=NUM_ROUNDS, return_trace=True)
    esk_last = esk_for_round(trace, NUM_ROUNDS)
    esk_prev = esk_for_round(trace, NUM_ROUNDS - 1)

    all_ok = True

    print("-- last round (round %d) --" % NUM_ROUNDS)
    for (i, j) in [(0, 1), (5, 6), (0, 31), (10, 15)]:
        ct_faulty, _ = encrypt_with_linked_fault_at_round(
            plaintext, key, i, j, target_round=NUM_ROUNDS, num_rounds=NUM_ROUNDS)
        rc = round_constant_word(NUM_ROUNDS)
        w_faulty = inv_perm_bits(ct_faulty ^ rc)
        leaked = get_nibble(w_faulty, i) ^ get_nibble(w_faulty, j)
        expected = get_nibble(esk_last, i) ^ get_nibble(esk_last, j)
        status = "OK" if leaked == expected else "MISMATCH"
        if leaked != expected:
            all_ok = False
        print(f"fault linking nibble {j:2d} to {i:2d}: leaked=0x{leaked:x}  expected=0x{expected:x}  [{status}]")

    print(f"\n-- second-to-last round (round {NUM_ROUNDS - 1}), peeled back through round {NUM_ROUNDS} --")
    last_step = trace[NUM_ROUNDS - 1]
    for (i, j) in [(0, 1), (5, 6), (0, 31), (10, 15)]:
        ct_faulty, _ = encrypt_with_linked_fault_at_round(
            plaintext, key, i, j, target_round=NUM_ROUNDS - 1, num_rounds=NUM_ROUNDS)
        state_after_prev = peel_back_round(ct_faulty, last_step["U"], last_step["V"], NUM_ROUNDS)
        rc = round_constant_word(NUM_ROUNDS - 1)
        w_faulty = inv_perm_bits(state_after_prev ^ rc)
        leaked = get_nibble(w_faulty, i) ^ get_nibble(w_faulty, j)
        expected = get_nibble(esk_prev, i) ^ get_nibble(esk_prev, j)
        status = "OK" if leaked == expected else "MISMATCH"
        if leaked != expected:
            all_ok = False
        print(f"fault linking nibble {j:2d} to {i:2d}: leaked=0x{leaked:x}  expected=0x{expected:x}  [{status}]")

    print(f"\n{'ALL CHECKS PASSED' if all_ok else 'SOMETHING IS WRONG'}")
    return all_ok


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
