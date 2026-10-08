"""
Run: python3 tests/test_fault_sim.py
(run from the project root, e.g. ~/baksheesh_lfa)

Sanity-checks the fault simulator's underlying algebra: that a linked fault
linking nibble j to nibble i in the last round really does make
    w'[i] XOR w'[j] == esk[i] XOR esk[j]
where esk = PermBits^-1(round_key). We compute the right-hand side directly
from the (secret, but known to us as testers) key to confirm the fault
simulator behaves exactly as the theory in Phase 3 predicts.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.baksheesh import (
    encrypt, hex_to_int, get_nibble, inv_perm_bits, add_constants, NUM_ROUNDS
)
from src.fault_sim import encrypt_with_linked_fault_last_round


def main():
    key = hex_to_int("76543210032032032032032032032032")
    plaintext = hex_to_int("789a789a789a789a789a789a789a789a")

    # "God-mode" info a real attacker would NOT have -- used only to verify our math.
    _, trace, k = encrypt(plaintext, key, return_trace=True)
    esk35 = inv_perm_bits(k[NUM_ROUNDS + 1])

    all_ok = True
    for (i, j) in [(0, 1), (5, 6), (0, 31), (10, 15)]:
        ct_faulty, _ = encrypt_with_linked_fault_last_round(plaintext, key, i, j)
        w_faulty = inv_perm_bits(ct_faulty ^ add_constants(0, NUM_ROUNDS))
        leaked = get_nibble(w_faulty, i) ^ get_nibble(w_faulty, j)
        expected = get_nibble(esk35, i) ^ get_nibble(esk35, j)
        status = "OK" if leaked == expected else "MISMATCH"
        if leaked != expected:
            all_ok = False
        print(f"fault linking nibble {j:2d} to {i:2d}: leaked=0x{leaked:x}  expected=0x{expected:x}  [{status}]")

    print(f"\n{'ALL CHECKS PASSED' if all_ok else 'SOMETHING IS WRONG'}")
    return all_ok


if __name__ == "__main__":
    sys.exit(0 if main() else 1)