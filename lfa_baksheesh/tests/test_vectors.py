"""
Run: python3 tests/test_vectors.py
(run from the project root, e.g. ~/baksheesh_lfa)

Validates the BAKSHEESH implementation against all 8 official test vectors
from Table 14 of the BAKSHEESH paper. Exits with code 0 if all pass, 1 otherwise.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.baksheesh import encrypt, hex_to_int, int_to_hex
from src.constants import TEST_VECTORS


def main():
    ok = 0
    for i, (k, p, c) in enumerate(TEST_VECTORS, 1):
        ct = encrypt(hex_to_int(p), hex_to_int(k))
        got = int_to_hex(ct)
        status = "OK" if got == c else "MISMATCH"
        if got == c:
            ok += 1
        print(f"vector {i}: key={k}")
        print(f"           plaintext ={p}")
        print(f"           expected  ={c}")
        print(f"           got       ={got}   [{status}]")
    print(f"\n{ok}/{len(TEST_VECTORS)} test vectors passed")
    return ok == len(TEST_VECTORS)


if __name__ == "__main__":
    sys.exit(0 if main() else 1)