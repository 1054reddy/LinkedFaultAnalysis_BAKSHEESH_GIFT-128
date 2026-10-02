"""
Simulation of a redundancy-based countermeasure (duplicate-and-compare
detection) for GIFT-128 on embedded devices. Mirrors
../baksheesh_lfa/src/countermeasure.py.

Countermeasure Model:
- The device executes encryption with redundant checks.
- When an external fault injection is simulated on the primary crypto core:
  - If the fault is EFFECTIVE (alters the state / output): the duplicate-and-
    compare unit detects the mismatch and SUPPRESSES the output (returns
    None / error).
  - If the fault is INEFFECTIVE (state is unaltered, i.e. y_R[i] == y_R[j]):
    the primary output matches the redundant execution, and the device
    emits a valid ciphertext.
"""

from typing import Optional, Tuple
from .gift import encrypt, sub_cells, perm_bits, get_nibble, NUM_ROUNDS, MASK128


class RedundantGiftDevice:
    """
    Represents a tamper-resistant cryptographic device running GIFT-128
    with hardware/software redundancy checking.
    """

    def __init__(self, master_key: int, num_rounds: int = NUM_ROUNDS):
        self.master_key = master_key & MASK128
        self.num_rounds = num_rounds
        self.total_queries = 0
        self.suppressed_faults = 0
        self.ineffective_faults = 0

    def reset_stats(self):
        self.total_queries = 0
        self.suppressed_faults = 0
        self.ineffective_faults = 0

    def encrypt_normal(self, plaintext: int) -> int:
        """Standard fault-free encryption."""
        return encrypt(plaintext, self.master_key, num_rounds=self.num_rounds)

    def encrypt_with_redundancy_and_fault(
        self, plaintext: int, i: int, j: int, num_rounds: int = None
    ) -> Tuple[Optional[int], bool]:
        """
        Executes encryption with a simulated linked fault on nibble pair (i, j)
        in the SubCells layer of round `num_rounds` (default: the final round),
        protected by duplicate-and-compare redundancy.

        Returns:
            (ciphertext, is_ineffective):
                - If ineffective: returns (correct_ciphertext, True).
                - If effective (detected): returns (None, False).
        """
        assert i != j
        target_round = num_rounds or self.num_rounds
        self.total_queries += 1

        golden_ct, trace, _ = encrypt(
            plaintext, self.master_key, num_rounds=self.num_rounds, return_trace=True
        )
        target = trace[target_round - 1]
        x_R = target["x"]
        y_R_correct = sub_cells(x_R)

        # Physical link: y'_R[j] = S(x_R[i])
        val_i = get_nibble(y_R_correct, i)
        val_j = get_nibble(y_R_correct, j)

        is_ineffective = (val_i == val_j)

        if is_ineffective:
            self.ineffective_faults += 1
            return golden_ct, True
        else:
            self.suppressed_faults += 1
            return None, False
