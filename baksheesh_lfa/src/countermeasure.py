"""
Simulation of a redundancy-based countermeasure (duplicate-and-compare detection)
for BAKSHEESH on embedded devices.

Countermeasure Model:
- The device executes encryption with redundant checks.
- When an external fault injection is simulated on the primary crypto core:
  - If the fault is EFFECTIVE (alters the state / output): the duplicate-and-compare
    unit detects the mismatch and SUPPRESSES the output (returns None / error).
  - If the fault is INEFFECTIVE (state is unaltered, i.e., y_R[i] == y_R[j]): the primary
    output matches the redundant execution, and the device emits a valid ciphertext.
"""

import random
from typing import Optional, Tuple
from .baksheesh import (
    encrypt, sub_cells, perm_bits, add_constants, get_nibble, set_nibble,
    NUM_ROUNDS, MASK128
)


class RedundantBaksheeshDevice:
    """
    Represents a tamper-resistant cryptographic device running BAKSHEESH
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
        self, plaintext: int, i: int, j: int
    ) -> Tuple[Optional[int], bool]:
        """
        Executes encryption with a simulated linked fault on nibble pair (i, j)
        in the final round's SubCells, protected by duplicate-and-compare redundancy.

        Returns:
            (ciphertext, is_ineffective):
                - If ineffective: returns (correct_ciphertext, True).
                - If effective (detected): returns (None, False).
        """
        assert i != j
        self.total_queries += 1

        # Golden / Redundant execution (or reference check)
        golden_ct, trace, k = encrypt(
            plaintext, self.master_key, num_rounds=self.num_rounds, return_trace=True
        )

        # Primary execution under fault injection
        x_R = trace[-1]["x"]
        y_R_correct = sub_cells(x_R)

        # Physical link: y'_R[j] = S(x_R[i])
        val_i = get_nibble(y_R_correct, i)
        val_j = get_nibble(y_R_correct, j)

        is_ineffective = (val_i == val_j)

        if is_ineffective:
            # Fault did not modify the state (y'_R[j] == y_R[j])
            self.ineffective_faults += 1
            return golden_ct, True
        else:
            # State altered -> detected by redundancy check -> output suppressed
            self.suppressed_faults += 1
            return None, False
