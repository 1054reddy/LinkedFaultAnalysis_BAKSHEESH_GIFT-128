"""
Simulates the *effect* of a linked instruction-skip fault (per Beigizad et al.,
"Linked Fault Analysis", IEEE TIFS 2024) on BAKSHEESH's SubCells layer in the
final round.

Physical model being simulated:
  During the last round's SubCells execution, the S-box lookup table is called
  once per nibble, in nibble order 0..31. An instruction skip while nibble j's
  S-box output is being fetched/stored causes it to be overwritten by the value
  that was just computed for nibble i (i < j): y'_35[j] = S(x_35[i]).
  All other nibbles are computed correctly. This is the "linked fault".

We do not model instruction-level timing (no real microcontroller here) --
we directly inject the resulting *value-level* effect, which is exactly what
the attack's key-recovery math depends on.
"""

from .baksheesh import (
    encrypt, sub_cells, perm_bits, add_constants, get_nibble, set_nibble,
    NUM_ROUNDS,
)


def encrypt_with_linked_fault_last_round(plaintext: int, master_key: int, i: int, j: int,
                                          num_rounds: int = NUM_ROUNDS):
    """
    Encrypt plaintext with a linked fault injected in the SubCells layer of the
    FINAL round, such that y'_R[j] = S(x_R[i]) instead of the correct S(x_R[j]).

    Returns (faulty_ciphertext, x_R) where x_R is the correct input state to the
    final round's SubCells layer -- returned only so we can sanity-check things
    in this phase; a real attacker does NOT get to see x_R.
    """
    assert i != j
    # Run num_rounds-1 rounds correctly to get the input to the final round.
    _, trace, k = encrypt(plaintext, master_key, num_rounds=num_rounds, return_trace=True)
    x_R = trace[-1]["x"]                      # correct input to SubCells of final round
    y_R_correct = sub_cells(x_R)               # correct SubCells output

    # Inject the linked fault: overwrite nibble j with S(x_R[i])
    faulty_val_i = get_nibble(y_R_correct, i)  # == S(x_R[i]) since nibble i unaffected
    y_R_faulty = set_nibble(y_R_correct, j, faulty_val_i)

    state = perm_bits(y_R_faulty)
    state = add_constants(state, num_rounds)
    ct_faulty = state ^ k[num_rounds + 1]
    return ct_faulty, x_R