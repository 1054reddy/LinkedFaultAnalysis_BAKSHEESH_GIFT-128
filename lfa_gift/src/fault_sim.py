"""
Simulates the effect of a linked instruction-skip fault (same physical model
as ../baksheesh_lfa/src/fault_sim.py, per Beigizad et al., "Linked Fault
Analysis", IEEE TIFS 2024) on GIFT-128's SubCells layer in the final round.

Physical model being simulated:
  During the last round's SubCells execution, the S-box lookup table is
  called once per nibble, in nibble order 0..31. An instruction skip while
  nibble j's S-box output is being fetched/stored causes it to be
  overwritten by the value that was just computed for nibble i (i < j):
  y'_R[j] = S(x_R[i]). All other nibbles are computed correctly.

We do not model instruction-level timing -- we directly inject the
resulting value-level effect on SubCells, then re-run PermBits and
AddRoundKey (using that round's real U, V, and round-constant word) to
get the faulty ciphertext.
"""

from .gift import (
    encrypt, sub_cells, perm_bits, get_nibble, set_nibble, NUM_ROUNDS,
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
    return encrypt_with_linked_fault_at_round(plaintext, master_key, i, j,
                                               target_round=num_rounds, num_rounds=num_rounds)


def encrypt_with_linked_fault_at_round(plaintext: int, master_key: int, i: int, j: int,
                                        target_round: int, num_rounds: int = NUM_ROUNDS):
    """
    Encrypt plaintext with a linked fault injected in the SubCells layer of
    ROUND `target_round` (not necessarily the last), such that
    y'_R[j] = S(x_R[i]) instead of the correct S(x_R[j]) at that round, and
    the fault then propagates naturally through any remaining rounds.

    The GIFT-128 key schedule is data-independent (it only depends on the
    master key, never on the cipher state), so every later round's (U, V,
    round-constant) are unaffected by the fault -- we can safely reuse the
    fault-free trace's per-round key material to keep simulating forward
    from the faulted round.

    Returns (faulty_ciphertext, x_R) where x_R is the correct input state to
    round `target_round`'s SubCells layer -- returned only for sanity-checks;
    a real attacker does NOT get to see x_R.
    """
    assert i != j
    _, trace, _ = encrypt(plaintext, master_key, num_rounds=num_rounds, return_trace=True)
    target = trace[target_round - 1]
    x_R = target["x"]
    y_R_correct = sub_cells(x_R)                # == target["y"]

    faulty_val_i = get_nibble(y_R_correct, i)   # == S(x_R[i]) since nibble i unaffected
    y_faulty = set_nibble(y_R_correct, j, faulty_val_i)

    state = perm_bits(y_faulty) ^ target["rcword"] ^ target["rkword"]
    for r in range(target_round + 1, num_rounds + 1):
        step = trace[r - 1]
        y = sub_cells(state)
        z = perm_bits(y)
        state = z ^ step["rcword"] ^ step["rkword"]
    return state, x_R
