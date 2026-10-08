# gift_lfa

A Linked (Ineffective) Fault Analysis toolkit for **GIFT-128**, mirroring the
structure and attack model of `../baksheesh_lfa`.

```
gift_lfa/
├── src/
│   ├── gift.py           # GIFT-128 cipher (S-box, PermBits, key schedule, encrypt)
│   ├── constants.py       # GIFT-128 S-box, bit permutation, round constants, test vectors
│   ├── fault_sim.py        # Linked-fault injection (any round, propagates forward)
│   ├── countermeasure.py   # Duplicate-and-compare protected-device simulation
│   ├── ldfa_attack.py      # Linked Differential Fault Attack (unprotected device)
│   └── lifa_attack.py      # Linked Ineffective Fault Attack (protected device)
├── experiments/
│   ├── run_ldfa.py
│   └── run_lifa.py
├── results/
│   ├── phase1_gift_validation/
│   ├── phase2_fault_simulation/
│   └── phase5_lifa/
└── tests/
    ├── test_vectors.py
    ├── test_fault_sim.py
    ├── test_ldfa.py
    └── test_lifa.py
```

## Running it

```
cd gift_lfa
python3 tests/test_vectors.py      # validate the cipher against known-answer vectors
python3 tests/test_fault_sim.py    # validate the fault-leak algebra (both attacked rounds)
python3 experiments/run_ldfa.py    # full LDFA key-recovery demo
python3 experiments/run_lifa.py    # full LIFA key-recovery demo (protected device)
python3 tests/test_ldfa.py         # 10-trial LDFA reliability sweep
python3 tests/test_lifa.py         # 10-trial LIFA reliability sweep (slower: ~8-9k queries/trial)
```

All of the above are self-contained, cross-validated against the canonical
GIFT-128 known-answer test vector (all-zero key/plaintext -> ciphertext
`cd0bd738388ad3f668b15a36ceb6ff92`) plus two independent reference vectors.

## Why GIFT-128 needs *two* attacked rounds, not one

This is the central structural difference from BAKSHEESH, and it's worth
understanding before reading the attack code:

- **BAKSHEESH's `AddRoundKey`** XORs a *full* 128-bit subkey into the entire
  permuted state every round. One round's "equivalent subkey" (ESK) is
  therefore a bijective function of the *whole* 128-bit master key (via a
  single 1-bit rotation), so a single last-round fault attack pins down the
  entire master key (up to a 16-way ambiguity from the one ESK nibble the
  31-pair adjacent-difference chain can't fix).

- **GIFT-128's `AddRoundKey`** only ever injects **64** key bits (`U`, `V`)
  into the two "middle" bit positions of each 4-bit nibble — the nibble's
  LSB and MSB are never touched by the key (see the module docstring in
  `src/gift.py`). So one round's ESK only pins down 64 of the 128
  key-schedule bits, and empirically only a **4-way** (not 16-way)
  ambiguity survives per round, because 2 of the free ESK nibble's 4 bits
  land (via `PermBits`) on key-free positions.

To recover the full 128-bit master key we therefore attack **the last two
rounds**:
1. **Phase 1** attacks round 40 directly (`U40, V40`, 4 real candidates
   after dedup, 16 raw guesses).
2. **Phase 2** attacks round 39, but since a round-39 fault has to
   propagate through the (unfaulted) round 40 before reaching the
   ciphertext, we first *peel round 40 back* (`gift.peel_back_round`)
   using each Phase 1 candidate, then apply the identical ESK-chain leak.
3. The two rounds' recovered key-schedule words are stitched into the full
   8-word key state and the key schedule is inverted back to the master
   key (`gift.key_update_inverse`).
4. All resulting candidates (up to 16 x 16 = 256) are disambiguated with
   one known (plaintext, ciphertext) pair via a direct black-box
   `encrypt()` check — exactly BAKSHEESH's final disambiguation step, just
   over a larger candidate set.

This two-phase "attack-the-last-round-then-peel-back-and-attack-the-one-
before-it" pattern is exactly how real GIFT-128 differential fault attacks
in the literature are structured, and reflects a genuine security
difference between the two ciphers' key-injection schedules — not an
implementation shortcut.

## Key comparison metrics (GIFT-128 vs. BAKSHEESH), as measured by these repos

| Metric | GIFT-128 (this repo) | BAKSHEESH (`../baksheesh_lfa`) |
| --- | --- | --- |
| Rounds | 40 | 35 |
| AddRoundKey width | 64 bits/round (2 bits/nibble) | 128 bits/round (full state) |
| Rounds that must be fault-attacked for full key recovery | 2 (last + second-to-last) | 1 (last only) |
| Residual ambiguity per attacked round | 4-way | 16-way |
| Combined master-key candidates before disambiguation | 256 | 16 |
| Faulty/ineffective observations needed | 62 (31 per round) | 31 |
| Disambiguation | 1 known (plaintext, ciphertext) pair | 1 known (plaintext, ciphertext) pair |
| Key-schedule complexity | Word rotate + reorder (8 x 16-bit words) | Single 1-bit rotation of full 128-bit key |

The practical upshot: GIFT-128's diffusion-plus-narrow-key-injection design
means an attacker needs roughly double the fault-injection queries and a
16x larger candidate-key search compared to BAKSHEESH for full master-key
recovery via this class of attack — even though each individual round leaks
less information per nibble pair. Both ciphers remain fully broken by this
attack class once enough rounds/pairs are covered; the difference is
attack *cost*, not attack *feasibility*.
