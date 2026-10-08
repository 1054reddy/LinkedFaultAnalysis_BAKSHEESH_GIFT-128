# BAKSHEESH + Linked Fault Analysis (LDFA & LIFA)

## 1. Project Overview

This project implements the **BAKSHEESH lightweight block cipher** and mounts both **Linked Differential Fault Analysis (LDFA)** and **Linked Ineffective Fault Analysis (LIFA)** on the implementation.

The project is based on two main research papers:

1. **BAKSHEESH: Similar Yet Different From GIFT — Introducing a Lightweight Cipher** (Baksi et al., 2023)
2. **Linked Fault Analysis** (Beigizad, Soleimany, Zarei, Ramzanipour, IEEE TIFS 2024)

The BAKSHEESH paper provides the cipher construction and implementation details, while the Linked Fault Analysis paper provides the fault-analysis methodologies (LDFA in the absence of countermeasures, and LIFA in the presence of redundancy-based countermeasures).

---

## 2. Project Objective

The main objective is:

```text
Implement BAKSHEESH
        ↓
Validate the cipher implementation (8/8 test vectors)
        ↓
Simulate the linked fault in SubCells (round 35)
        ↓
Mount LDFA (31 faulty ciphertexts → full 128-bit key recovery)
        ↓
Implement Duplicate-and-Compare Countermeasure
        ↓
Mount LIFA (31 ineffective ciphertexts → full 128-bit key recovery, bypassing countermeasure)
        ↓
Validate both attacks across multiple random keys (100% success rate)
```

---

## 3. BAKSHEESH Cipher

BAKSHEESH is a lightweight block cipher derived from the design philosophy of GIFT-128.

### Main parameters

* Block size: **128 bits**
* Key size: **128 bits**
* Number of rounds: **35**
* State size: **128 bits**
* State representation: **32 × 4-bit nibbles**
* S-Box size: **4 × 4**

The BAKSHEESH round consists of:

```text
SubCells
    ↓
PermBits
    ↓
AddConstants
    ↓
AddRoundKey
```

The same 4-bit S-Box is applied independently to all 32 nibbles.

### BAKSHEESH S-Box

```text
306DB58ECF924A71
```

---

## 4. Why BAKSHEESH?

BAKSHEESH uses a 4-bit S-Box with **one non-trivial Linear Structure (LS)**.

The BAKSHEESH paper explicitly states that it does **not claim inherent DFA protection**, unlike DEFAULT, which was presented with DFA-protection motivation.

This makes BAKSHEESH an interesting and relevant target for investigating both differential (LDFA) and ineffective (LIFA) linked fault attacks.

---

# 5. Linked Fault Analysis (LFA)

## 5.1 What is LFA?

Traditional fault attacks generally exploit a relationship between a correct computation and a faulty computation.

Linked Fault Analysis introduces a different fault model where a fault changes an intermediate value:

```text
u → u'
```

and the faulty value `u'` is linked to another intermediate value `v`:

```text
u' = l(v)
```

In the instruction-skip fault model targeting the S-Box lookup loop, the equality relation holds:

```text
u' = v
```

---

## 5.2 LDFA vs. LIFA

| Feature | LDFA (Linked Differential) | LIFA (Linked Ineffective) |
| :--- | :--- | :--- |
| **Countermeasure Setting** | Unprotected implementations | Redundancy-based countermeasures (detection/infection) |
| **Ciphertexts Used** | Faulty ciphertexts ($C'$) | Ineffective ciphertexts ($C$) |
| **Effective Faults** | Captured and analyzed | Detected and suppressed by countermeasure |
| **Ineffective Faults** | Ignored / treated as non-event | Key asset: bypasses countermeasure completely |
| **Ineffectiveness Condition** | N/A | $x_R[i] == x_R[j] \iff y_R[i] == y_R[j]$ |
| **Per-Pair Data** | 1 faulty ciphertext | 1 ineffective ciphertext ($\approx 16$ queries on avg) |
| **Total Attack Queries** | 31 queries | $\approx 496$ queries ($31 \times 16$) |
| **Key-Space Reduction** | $2^{128} \to 2^4$ (16 candidates) | $2^{128} \to 2^4$ (16 candidates) |

---

# 6. Project Structure

```text
baksheesh_lfa/
│
├── README.md
│
├── src/
│   ├── __init__.py
│   ├── baksheesh.py           # Core BAKSHEESH cipher implementation
│   ├── constants.py           # S-Box, P128, round constants, test vectors
│   ├── countermeasure.py      # Duplicate-and-compare redundancy simulation
│   ├── fault_sim.py           # LDFA linked-fault simulator (round 35)
│   ├── ldfa_attack.py         # LDFA attack logic (Algorithm 1 + key reconstruction)
│   └── lifa_attack.py         # LIFA attack logic (Ineffective fault harvesting & recovery)
│
├── experiments/
│   ├── run_ldfa.py            # End-to-end LDFA demonstration
│   └── run_lifa.py            # End-to-end LIFA demonstration (against countermeasure)
│
├── tests/
│   ├── test_vectors.py        # Official test vectors validation (8/8)
│   ├── test_fault_sim.py      # LDFA fault-simulation algebraic sanity check
│   ├── test_ldfa.py           # 25-trial LDFA reliability test
│   ├── test_lifa_sim.py       # LIFA algebraic check & ineffectiveness rate test
│   └── test_lifa.py           # 25-trial LIFA reliability test
│
└── results/
    ├── phase1_baksheesh_validation/
    │   ├── result.txt
    │   └── notes.txt
    ├── phase2_fault_simulation/
    │   ├── result.txt
    │   └── notes.txt
    ├── phase3_ldfa/
    │   ├── result.txt
    │   └── notes.txt
    ├── phase4_key_recovery/
    │   ├── result.txt
    │   └── notes.txt
    └── phase5_lifa/
        ├── result.txt
        └── notes.txt
```

---

# 7. Phase 1 — BAKSHEESH Validation

## Test
```bash
python tests/test_vectors.py
```

## Result
**8/8 test vectors passed**. Validates that the integer-based implementation of the round function, key schedule, constants, and whitening is 100% compliant with the official cipher specification.

---

# 8. Phase 2 — LDFA Fault Simulation

## Test
```bash
python tests/test_fault_sim.py
```

## Result
**ALL CHECKS PASSED**. Confirms that the simulated linked fault in round 35 SubCells satisfies:
$$w'[i] \oplus w'[j] = esk[i] \oplus esk[j]$$

---

# 9. Phase 3 — LDFA Key Recovery

## Test
```bash
python experiments/run_ldfa.py
```

## Result
* **Faulty ciphertexts**: 31
* **Key-space reduction**: $2^{128} \to 2^4$ (16 candidates)
* **Disambiguation**: 1 known $(P, C)$ pair uniquely isolates the true 128-bit key.
* **Status**: **PASSED**

---

# 10. Phase 4 — LDFA Reliability Testing

## Test
```bash
python tests/test_ldfa.py
```

## Result
**25/25 random key trials succeeded (100% success rate)**.

---

# 11. Phase 5 — Linked Ineffective Fault Analysis (LIFA)

## 11.1 The Countermeasure & Ineffective Fault Model
A hardware/software **duplicate-and-compare redundancy countermeasure** is modeled in `src/countermeasure.py`.
* When a linked fault $y'_R[j] = S(x_R[i])$ is injected:
  * **Effective Fault ($x_R[i] \neq x_R[j]$)**: The output differs from the redundant computation. The countermeasure detects the mismatch and **suppresses** the ciphertext (returns `None`).
  * **Ineffective Fault ($x_R[i] == x_R[j]$)**: Because $S$ is bijective, $y_R[i] == y_R[j]$, meaning the fault causes zero modification. The countermeasure is bypassed and the device emits the valid ciphertext $C$.

## 11.2 Ineffective Leakage Algebra
From the emitted ineffective ciphertext $C$:
$$w = \text{PermBits}^{-1}(C \oplus \text{AddConstants}) = y_R \oplus esk_R$$
$$w[i] \oplus w[j] = (y_R[i] \oplus esk_R[i]) \oplus (y_R[j] \oplus esk_R[j]) = (y_R[i] \oplus y_R[j]) \oplus (esk_R[i] \oplus esk_R[j])$$
Because the fault was ineffective, $y_R[i] == y_R[j]$, so $y_R[i] \oplus y_R[j] = 0$:
$$w[i] \oplus w[j] = esk_R[i] \oplus esk_R[j] = \Delta esk_R[i, j]$$

## 11.3 Demonstration & Reliability
Run the demonstration:
```bash
python experiments/run_lifa.py
```
Run the 25-trial test:
```bash
python tests/test_lifa.py
```

### Measured Performance:
* **Ineffectiveness rate**: $\approx 6.10\%$ (theoretical $2^{-4} = 6.25\%$)
* **Ineffective ciphertexts needed**: 31 (1 per adjacent pair)
* **Average queries per key**: $508.9$ (theoretical expectation $31 \times 16 = 496$)
* **Key-space reduction**: $2^{128} \to 2^4$ (16 candidates)
* **25-trial success rate**: **25/25 (100%)**

---

# 12. Complete Results Summary

| Phase | Experiment | Objective | Verified Outcome |
| :--- | :--- | :--- | :--- |
| **Phase 1** | `tests/test_vectors.py` | Official test vectors | **8/8 PASS** |
| **Phase 2** | `tests/test_fault_sim.py` | LDFA fault algebra | **4/4 PASS** |
| **Phase 3** | `experiments/run_ldfa.py` | 31-fault LDFA run | **Exact Key Recovered** |
| **Phase 4** | `tests/test_ldfa.py` | LDFA multi-key reliability | **25/25 PASS (100%)** |
| **Phase 5a** | `tests/test_lifa_sim.py` | LIFA countermeasure & algebra | **ALL CHECKS PASS** |
| **Phase 5b** | `experiments/run_lifa.py` | End-to-end LIFA attack | **Countermeasure Bypassed** |
| **Phase 5c** | `tests/test_lifa.py` | LIFA multi-key reliability | **25/25 PASS (100%)** |

---

# 13. Reproducing All Experiments

From the project root:

```bash
# 1. Validate cipher
python tests/test_vectors.py

# 2. Validate LDFA fault simulation
python tests/test_fault_sim.py

# 3. Run LDFA single attack demo
python experiments/run_ldfa.py

# 4. Run LDFA 25-trial test
python tests/test_ldfa.py

# 5. Validate LIFA simulation & countermeasure
python tests/test_lifa_sim.py

# 6. Run LIFA single attack demo
python experiments/run_lifa.py

# 7. Run LIFA 25-trial test
python tests/test_lifa.py
```
