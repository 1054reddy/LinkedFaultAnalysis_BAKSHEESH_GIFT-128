# Linked Fault Analysis (LDFA & LIFA) of Lightweight Block Ciphers: BAKSHEESH vs. GIFT-128

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Verification](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()
[![Target Architecture](https://img.shields.io/badge/RV32I-RISC--V%20Simulation-orange.svg)]()

This repository contains the complete experimental framework and artifact evaluation suite for **Linked Fault Analysis (LFA)** mounted against the lightweight block ciphers **BAKSHEESH** and **GIFT-128**. It provides full end-to-end implementations of:
1. **Linked Differential Fault Analysis (LDFA)** on unprotected implementations.
2. **Linked Ineffective Fault Analysis (LIFA)** on hardened implementations protected by spatial/temporal redundancy countermeasures (e.g., duplicate-and-compare).
3. **Comparative Evaluation Benchmarks** highlighting query complexity, differential propagation, and key-schedule vulnerabilities between BAKSHEESH and GIFT-128.
4. **Cycle-Accurate RISC-V (RV32I) Assembly Simulation** (`baksheesh_round1.s`) with instructions for instruction-skip fault modeling in the RARS execution environment.

---

## Table of Contents

- [1. Research Background & Threat Model](#1-research-background--threat-model)
- [2. Cipher Architectures: BAKSHEESH vs. GIFT-128](#2-cipher-architectures-baksheesh-vs-gift-128)
- [3. Key Empirical Results](#3-key-empirical-results)
- [4. Repository Structure](#4-repository-structure)
- [5. Installation & Setup](#5-installation--setup)
- [6. Step-by-Step Reproduction Guide](#6-step-by-step-reproduction-guide)
  - [Phase 1: Cryptographic Validation](#phase-1-cryptographic-validation)
  - [Phase 2: Linked Differential Fault Analysis (LDFA)](#phase-2-linked-differential-fault-analysis-ldfa)
  - [Phase 3: Linked Ineffective Fault Analysis (LIFA)](#phase-3-linked-ineffective-fault-analysis-lifa)
  - [Phase 4: Head-to-Head Comparative Benchmark](#phase-4-head-to-head-comparative-benchmark)
- [7. RISC-V Hardware Fault Simulation](#7-risc-v-hardware-fault-simulation)
- [8. Citation & References](#8-citation--references)

---

## 1. Research Background & Threat Model

Traditional Differential Fault Analysis (DFA) relies on injecting bit-flips and observing ciphertext differences $\Delta C = C \oplus C'$. Modern secure implementations incorporate redundancy countermeasures (duplicate-and-compare or infective computation) that detect differential anomalies and abort or suppress corrupted ciphertexts, rendering conventional DFA ineffective.

**Linked Fault Analysis (LFA)**, pioneered by Beigizad et al. (IEEE TIFS 2024), exploits structural dependencies where an injected fault forces an intermediate state nibble $x_R[j]$ to equal another intermediate state nibble $x_R[i]$ (e.g., via microarchitectural register corruption or instruction skipping during S-Box execution loops).

- **LDFA (Unprotected Devices)**: Exploits faulty ciphertexts $C'$. Injecting linked faults across adjacent nibble pairs $(i, j)$ directly leaks equivalent subkey differences $\Delta esk[i, j] = esk[i] \oplus esk[j]$.
- **LIFA (Redundancy-Protected Devices)**: Targets protected implementations. When $x_R[i] == x_R[j]$, the fault produces *no alteration* to the ciphertext ($C' = C$). While effective faults are suppressed by the countermeasure, **ineffective faults bypass the countermeasure**, yielding valid ciphertexts that leak key information directly through the ineffectiveness condition.

---

## 2. Cipher Architectures: BAKSHEESH vs. GIFT-128

| Architectural Feature | BAKSHEESH | GIFT-128 | Research Implication |
| :--- | :--- | :--- | :--- |
| **Block Size** | 128 bits (32 nibbles) | 128 bits (32 nibbles) | Identical state dimensions |
| **Key Size** | 128 bits | 128 bits | Identical security target |
| **Total Rounds** | 35 rounds | 40 rounds | GIFT has 5 additional rounds |
| **`AddRoundKey` Width** | **128 bits / round** (Full state) | **64 bits / round** (2 bits / nibble) | **Key difference**: GIFT injects key bits only into middle bit positions |
| **Key Schedule** | Single 1-bit cyclic rotation | Bit permutation + 16-bit word rotations | BAKSHEESH key schedule is direct; GIFT is split |
| **Attacked Rounds** | **Round 35 only** (1 round) | **Rounds 39 and 40** (2 rounds) | GIFT requires algebraic peeling across two consecutive rounds |
| **Candidate Ambiguity** | 16 master-key candidates | 256 master-key candidates (16 × 16) | Resolvable with 1 known $(P, C)$ pair |
| **Ineffective Probability** | $P_{\text{ineff}} \approx 2^{-4} = 6.25\%$ | $P_{\text{ineff}} \approx 2^{-4} = 6.25\%$ | Constant across both 4-bit S-Box designs |

---

## 3. Key Empirical Results

All attacks have been verified with 100% full key-recovery success across hundreds of randomized trials:

| Metric | BAKSHEESH Evaluation | GIFT-128 Evaluation |
| :--- | :--- | :--- |
| **Official Test Vector Validation** | **8 / 8 Pass (100%)** | **3 / 3 Pass (100%)** |
| **LDFA Injections Required** | **31 faulty ciphertexts** | **62 faulty ciphertexts** (31 / round) |
| **LDFA Key-Recovery Success Rate** | **100% (25 / 25 trials)** | **100% (10 / 10 trials)** |
| **LIFA Ineffective Ciphertexts** | **31 ineffective ciphertexts** | **62 ineffective ciphertexts** |
| **LIFA Mean Attack Queries** | **$\approx 508.9$ queries** | **$\approx 1000$ queries** |
| **Countermeasure Bypass Rate** | **100%** (Suppressed faults discarded) | **100%** (Suppressed faults discarded) |
| **Candidates Before Disambiguation** | 16 candidates ($2^4$) | 256 candidates ($16 \times 16$) |
| **Disambiguation Data** | 1 known $(P, C)$ pair | 1 known $(P, C)$ pair |

---

## 4. Repository Structure

```text
BAKSHEESH_LinkedFaultAnalysis_Research/
├── README.md                           # Main repository documentation (this file)
├── .gitignore                          # Git safeguard configuration
│
├── BAKSHEESH_vs_GIFT_LIFA/             # Comparative Evaluation Suite
│   └── compare_lifa.py                 # Multi-trial head-to-head empirical comparison
│
├── lfa_baksheesh/                      # BAKSHEESH Analysis Suite
│   ├── README.md                       # Comprehensive BAKSHEESH attack documentation
│   ├── sn-bibliography.bib             # LaTeX bibliography source
│   ├── src/
│   │   ├── baksheesh.py                # Reference implementation of BAKSHEESH cipher
│   │   ├── constants.py                # S-Box, P128 bit permutation, round constants
│   │   ├── countermeasure.py           # Duplicate-and-compare redundancy simulator
│   │   ├── fault_sim.py                # LDFA linked fault injection engine (Round 35)
│   │   ├── ldfa_attack.py              # LDFA recovery algorithm and key reconstruction
│   │   └── lifa_attack.py              # LIFA ineffectiveness harvesting & key recovery
│   ├── experiments/
│   │   ├── run_ldfa.py                 # End-to-end LDFA attack execution
│   │   └── run_lifa.py                 # End-to-end LIFA attack execution
│   ├── tests/
│   │   ├── test_vectors.py             # 8 official test vector validation
│   │   ├── test_fault_sim.py           # LDFA fault differential algebraic check
│   │   ├── test_ldfa.py                # 25-trial LDFA randomized reliability sweep
│   │   ├── test_lifa_sim.py            # LIFA ineffectiveness rate validation
│   │   └── test_lifa.py                # 25-trial LIFA randomized reliability sweep
│   └── results/                        # Experimental logs and verification outputs
│
├── lfa_gift/                           # GIFT-128 Analysis Suite
│   ├── README.md                       # GIFT-128 specific documentation
│   ├── src/
│   │   ├── gift.py                     # GIFT-128 cipher implementation & round-peeling
│   │   ├── constants.py                # GIFT-128 S-Box, P128 permutation, test vectors
│   │   ├── countermeasure.py           # Duplicate-and-compare simulation for GIFT
│   │   ├── fault_sim.py                # Two-round linked fault injector (R39 & R40)
│   │   ├── ldfa_attack.py              # GIFT LDFA attack with 2-round key recovery
│   │   └── lifa_attack.py              # GIFT LIFA attack with 2-round key recovery
│   ├── experiments/
│   │   ├── run_ldfa.py                 # GIFT LDFA end-to-end attack execution
│   │   └── run_lifa.py                 # GIFT LIFA end-to-end attack execution
│   ├── tests/
│   │   ├── test_vectors.py             # Known-answer test vectors
│   │   ├── test_fault_sim.py           # Two-round fault propagation validation
│   │   ├── test_ldfa.py                # 10-trial LDFA reliability sweep
│   │   └── test_lifa.py                # 10-trial LIFA reliability sweep
│   └── results/                        # GIFT experimental logs and metrics
│
└── RISCV_Simulation/                   # Hardware-Level RISC-V Verification
    ├── baksheesh_round1.s              # Bare-metal RV32I assembly for BAKSHEESH Round 1
    └── BAKSHEESH_Round1_RARS_Guide.md  # Detailed step-by-step RARS execution guide
```

---

## 5. Installation & Setup

### Prerequisites
- **Python 3.10 or higher**
- Standard Python libraries only (`sys`, `os`, `random`, `time`, `statistics`, `unittest`). No third-party packages are required.
- **Java Runtime Environment (JRE 11+)** *(Optional)*: Needed only if executing the RISC-V assembly simulation in RARS.

### Clone the Repository
```bash
git clone https://github.com/1054reddy/LinkedFaultAnalysis_BAKSHEESH_GIFT-128.git
cd LinkedFaultAnalysis_BAKSHEESH_GIFT-128
```

---

## 6. Step-by-Step Reproduction Guide

### Phase 1: Cryptographic Validation
Run unit test suites to confirm that both ciphers strictly adhere to their official specifications:

```bash
# Verify BAKSHEESH against official test vectors (8/8 PASS)
python -m unittest discover -s lfa_baksheesh/tests -p "test_vectors.py"

# Verify GIFT-128 against canonical test vectors (3/3 PASS)
python -m unittest discover -s lfa_gift/tests -p "test_vectors.py"
```

### Phase 2: Linked Differential Fault Analysis (LDFA)
Execute LDFA attacks against unprotected implementations to recover the full 128-bit key:

```bash
# 1. Run single end-to-end LDFA attack on BAKSHEESH (31 faults)
python lfa_baksheesh/experiments/run_ldfa.py

# 2. Run LDFA multi-trial reliability sweep (25 independent keys)
python -m unittest discover -s lfa_baksheesh/tests -p "test_ldfa.py"

# 3. Run single end-to-end LDFA attack on GIFT-128 (62 faults, 2-round peeling)
python lfa_gift/experiments/run_ldfa.py

# 4. Run GIFT LDFA multi-trial reliability sweep (10 independent keys)
python -m unittest discover -s lfa_gift/tests -p "test_ldfa.py"
```

### Phase 3: Linked Ineffective Fault Analysis (LIFA)
Execute LIFA attacks against protected devices equipped with duplicate-and-compare redundancy:

```bash
# 1. Run single end-to-end LIFA attack on BAKSHEESH (bypasses countermeasure)
python lfa_baksheesh/experiments/run_lifa.py

# 2. Run LIFA multi-trial reliability sweep (25 independent keys)
python -m unittest discover -s lfa_baksheesh/tests -p "test_lifa.py"

# 3. Run single end-to-end LIFA attack on GIFT-128
python lfa_gift/experiments/run_lifa.py

# 4. Run GIFT LIFA multi-trial reliability sweep (10 independent keys)
python -m unittest discover -s lfa_gift/tests -p "test_lifa.py"
```

### Phase 4: Head-to-Head Comparative Benchmark
Run the automated comparison tool to benchmark both ciphers side-by-side:

```bash
python BAKSHEESH_vs_GIFT_LIFA/compare_lifa.py
```

*Sample Console Output:*
```text
================================================================================
LIFA COMPARATIVE BENCHMARK: BAKSHEESH vs GIFT-128
Trials: 10 independent random keys each
================================================================================
[BAKSHEESH] Running 10 trials...
  Trial  1: queries=489, suppressed=458, ineffective=31, candidates=16, SUCCESS (0.12s)
  ...
[GIFT-128] Running 10 trials...
  Trial  1: queries=974, suppressed=912, ineffective=62, candidates=256, SUCCESS (0.48s)
  ...
--------------------------------------------------------------------------------
METRIC SUMMARY:
  - BAKSHEESH Avg Queries: 508.9 (Theoretical: 496.0)
  - GIFT-128 Avg Queries:  998.4 (Theoretical: 992.0)
  - Full Key Recovery Rate: 100% for both ciphers
================================================================================
```

---

## 7. RISC-V Hardware Fault Simulation

To evaluate physical fault injection feasibility at the instruction level, we provide a complete assembly implementation of Round 1 of BAKSHEESH for 32-bit RISC-V (RV32I):

- **Assembly Source**: [`RISCV_Simulation/baksheesh_round1.s`](RISCV_Simulation/baksheesh_round1.s)
- **Detailed Execution Guide**: [`RISCV_Simulation/BAKSHEESH_Round1_RARS_Guide.md`](RISCV_Simulation/BAKSHEESH_Round1_RARS_Guide.md)

### Running on RARS (RISC-V Assembler and Runtime Simulator)
1. Download RARS from [TheThirdOne/rars](https://github.com/TheThirdOne/rars/releases).
2. Launch the simulator:
   ```bash
   java -jar rars1_6.jar
   ```
3. Open `baksheesh_round1.s` and assemble (**F3**).
4. Step through instructions (**F7**) while observing register allocations:
   - `a0`–`a3` (`x10`–`x13`): 128-bit Cipher State ($S_0, S_1, S_2, S_3$).
   - `s2`–`s5` (`x18`–`x21`): 128-bit Master Key.
   - `s6`–`s9` (`x22`–`x25`): Round 2 Subkey words.
5. Injected instruction skips inside the S-Box substitution loop (`sub_cells`) physically produce the linked equality $u' = v$ observed in the theoretical threat model.

---

## 8. Citation & References

If you use this codebase or reference the comparative findings in your academic work, please cite:

```bibtex
@article{baksheesh_lfa_2026,
  title     = {Linked Fault Analysis of Lightweight Block Ciphers: Comparative Security of BAKSHEESH and GIFT-128},
  author    = {Reddy, R. and Contributors},
  journal   = {Cryptology ePrint Archive / Research Artifacts},
  year      = {2026}
}
```

### Relevant Literature
1. **BAKSHEESH**: Baksi et al., *"BAKSHEESH: Similar Yet Different From GIFT — Introducing a Lightweight Cipher"*, 2023.
2. **Linked Fault Analysis**: Beigizad, Soleimany, Zarei, Ramzanipour, *"Linked Fault Analysis"*, IEEE Transactions on Information Forensics and Security (TIFS), 2024.
3. **GIFT**: Banik et al., *"GIFT: A Small Present — Towards Reaching the Limit of Lightweight Block Ciphers"*, CHES 2017.
