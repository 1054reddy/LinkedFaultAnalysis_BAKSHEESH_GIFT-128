# BAKSHEESH & GIFT Fault Analysis Framework

This repository provides an evaluation framework for assessing the security of lightweight block ciphers—specifically **BAKSHEESH** and **GIFT**—against advanced fault analysis techniques. It accompanies research investigating Linkage Fault Analysis (LFA), Linkage Differential Fault Analysis (LDFA), and Linkage Ineffective Fault Analysis (LIFA).

---

## Repository Structure

* `baksheesh_lfa/`

  * `src/`: Core cryptographic implementations, fault simulation logic, and attack scripts (`ldfa_attack.py`, `lifa_attack.py`).
  * `experiments/`: Out-of-the-box runner scripts (`run_ldfa.py`, `run_lifa.py`) to execute evaluations.
  * `tests/`: Unit test suite verifying cipher correctness and fault mechanisms.

* `gift_lfa/`

  * `src/`: Core logic, fault simulators, and attack scripts for GIFT.
  * `experiments/`: Execution scripts for LDFA and LIFA simulations on GIFT.
  * `tests/`: Verification unit tests.

* `BAKSHEESH_vs_GIFT_LIFA/`

  * Comparative evaluation scripts (`compare_lifa.py`) measuring cost and efficiency differences between both ciphers.

* `RISCV_Simulation/`

  * Hardware-level verification files, including assembly implementations (`baksheesh_round1.s`) and the RARS execution guide (`BAKSHEESH_Round1_RARS_Guide.md`).

---

## Prerequisites & Requirements

* **Python 3.12+**
* **RARS** (RISC-V Assembler and Runtime Simulator) if you plan to run the hardware-level assembly simulations.

---

## Running Unit Tests

To verify that all cryptographic modules, fault simulators, and attack vectors are functioning correctly on your machine, run the test suites:

```bash
python -m unittest discover -s baksheesh_lfa/tests
python -m unittest discover -s gift_lfa/tests
```

## 2. Executing Attack Experiments

You can run individual simulation pipelines using the scripts provided inside the experiment directories:

* **Run LDFA on BAKSHEESH:**

```bash
cd baksheesh_lfa/experiments
python run_ldfa.py
```

* **Run LIFA on GIFT:**

```bash
cd gift_lfa/experiments
python run_lifa.py
```

## 3. RISC-V Simulation

For details on running the BAKSHEESH Round 1 implementation on simulated hardware, check out the documentation provided in `RISCV_Simulation/BAKSHEESH_Round1_RARS_Guide.md`.
