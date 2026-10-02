"""
Empirical comparison: how LIFA behaves on BAKSHEESH vs GIFT-128.

Runs the full LIFA pipeline (query the protected device under linked
adjacent-nibble faults until each pair goes ineffective, reconstruct
candidates, disambiguate with one known plaintext/ciphertext pair) against
both ciphers, N independent random-key trials each, and reports:
  - fault-injection queries needed (total / suppressed / ineffective)
  - candidate-key search space before disambiguation
  - success rate
  - wall-clock time per full key recovery
"""

import random
import time
import statistics
import sys, os

BK_PATH = os.environ.get("BAKSHEESH_LFA_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "baksheesh_lfa"))
GIFT_PATH = os.environ.get("GIFT_LFA_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "gift_lfa"))

for _p, _name in [(BK_PATH, "baksheesh_lfa"), (GIFT_PATH, "gift_lfa")]:
    if not os.path.isdir(_p):
        sys.exit(
            f"Couldn't find '{_name}' at {_p}.\n"
            f"Put this script next to both the 'baksheesh_lfa' and 'gift_lfa' folders "
            f"(unzip Baksheesh_LFA.zip and gift_lfa.zip alongside it), or set the "
            f"BAKSHEESH_LFA_PATH / GIFT_LFA_PATH environment variables to their locations."
        )

sys.path.insert(0, BK_PATH)

# --- BAKSHEESH imports ---
from src.baksheesh import encrypt as bk_encrypt, NUM_ROUNDS as BK_ROUNDS
from src.countermeasure import RedundantBaksheeshDevice
from src.lifa_attack import (
    collect_ineffective_ciphertext_and_leak as bk_collect,
    recover_master_key_candidates_lifa as bk_recover,
)

sys.path.remove(BK_PATH)
# purge cached 'src.*' modules so GIFT's own src.* package (different files,
# same package name) gets imported fresh instead of reusing BAKSHEESH's.
for m in list(sys.modules):
    if m == "src" or m.startswith("src."):
        del sys.modules[m]

sys.path.insert(0, GIFT_PATH)

# --- GIFT-128 imports (re-imported fresh from its own src/ package) ---
from src.gift import NUM_ROUNDS as GIFT_ROUNDS
from src.countermeasure import RedundantGiftDevice
from src.lifa_attack import recover_master_key_lifa

N_TRIALS = 8
L = 32  # nibbles


def run_baksheesh_trial(seed):
    random.seed(seed)
    master_key = random.getrandbits(128)
    plaintext_verify = random.getrandbits(128)

    device = RedundantBaksheeshDevice(master_key, num_rounds=BK_ROUNDS)
    correct_ct = device.encrypt_normal(plaintext_verify)

    t0 = time.perf_counter()
    delta_chain = []
    for i in range(L - 1):
        delta, _, _ = bk_collect(device, i, i + 1)
        delta_chain.append(delta)

    candidates = bk_recover(delta_chain, num_rounds=BK_ROUNDS)
    matches = [c for _, c in candidates if bk_encrypt(plaintext_verify, c) == correct_ct]
    elapsed = time.perf_counter() - t0

    success = (len(matches) == 1 and matches[0] == master_key)
    return {
        "success": success,
        "total_queries": device.total_queries,
        "suppressed": device.suppressed_faults,
        "ineffective": device.ineffective_faults,
        "num_candidates": len(candidates),
        "elapsed_sec": elapsed,
    }


def run_gift_trial(seed):
    random.seed(seed)
    master_key = random.getrandbits(128)
    plaintext_verify = random.getrandbits(128)

    device = RedundantGiftDevice(master_key, num_rounds=GIFT_ROUNDS)
    correct_ct = device.encrypt_normal(plaintext_verify)

    t0 = time.perf_counter()
    key, num_candidates = recover_master_key_lifa(device, plaintext_verify, correct_ct, num_rounds=GIFT_ROUNDS)
    elapsed = time.perf_counter() - t0

    success = (key == master_key)
    return {
        "success": success,
        "total_queries": device.total_queries,
        "suppressed": device.suppressed_faults,
        "ineffective": device.ineffective_faults,
        "num_candidates": num_candidates,
        "elapsed_sec": elapsed,
    }


def summarize(results, label):
    n = len(results)
    successes = sum(r["success"] for r in results)
    avg_q = statistics.mean(r["total_queries"] for r in results)
    std_q = statistics.pstdev(r["total_queries"] for r in results)
    min_q = min(r["total_queries"] for r in results)
    max_q = max(r["total_queries"] for r in results)
    avg_ineff = statistics.mean(r["ineffective"] for r in results)
    avg_supp = statistics.mean(r["suppressed"] for r in results)
    avg_time = statistics.mean(r["elapsed_sec"] for r in results)
    candidates = results[0]["num_candidates"]

    print(f"=== {label} ===")
    print(f"  success rate:            {successes}/{n} ({successes/n*100:.0f}%)")
    print(f"  candidate search space:  {candidates}")
    print(f"  total queries: avg={avg_q:.0f}  std={std_q:.0f}  min={min_q}  max={max_q}")
    print(f"  avg ineffective observed:{avg_ineff:.0f}   avg suppressed: {avg_supp:.0f}")
    print(f"  avg wall-clock time:     {avg_time*1000:.1f} ms")
    print()
    return {
        "label": label, "success_rate": successes / n, "candidates": candidates,
        "avg_queries": avg_q, "std_queries": std_q, "avg_time_ms": avg_time * 1000,
    }


def main():
    print(f"Running {N_TRIALS} independent LIFA trials against BAKSHEESH ({BK_ROUNDS} rounds)"
          f" and GIFT-128 ({GIFT_ROUNDS} rounds)...\n")

    bk_results = [run_baksheesh_trial(1000 + t) for t in range(N_TRIALS)]
    gift_results = [run_gift_trial(2000 + t) for t in range(N_TRIALS)]

    bk_summary = summarize(bk_results, "BAKSHEESH (1 attacked round)")
    gift_summary = summarize(gift_results, "GIFT-128 (2 attacked rounds)")

    print("=== Head-to-head ===")
    ratio_q = gift_summary["avg_queries"] / bk_summary["avg_queries"]
    ratio_c = gift_summary["candidates"] / bk_summary["candidates"]
    ratio_t = gift_summary["avg_time_ms"] / bk_summary["avg_time_ms"]
    print(f"  GIFT-128 needs {ratio_q:.1f}x the fault-injection queries of BAKSHEESH")
    print(f"  GIFT-128 leaves {ratio_c:.1f}x the candidate-key search space of BAKSHEESH")
    print(f"  GIFT-128 attack takes {ratio_t:.1f}x the wall-clock time of BAKSHEESH")

    return bk_summary, gift_summary, bk_results, gift_results


if __name__ == "__main__":
    main()
