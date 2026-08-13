#!/usr/bin/env python3
"""Analyze scaffold hallucination effect using CCV results.

Produces:
1. Per harness-model pair: hallucination rate, claim count, claim-type distribution
2. Per harness (pooled): hallucination fingerprint
3. VERIFY failure decomposition
4. Cross-benchmark comparison with CyberGym/Multi-SWE data

Usage:
    python eval/scaffold/analyze.py
"""
from __future__ import annotations

import json
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

SCAFFOLD_RESULTS = "eval/scaffold/results"
CYBERGYM_RESULTS = "eval/cybergym/results"
MULTISWE_RESULTS = "eval/multiswe/results"


def load_results(results_dir: str) -> list[dict]:
    results = []
    for fpath in glob.glob(f"{results_dir}/*/*/*.json"):
        with open(fpath) as f:
            results.append(json.load(f))
    return results


def analyze_scaffold():
    results = load_results(SCAFFOLD_RESULTS)
    if not results:
        print("No scaffold results found. Run verify_trials.py first.")
        return

    print(f"\n{'='*70}")
    print("SCAFFOLD HALLUCINATION ANALYSIS")
    print(f"{'='*70}\n")

    # 1. Per harness-model pair
    print(f"{'Harness':<18} {'Model':<20} {'Trials':>6} {'Claims':>6} {'V':>5} {'R':>5} {'U':>5} {'Hall%':>6} {'Solved':>6}")
    print("-" * 85)

    pairs = {}
    for r in results:
        key = (r.get("harness", ""), r.get("model", "").split("/")[-1])
        pairs.setdefault(key, []).append(r)

    grand_v = grand_r = grand_u = 0
    for (harness, model), rs in sorted(pairs.items()):
        v = sum(r["ccv"]["verified"] for r in rs)
        ref = sum(r["ccv"]["refuted"] for r in rs)
        u = sum(r["ccv"]["unverifiable"] for r in rs)
        total = sum(r["ccv"]["total_claims"] for r in rs)
        solved = sum(1 for r in rs if r.get("solved"))
        denom = v + ref
        hall = (ref / denom * 100) if denom > 0 else 0
        print(f"{harness:<18} {model:<20} {len(rs):>6} {total:>6} {v:>5} {ref:>5} {u:>5} {hall:>5.1f}% {solved:>6}")
        grand_v += v; grand_r += ref; grand_u += u

    denom = grand_v + grand_r
    hall = (grand_r / denom * 100) if denom > 0 else 0
    print(f"\n{'TOTAL':<40} {len(results):>6} {grand_v+grand_r+grand_u:>6} {grand_v:>5} {grand_r:>5} {grand_u:>5} {hall:>5.1f}%")

    # 2. Per harness (pooled across models)
    print(f"\n\n{'Harness':<18} {'Claims':>6} {'V':>5} {'R':>5} {'Hall%':>6}")
    print("-" * 45)

    by_harness = {}
    for r in results:
        h = r.get("harness", "")
        s = by_harness.setdefault(h, {"v": 0, "r": 0, "u": 0})
        s["v"] += r["ccv"]["verified"]
        s["r"] += r["ccv"]["refuted"]
        s["u"] += r["ccv"]["unverifiable"]

    for h in sorted(by_harness):
        s = by_harness[h]
        d = s["v"] + s["r"]
        hall = (s["r"] / d * 100) if d > 0 else 0
        print(f"{h:<18} {s['v']+s['r']+s['u']:>6} {s['v']:>5} {s['r']:>5} {hall:>5.1f}%")

    # 3. Per-claim-type hallucination fingerprint by harness
    print(f"\n\nClaim-type hallucination fingerprint (refute % per harness):")
    print(f"{'Harness':<18} {'FILE_EX':>7} {'FUNC_EX':>8} {'LINE_C':>7} {'IMPORT':>7} {'FUNC_CA':>8} {'ABSENCE':>8}")
    print("-" * 70)

    for harness in sorted(by_harness):
        type_v = {}; type_r = {}
        for r in results:
            if r.get("harness") != harness:
                continue
            for c in r["ccv"].get("claims", []):
                ct = c["claim_type"]
                if c["verdict"] == "VERIFIED": type_v[ct] = type_v.get(ct, 0) + 1
                elif c["verdict"] == "REFUTED": type_r[ct] = type_r.get(ct, 0) + 1
        parts = []
        for ct in ["FILE_EXISTS", "FUNCTION_EXISTS", "LINE_CONTENT", "IMPORT_EXISTS", "FUNCTION_CALLED", "ABSENCE"]:
            tv = type_v.get(ct, 0); tr = type_r.get(ct, 0)
            d = tv + tr
            ref = (tr / d * 100) if d > 0 else 0
            parts.append(f"{ref:>6.1f}%")
        print(f"{harness:<18} {' '.join(parts)}")

    # 4. VERIFY failure decomposition
    print(f"\n\nVERIFY failure decomposition (agent said done, tests failed):")
    print(f"{'Harness':<18} {'VERIFY trials':>13} {'Avg claims':>10} {'Avg hall%':>9}")
    print("-" * 55)

    for harness in sorted(by_harness):
        verify_trials = [r for r in results if r.get("harness") == harness
                         and r.get("failure_category") == "VERIFY"]
        if not verify_trials:
            print(f"{harness:<18} {'0':>13}")
            continue
        avg_claims = sum(r["ccv"]["total_claims"] for r in verify_trials) / len(verify_trials)
        halls = []
        for r in verify_trials:
            v = r["ccv"]["verified"]; ref = r["ccv"]["refuted"]
            d = v + ref
            if d > 0:
                halls.append(ref / d * 100)
        avg_hall = sum(halls) / len(halls) if halls else 0
        print(f"{harness:<18} {len(verify_trials):>13} {avg_claims:>10.1f} {avg_hall:>8.1f}%")

    # 5. Solved vs failed hallucination comparison
    print(f"\n\nSolved vs failed hallucination rate:")
    print(f"{'Harness':<18} {'Solved hall%':>12} {'Failed hall%':>12} {'Delta':>7}")
    print("-" * 55)

    for harness in sorted(by_harness):
        for status, label in [(True, "solved"), (False, "failed")]:
            subset = [r for r in results if r.get("harness") == harness and r.get("solved") == status]
            v = sum(r["ccv"]["verified"] for r in subset)
            ref = sum(r["ccv"]["refuted"] for r in subset)
            d = v + ref
            if status:
                solved_hall = (ref / d * 100) if d > 0 else 0
            else:
                failed_hall = (ref / d * 100) if d > 0 else 0
        delta = failed_hall - solved_hall
        print(f"{harness:<18} {solved_hall:>11.1f}% {failed_hall:>11.1f}% {delta:>+6.1f}%")


def main():
    analyze_scaffold()


if __name__ == "__main__":
    main()
