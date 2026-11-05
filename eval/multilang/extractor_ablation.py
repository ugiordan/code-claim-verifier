#!/usr/bin/env python3
"""Extractor ablation: compare hallucination metrics across extraction LLMs.

The extractor LLM is the model used to parse claims out of reasoning traces.
This script compares results from different extractor choices on the same
reasoning files, analogous to the scaffold effect in coding-agent benchmarks.

Usage:
    # Run verify passes with different extractors first:
    #   python3 -m eval.cybergym.run_pipeline verify \\
    #       --manifest eval/multilang/manifest.jsonl \\
    #       --reasoning-dir eval/multilang/reasoning \\
    #       --output-dir eval/multilang/results_extractor/claude-haiku-4.5 \\
    #       --extraction-llm claude-haiku-4.5
    #
    #   python3 -m eval.cybergym.run_pipeline verify \\
    #       --manifest eval/multilang/manifest.jsonl \\
    #       --reasoning-dir eval/multilang/reasoning \\
    #       --output-dir eval/multilang/results_extractor/granite-3.3-8b \\
    #       --extraction-llm granite-3.3-8b

    python3 eval/multilang/extractor_ablation.py
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from eval.cybergym.utils import load_json

BASELINE_RESULTS_DIR = "eval/multilang/results"
EXTRACTOR_RESULTS_BASE = "eval/multilang/results_extractor"
ANALYSIS_DIR = "eval/multilang/analysis"

# Extractors to compare. Baseline (sonnet) reads from the main results dir.
EXTRACTORS = {
    "claude-sonnet-4": BASELINE_RESULTS_DIR,
    "claude-haiku-4.5": os.path.join(EXTRACTOR_RESULTS_BASE, "claude-haiku-4.5"),
    "granite-3.3-8b": os.path.join(EXTRACTOR_RESULTS_BASE, "granite-3.3-8b"),
}

# Focus on the informed condition of the main generation model for clean comparison
FOCUS_MODEL = "claude-sonnet-4"
FOCUS_CONDITION = "informed"


def load_results(results_dir: str, model: str, condition: str) -> list[dict]:
    path = os.path.join(results_dir, model, condition)
    if not os.path.isdir(path):
        return []
    results = []
    for fname in os.listdir(path):
        if not fname.endswith(".json"):
            continue
        r = load_json(os.path.join(path, fname))
        if r:
            results.append(r)
    return results


def compute_metrics(results: list[dict]) -> dict:
    if not results:
        return {}
    total_claims = sum(r.get("ccv", {}).get("total_claims", 0) for r in results)
    total_refuted = sum(r.get("ccv", {}).get("refuted", 0) for r in results)
    total_verified = sum(r.get("ccv", {}).get("verified", 0) for r in results)
    total_unverifiable = sum(r.get("ccv", {}).get("unverifiable", 0) for r in results)
    zero_claim = sum(1 for r in results if r.get("ccv", {}).get("total_claims", 0) == 0)

    # Per-claim-type breakdown
    by_type: dict[str, dict] = {}
    for r in results:
        for claim in r.get("ccv", {}).get("claims", []):
            ct = claim.get("claim_type", "UNKNOWN")
            verdict = claim.get("verdict", "UNVERIFIABLE")
            if ct not in by_type:
                by_type[ct] = {"total": 0, "verified": 0, "refuted": 0}
            by_type[ct]["total"] += 1
            if verdict == "VERIFIED":
                by_type[ct]["verified"] += 1
            elif verdict == "REFUTED":
                by_type[ct]["refuted"] += 1

    return {
        "samples": len(results),
        "total_claims": total_claims,
        "avg_claims_per_case": round(total_claims / len(results), 2),
        "total_verified": total_verified,
        "total_refuted": total_refuted,
        "total_unverifiable": total_unverifiable,
        "hallucination_rate": round(total_refuted / total_claims, 4) if total_claims > 0 else 0.0,
        "zero_claim_cases": zero_claim,
        "by_claim_type": {
            ct: {
                "total": v["total"],
                "hallucination_rate": round(v["refuted"] / v["total"], 4) if v["total"] > 0 else 0.0,
            }
            for ct, v in sorted(by_type.items())
        },
    }


def main() -> None:
    print(f"Extractor ablation: {FOCUS_MODEL}/{FOCUS_CONDITION}")
    print(f"{'Extractor':<25} {'Samples':>7} {'Claims/case':>11} {'Halluc rate':>12} {'Zero-claim':>10}")
    print("-" * 70)

    all_metrics: dict[str, dict] = {}
    for extractor, results_dir in EXTRACTORS.items():
        results = load_results(results_dir, FOCUS_MODEL, FOCUS_CONDITION)
        if not results:
            print(f"  {extractor:<23} — no results found at {results_dir}")
            continue
        m = compute_metrics(results)
        all_metrics[extractor] = m
        print(f"  {extractor:<23} {m['samples']:>7} {m['avg_claims_per_case']:>11.1f} "
              f"{m['hallucination_rate']:>11.1%} {m['zero_claim_cases']:>10}")

    if len(all_metrics) < 2:
        print("\nNot enough extractor results to compute deltas.")
        return

    baseline = all_metrics.get("claude-sonnet-4", {})
    if not baseline:
        print("\nBaseline (claude-sonnet-4) not found.")
        return

    print("\nDelta vs. claude-sonnet-4 (baseline):")
    print(f"{'Extractor':<25} {'Δ claims/case':>14} {'Δ halluc rate':>14}")
    print("-" * 55)
    for extractor, m in all_metrics.items():
        if extractor == "claude-sonnet-4":
            continue
        delta_claims = m["avg_claims_per_case"] - baseline["avg_claims_per_case"]
        delta_halluc = m["hallucination_rate"] - baseline["hallucination_rate"]
        print(f"  {extractor:<23} {delta_claims:>+13.1f} {delta_halluc:>+13.1%}")

    print("\nPer-claim-type hallucination rate by extractor:")
    all_types = sorted({ct for m in all_metrics.values() for ct in m.get("by_claim_type", {})})
    header = f"{'Claim type':<20}" + "".join(f"{e[:14]:>16}" for e in all_metrics)
    print("  " + header)
    print("  " + "-" * len(header))
    for ct in all_types:
        row = f"  {ct:<20}"
        for m in all_metrics.values():
            rate = m.get("by_claim_type", {}).get(ct, {}).get("hallucination_rate")
            row += f"{rate:>15.1%}" if rate is not None else f"{'—':>15}"
        print(row)

    out_path = os.path.join(ANALYSIS_DIR, "extractor_ablation.json")
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({
            "focus": f"{FOCUS_MODEL}/{FOCUS_CONDITION}",
            "extractors": all_metrics,
        }, f, indent=2)
    print(f"\nSaved to {out_path}")


if __name__ == "__main__":
    main()
