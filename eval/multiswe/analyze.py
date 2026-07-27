#!/usr/bin/env python3
"""Analyze Multi-SWE-bench CCV results.

Usage:
    python eval/multiswe/analyze.py
"""
from __future__ import annotations

import json
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

RESULTS_DIR = "eval/multiswe/results"
MANIFEST = "eval/multiswe/manifest.jsonl"


def main():
    manifest = {}
    if os.path.isfile(MANIFEST):
        with open(MANIFEST) as f:
            for line in f:
                entry = json.loads(line)
                manifest[entry["vuln_id"]] = entry

    models = sorted([d for d in os.listdir(RESULTS_DIR)
                     if os.path.isdir(os.path.join(RESULTS_DIR, d))])

    if not models:
        print("No results found")
        return

    print(f"\n{'Model':<22} {'Repos':>5} {'Claims':>6} {'V':>5} {'R':>5} {'U':>5} {'Hall%':>6}")
    print("-" * 60)

    grand_v = grand_r = grand_u = grand_total = 0

    for model in models:
        files = glob.glob(f"{RESULTS_DIR}/{model}/informed/*.json")
        v = r = u = total = 0
        for fpath in files:
            with open(fpath) as f:
                data = json.load(f)
            ccv = data.get("ccv", {})
            v += ccv.get("verified", 0)
            r += ccv.get("refuted", 0)
            u += ccv.get("unverifiable", 0)
            total += ccv.get("total_claims", 0)

        denom = v + r
        hall = (r / denom * 100) if denom > 0 else 0
        print(f"{model:<22} {len(files):>5} {total:>6} {v:>5} {r:>5} {u:>5} {hall:>5.1f}%")
        grand_v += v; grand_r += r; grand_u += u; grand_total += total

    denom = grand_v + grand_r
    hall = (grand_r / denom * 100) if denom > 0 else 0
    print("-" * 60)
    print(f"{'TOTAL':<22} {'':>5} {grand_total:>6} {grand_v:>5} {grand_r:>5} {grand_u:>5} {hall:>5.1f}%")

    # Per-language breakdown
    print(f"\n\n{'Language':<15} {'Claims':>6} {'V':>5} {'R':>5} {'U':>5} {'Hall%':>6}")
    print("-" * 50)

    lang_stats: dict[str, dict] = {}
    for model in models:
        for fpath in glob.glob(f"{RESULTS_DIR}/{model}/informed/*.json"):
            with open(fpath) as f:
                data = json.load(f)
            vid = data.get("vuln_id", os.path.basename(fpath).replace(".json", ""))
            lang = manifest.get(vid, {}).get("language", "unknown")
            ccv = data.get("ccv", {})
            s = lang_stats.setdefault(lang, {"v": 0, "r": 0, "u": 0, "total": 0})
            s["v"] += ccv.get("verified", 0)
            s["r"] += ccv.get("refuted", 0)
            s["u"] += ccv.get("unverifiable", 0)
            s["total"] += ccv.get("total_claims", 0)

    for lang in sorted(lang_stats):
        s = lang_stats[lang]
        denom = s["v"] + s["r"]
        hall = (s["r"] / denom * 100) if denom > 0 else 0
        print(f"{lang:<15} {s['total']:>6} {s['v']:>5} {s['r']:>5} {s['u']:>5} {hall:>5.1f}%")

    # Per-claim-type breakdown
    print(f"\n\n{'Claim Type':<25} {'Count':>6} {'Refute%':>7}")
    print("-" * 45)

    type_stats: dict[str, dict] = {}
    for model in models:
        for fpath in glob.glob(f"{RESULTS_DIR}/{model}/informed/*.json"):
            with open(fpath) as f:
                data = json.load(f)
            for c in data.get("ccv", {}).get("claims", []):
                ct = c.get("claim_type", "?")
                v = c.get("verdict", "?")
                s = type_stats.setdefault(ct, {"v": 0, "r": 0, "u": 0})
                if v == "VERIFIED": s["v"] += 1
                elif v == "REFUTED": s["r"] += 1
                else: s["u"] += 1

    for ct in sorted(type_stats, key=lambda x: type_stats[x]["v"] + type_stats[x]["r"], reverse=True):
        s = type_stats[ct]
        total = s["v"] + s["r"] + s["u"]
        denom = s["v"] + s["r"]
        ref = (s["r"] / denom * 100) if denom > 0 else 0
        print(f"{ct:<25} {total:>6} {ref:>6.1f}%")


if __name__ == "__main__":
    main()
