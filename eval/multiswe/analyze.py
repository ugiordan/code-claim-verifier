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
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from eval.provenance import git_head, git_is_clean, is_immutable_revision, snapshot_digest

RESULTS_DIR = "eval/multiswe/results"
MANIFEST = "eval/multiswe/manifest-full.jsonl"


def _is_provenance_valid(
    data: dict,
    manifest: dict,
    digest_cache: dict[str, str] | None = None,
    clean_cache: dict[str, bool] | None = None,
    head_cache: dict[str, str | None] | None = None,
) -> bool:
    entry = manifest.get(data.get("vuln_id"))
    provenance = data.get("provenance", {})
    if not entry or not provenance:
        return False
    if provenance.get("include_patch_files"):
        return False
    if entry.get("manifest_schema") != 2:
        return False
    if not is_immutable_revision(entry.get("dataset_revision")):
        return False
    if entry.get("ground_truth_validation") != "independent":
        return False
    expected = entry.get("base_sha", "")
    actual = provenance.get("source_head", "")
    if not (expected and actual and actual.startswith(expected[:12])):
        return False
    if provenance.get("source_digest") != entry.get("source_digest"):
        return False
    root = entry.get("source_root", "")
    if digest_cache is None:
        digest_cache = {}
    if clean_cache is None:
        clean_cache = {}
    if head_cache is None:
        head_cache = {}
    if root not in head_cache:
        head_cache[root] = git_head(root)
    if head_cache[root] != actual or root not in clean_cache:
        clean_cache[root] = git_is_clean(root)
    if head_cache[root] != actual or not clean_cache[root]:
        return False
    if root not in digest_cache:
        digest_cache[root] = snapshot_digest(root)
    if digest_cache[root] != entry.get("source_digest"):
        return False
    required = ("provider", "resolved_model", "max_tokens", "temperature", "config_version")
    return all(key in provenance for key in required)


def main(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", default=RESULTS_DIR)
    parser.add_argument("--manifest", default=MANIFEST)
    parser.add_argument(
        "--allow-unprovenanced",
        action="store_true",
        help="Include legacy results for exploratory analysis only",
    )
    args = parser.parse_args(argv)
    digest_cache: dict[str, str] = {}
    clean_cache: dict[str, bool] = {}
    head_cache: dict[str, str | None] = {}

    manifest = {}
    if os.path.isfile(args.manifest):
        with open(args.manifest) as f:
            for line in f:
                entry = json.loads(line)
                manifest[entry["vuln_id"]] = entry

    models = sorted([d for d in os.listdir(args.results_dir)
                     if os.path.isdir(os.path.join(args.results_dir, d))])

    if not models:
        print("No results found")
        return

    print(f"\n{'Model':<22} {'Repos':>5} {'Claims':>6} {'V':>5} {'R':>5} {'U':>5} {'Refute%':>7}")
    print("-" * 60)

    grand_v = grand_r = grand_u = grand_total = 0

    skipped_invalid = 0
    for model in models:
        files = glob.glob(f"{args.results_dir}/{model}/informed/*.json")
        v = r = u = total = 0
        valid_files = []
        for fpath in files:
            with open(fpath) as f:
                data = json.load(f)
            if not args.allow_unprovenanced and not _is_provenance_valid(
                data, manifest, digest_cache, clean_cache, head_cache,
            ):
                skipped_invalid += 1
                continue
            valid_files.append(fpath)
            ccv = data.get("ccv", {})
            v += ccv.get("verified", 0)
            r += ccv.get("refuted", 0)
            u += ccv.get("unverifiable", 0)
            total += ccv.get("total_claims", 0)

        denom = v + r
        hall = (r / denom * 100) if denom > 0 else 0
        print(f"{model:<22} {len(valid_files):>5} {total:>6} {v:>5} {r:>5} {u:>5} {hall:>5.1f}%")
        grand_v += v
        grand_r += r
        grand_u += u
        grand_total += total

    denom = grand_v + grand_r
    hall = (grand_r / denom * 100) if denom > 0 else 0
    print("-" * 60)
    print(f"{'TOTAL':<22} {'':>5} {grand_total:>6} {grand_v:>5} {grand_r:>5} {grand_u:>5} {hall:>5.1f}%")
    print(f"Skipped invalid or unprovenanced result files: {skipped_invalid}")

    # Per-language breakdown
    print(f"\n\n{'Language':<15} {'Claims':>6} {'V':>5} {'R':>5} {'U':>5} {'Refute%':>7}")
    print("-" * 50)

    lang_stats: dict[str, dict] = {}
    for model in models:
        for fpath in glob.glob(f"{args.results_dir}/{model}/informed/*.json"):
            with open(fpath) as f:
                data = json.load(f)
            if not args.allow_unprovenanced and not _is_provenance_valid(
                data, manifest, digest_cache, clean_cache, head_cache,
            ):
                continue
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
        for fpath in glob.glob(f"{args.results_dir}/{model}/informed/*.json"):
            with open(fpath) as f:
                data = json.load(f)
            if not args.allow_unprovenanced and not _is_provenance_valid(
                data, manifest, digest_cache, clean_cache, head_cache,
            ):
                continue
            for c in data.get("ccv", {}).get("claims", []):
                ct = c.get("claim_type", "?")
                v = c.get("verdict", "?")
                s = type_stats.setdefault(ct, {"v": 0, "r": 0, "u": 0})
                if v == "VERIFIED":
                    s["v"] += 1
                elif v == "REFUTED":
                    s["r"] += 1
                else:
                    s["u"] += 1

    for ct in sorted(type_stats, key=lambda x: type_stats[x]["v"] + type_stats[x]["r"], reverse=True):
        s = type_stats[ct]
        total = s["v"] + s["r"] + s["u"]
        denom = s["v"] + s["r"]
        ref = (s["r"] / denom * 100) if denom > 0 else 0
        print(f"{ct:<25} {total:>6} {ref:>6.1f}%")


if __name__ == "__main__":
    main()
