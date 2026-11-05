#!/usr/bin/env python3
"""Re-verify repos that got 0 claims (extraction likely failed transiently)."""
from __future__ import annotations

import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from eval.cybergym.utils import load_jsonl
from eval.cybergym.verify import verify_one

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")

MANIFEST = "eval/cybergym/manifest.jsonl"
REASONING_DIR = "eval/cybergym/reasoning"
RESULTS_DIR = "eval/cybergym/results"
EXTRACTION_LLM = "claude-sonnet-4"


def main():
    manifest = load_jsonl(MANIFEST)
    manifest_by_id = {e["vuln_id"]: e for e in manifest}

    zeros = []
    for model in ["granite-3.3-8b", "llama-3.3-70b", "qwen3-14b", "mistral-7b",
                   "gpt-oss-20b", "claude-sonnet-4", "claude-haiku-4.5"]:
        model_dir = f"{RESULTS_DIR}/{model}/informed"
        if not os.path.isdir(model_dir):
            continue
        for fname in sorted(os.listdir(model_dir)):
            if not fname.endswith(".json"):
                continue
            with open(f"{model_dir}/{fname}") as f:
                data = json.load(f)
            if data.get("ccv", {}).get("total_claims", 0) == 0:
                vid = fname.replace(".json", "")
                zeros.append((model, vid))

    print(f"Found {len(zeros)} zero-claim pairs to re-verify", flush=True)
    if not zeros:
        return

    start = time.time()
    fixed = 0
    still_zero = 0

    for i, (model, vid) in enumerate(zeros):
        entry = manifest_by_id.get(vid)
        if not entry:
            print(f"  SKIP {model}/{vid}: not in manifest", flush=True)
            continue

        rpath = f"{REASONING_DIR}/{model}/informed/{vid}.json"
        if not os.path.isfile(rpath):
            print(f"  SKIP {model}/{vid}: no reasoning file", flush=True)
            continue

        result_path = f"{RESULTS_DIR}/{model}/informed/{vid}.json"
        if os.path.isfile(result_path):
            os.remove(result_path)

        result = verify_one(entry, rpath, RESULTS_DIR, extraction_llm=EXTRACTION_LLM)
        if result:
            n = result.get("ccv", {}).get("total_claims", 0)
            if n > 0:
                fixed += 1
                print(f"  FIXED {model}/{vid}: {n} claims", flush=True)
            else:
                still_zero += 1
                print(f"  STILL 0 {model}/{vid}", flush=True)
        else:
            still_zero += 1
            print(f"  FAIL {model}/{vid}", flush=True)

    elapsed = (time.time() - start) / 60
    print(f"\nDone in {elapsed:.1f}m: {fixed} fixed, {still_zero} still zero", flush=True)


if __name__ == "__main__":
    main()
