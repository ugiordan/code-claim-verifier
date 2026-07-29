#!/usr/bin/env python3
"""Run Multi-SWE-bench eval across multiple models. Use with nohup."""
from __future__ import annotations

import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from eval.cybergym.utils import load_jsonl
from eval.multiswe.run_eval import generate_reasoning, REASONING_DIR, RESULTS_DIR, EXTRACTION_LLM
from eval.cybergym.verify import verify_one

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")

MANIFEST = "eval/multiswe/manifest-full.jsonl"
MODELS = ["qwen3-14b", "mistral-7b", "gpt-oss-20b"]


def main():
    manifest = load_jsonl(MANIFEST)
    print(f"Manifest: {len(manifest)} instances, Models: {len(MODELS)}", flush=True)

    start = time.time()
    for model_name in MODELS:
        ok, fail = 0, 0
        for i, entry in enumerate(manifest):
            vid = entry["vuln_id"]

            reasoning_result = generate_reasoning(entry, model_name)
            if not reasoning_result:
                fail += 1
                continue

            reasoning_path = os.path.join(REASONING_DIR, model_name, "informed", f"{vid}.json")
            result_path = os.path.join(RESULTS_DIR, model_name, "informed", f"{vid}.json")

            if os.path.isfile(result_path):
                ok += 1
            else:
                result = verify_one(entry, reasoning_path, RESULTS_DIR, extraction_llm=EXTRACTION_LLM)
                if result and result.get("ccv", {}).get("total_claims", 0) > 0:
                    ok += 1
                else:
                    fail += 1

            if (i + 1) % 50 == 0:
                elapsed = (time.time() - start) / 60
                print(f"  {model_name}: {i+1}/{len(manifest)} [{elapsed:.0f}m]", flush=True)

        elapsed = (time.time() - start) / 60
        print(f"=== {model_name}: {ok} ok, {fail} failed [{elapsed:.1f}m] ===", flush=True)

    print(f"\nTotal: {(time.time()-start)/60:.1f} minutes", flush=True)


if __name__ == "__main__":
    main()
