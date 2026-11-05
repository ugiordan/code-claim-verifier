#!/usr/bin/env python3
"""Generate missing reasoning files for Qwen3 and GPT-OSS. Use with nohup.

Uses the existing generate_one() which handles idempotent resume.
The thinking-model fix in models.py handles the 'reasoning' field
that Qwen3 and GPT-OSS use instead of 'content'.
"""
from __future__ import annotations

import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from eval.cybergym.utils import load_jsonl
from eval.cybergym.generate import generate_one

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")

MANIFEST = "eval/cybergym/manifest.jsonl"
REASONING_DIR = "eval/cybergym/reasoning"
MODELS = ["qwen3-14b", "gpt-oss-20b"]


def main():
    manifest = load_jsonl(MANIFEST)
    print(f"Manifest: {len(manifest)} repos", flush=True)

    start = time.time()
    for model_name in MODELS:
        missing = []
        for entry in manifest:
            vid = entry["vuln_id"]
            rpath = f"{REASONING_DIR}/{model_name}/informed/{vid}.json"
            if not os.path.isfile(rpath):
                missing.append(entry)

        print(f"\n{model_name}: {len(missing)} missing repos", flush=True)
        if not missing:
            continue

        ok, fail = 0, 0
        for i, entry in enumerate(missing):
            result = generate_one(entry, model_name, "informed", REASONING_DIR)
            if result:
                ok += 1
            else:
                fail += 1
                print(f"  FAIL {entry['vuln_id']}", flush=True)

            if (i + 1) % 10 == 0:
                elapsed = (time.time() - start) / 60
                print(f"  {model_name}: {i+1}/{len(missing)} [{elapsed:.0f}m]", flush=True)

        elapsed = (time.time() - start) / 60
        print(f"=== {model_name}: {ok} ok, {fail} failed [{elapsed:.1f}m] ===", flush=True)

    print(f"\nTotal: {(time.time()-start)/60:.1f} minutes", flush=True)


if __name__ == "__main__":
    main()
