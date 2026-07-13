#!/usr/bin/env python3
"""Finish remaining models + re-verify Llama. Use with nohup."""
from __future__ import annotations

import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from eval.cybergym.utils import load_jsonl
from eval.cybergym.generate import generate_one
from eval.cybergym.verify import verify_one

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")

MANIFEST = "eval/cybergym/manifest.jsonl"
REASONING_DIR = "eval/cybergym/reasoning"
RESULTS_DIR = "eval/cybergym/results"
EXTRACTION_LLM = "claude-sonnet-4"


def run_model(model, manifest, force_reverify=False):
    s, sk, f = 0, 0, 0
    start = time.time()
    for i, entry in enumerate(manifest):
        vid = entry["vuln_id"]
        vpath = f"{RESULTS_DIR}/{model}/informed/{vid}.json"
        if os.path.isfile(vpath) and not force_reverify:
            sk += 1
            continue
        if force_reverify and os.path.isfile(vpath):
            os.unlink(vpath)
        rpath = f"{REASONING_DIR}/{model}/informed/{vid}.json"
        if not os.path.isfile(rpath):
            gen = generate_one(entry, model, "informed", REASONING_DIR)
            if not gen:
                f += 1
                continue
        ver = verify_one(entry, rpath, RESULTS_DIR, extraction_llm=EXTRACTION_LLM)
        if ver:
            s += 1
        else:
            f += 1
        done = s + sk + f
        if done % 50 == 0:
            print(f"  {model}: {done}/{len(manifest)}", flush=True)
    elapsed = (time.time() - start) / 60
    print(f"=== {model}: {s} new, {sk} cached, {f} failed [{elapsed:.1f}m] ===", flush=True)


manifest = load_jsonl(MANIFEST)
print(f"Manifest: {len(manifest)} repos", flush=True)

# Step 1: Finish Qwen and GPT-OSS
for model in ["qwen3-14b", "gpt-oss-20b"]:
    existing = len(os.listdir(f"{RESULTS_DIR}/{model}/informed/")) if os.path.isdir(f"{RESULTS_DIR}/{model}/informed/") else 0
    if existing >= len(manifest):
        print(f"{model}: already complete", flush=True)
        continue
    print(f"\n{model}: {existing}/{len(manifest)} done, resuming...", flush=True)
    run_model(model, manifest)

# Step 2: Re-verify Llama (import vs module fix)
print(f"\nRe-verifying llama-3.3-70b with import/module fix...", flush=True)
run_model("llama-3.3-70b", manifest, force_reverify=True)

print("\nAll done!", flush=True)
