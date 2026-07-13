#!/usr/bin/env python3
"""Run all remaining models to completion. Use with nohup."""
from __future__ import annotations

import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from eval.cybergym.utils import load_jsonl
from eval.cybergym.generate import generate_one
from eval.cybergym.verify import verify_one

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")
logger = logging.getLogger(__name__)

MODELS = ["qwen3-14b", "mistral-7b", "gpt-oss-20b", "claude-sonnet-4", "claude-haiku-4.5"]
MANIFEST = "eval/cybergym/manifest.jsonl"
REASONING_DIR = "eval/cybergym/reasoning"
RESULTS_DIR = "eval/cybergym/results"
EXTRACTION_LLM = "claude-sonnet-4"


def run_model(model: str, manifest: list[dict]) -> None:
    s, sk, f = 0, 0, 0
    total = len(manifest)
    start = time.time()

    for i, entry in enumerate(manifest):
        vid = entry["vuln_id"]
        vpath = f"{RESULTS_DIR}/{model}/informed/{vid}.json"
        if os.path.isfile(vpath):
            sk += 1
            continue

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
        if done % 25 == 0:
            elapsed = time.time() - start
            rate = done / elapsed if elapsed > 0 else 0
            eta = (total - done) / rate / 60 if rate > 0 else 0
            print(f"  {model}: {done}/{total} ({s} new, {sk} cached, {f} failed) ETA: {eta:.0f}m")

    elapsed = (time.time() - start) / 60
    print(f"=== {model}: DONE ({s} new, {sk} cached, {f} failed) [{elapsed:.1f}m] ===")


def main():
    os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    manifest = load_jsonl(MANIFEST)
    print(f"Manifest: {len(manifest)} repos")
    print(f"Models: {MODELS}")

    for model in MODELS:
        existing = len(os.listdir(f"{RESULTS_DIR}/{model}/informed/")) if os.path.isdir(f"{RESULTS_DIR}/{model}/informed/") else 0
        remaining = len(manifest) - existing
        if remaining <= 0:
            print(f"{model}: already complete ({existing}/{len(manifest)})")
            continue
        print(f"\n{model}: {existing}/{len(manifest)} done, {remaining} remaining")
        try:
            run_model(model, manifest)
        except Exception as e:
            print(f"ERROR on {model}: {e}")
            continue


if __name__ == "__main__":
    main()
