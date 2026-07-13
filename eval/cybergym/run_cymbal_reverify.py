#!/usr/bin/env python3
"""Re-verify all results with cymbal enabled. Use with nohup.

verify_one now auto-loads cymbal for each repo. This script clears
old results and re-runs verification (reasoning is cached).
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
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
MODELS = ["granite-3.3-8b", "llama-3.3-70b", "qwen3-14b", "mistral-7b",
          "gpt-oss-20b", "claude-sonnet-4", "claude-haiku-4.5"]


def ensure_git(path):
    if not os.path.isdir(os.path.join(path, ".git")):
        subprocess.run(["git", "init", "-q"], cwd=path, capture_output=True, timeout=10)
        subprocess.run(["git", "add", "-A"], cwd=path, capture_output=True, timeout=60)
        subprocess.run(["git", "commit", "-q", "-m", "init", "--no-verify"],
                       cwd=path, capture_output=True, timeout=60)


def main():
    manifest = load_jsonl(MANIFEST)
    print(f"Manifest: {len(manifest)} repos, Models: {len(MODELS)}", flush=True)

    # Ensure all repos have git init (cymbal requires it)
    print("Ensuring git init on all repos...", flush=True)
    for i, entry in enumerate(manifest):
        sr = entry.get("source_root", "")
        if os.path.isdir(sr):
            try:
                ensure_git(sr)
            except Exception:
                pass
        if (i + 1) % 50 == 0:
            print(f"  git init: {i+1}/{len(manifest)}", flush=True)
    print("Git init done.", flush=True)

    # Clear old results
    if os.path.isdir(RESULTS_DIR):
        shutil.rmtree(RESULTS_DIR)
    print("Cleared old results.", flush=True)

    # Re-verify all models
    start = time.time()
    for model in MODELS:
        s, f = 0, 0
        for i, entry in enumerate(manifest):
            vid = entry["vuln_id"]
            rpath = f"{REASONING_DIR}/{model}/informed/{vid}.json"
            if not os.path.isfile(rpath):
                f += 1
                continue
            ver = verify_one(entry, rpath, RESULTS_DIR, extraction_llm=EXTRACTION_LLM)
            if ver:
                s += 1
            else:
                f += 1
            done = s + f
            if done % 50 == 0:
                elapsed = (time.time() - start) / 60
                print(f"  {model}: {done}/{len(manifest)} [{elapsed:.0f}m]", flush=True)
        elapsed = (time.time() - start) / 60
        print(f"=== {model}: {s} ok, {f} failed [{elapsed:.1f}m] ===", flush=True)

    print(f"\nTotal: {(time.time()-start)/60:.1f} minutes", flush=True)


if __name__ == "__main__":
    main()
