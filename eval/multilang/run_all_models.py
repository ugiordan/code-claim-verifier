#!/usr/bin/env python3
"""Run multi-model evaluation for PolyVuln.

Generates reasoning for each model (informed condition), then runs CCV verify.
Resume-safe: skips models whose reasoning dir already has 247 files.

Vertex AI models (no VPN): claude-haiku-4.5
models-corp models (VPN required): llama-3.3-70b, qwen3-14b, granite-3.3-8b, mistral-7b

Usage:
    export CLAUDE_CODE_USE_VERTEX=1 ANTHROPIC_VERTEX_PROJECT_ID=itpc-gcp-ai-eng-claude CLOUD_ML_REGION=us-east5
    python3 eval/multilang/run_all_models.py [--skip-models-corp]
"""
from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from eval.cybergym.utils import load_jsonl
from eval.multilang.generate import generate_one

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

MANIFEST = "eval/multilang/manifest.jsonl"
REASONING_DIR = "eval/multilang/reasoning"
RESULTS_DIR = "eval/multilang/results"
ANALYSIS_DIR = "eval/multilang/analysis"
EXTRACTION_LLM = "claude-sonnet-4"
CONDITION = "informed"

VPN_CHECK_URL = "https://developer.models.corp.redhat.com"

VERTEX_MODELS = [
    "claude-haiku-4.5",
]

MODELS_CORP_MODELS = [
    "llama-3.3-70b",
    "qwen3-14b",
    "granite-3.3-8b",
    "mistral-7b",
]


def check_vpn() -> bool:
    try:
        result = subprocess.run(
            ["curl", "-s", "--max-time", "5", VPN_CHECK_URL],
            capture_output=True, timeout=8,
        )
        return result.returncode == 0
    except Exception:
        return False


def reasoning_count(model: str) -> int:
    path = os.path.join(REASONING_DIR, model, CONDITION)
    if not os.path.isdir(path):
        return 0
    return len([f for f in os.listdir(path) if f.endswith(".json")])


def results_count(model: str) -> int:
    path = os.path.join(RESULTS_DIR, model, CONDITION)
    if not os.path.isdir(path):
        return 0
    return len([f for f in os.listdir(path) if f.endswith(".json")])


def run_generate(model: str, manifest: list[dict]) -> int:
    total = len(manifest)
    success = 0
    skipped = 0
    failed = 0
    start = time.time()

    for i, entry in enumerate(manifest):
        vid = entry["vuln_id"]
        out_path = os.path.join(REASONING_DIR, model, CONDITION, f"{vid}.json")
        if os.path.isfile(out_path):
            skipped += 1
            continue

        result = generate_one(entry, model, CONDITION, REASONING_DIR)
        if result:
            success += 1
        else:
            failed += 1
            logger.warning("Failed to generate %s/%s", model, vid)

        done = success + skipped + failed
        if done % 25 == 0 or done == total:
            elapsed = time.time() - start
            rate = (success + failed) / elapsed if elapsed > 0 else 0
            remaining = total - done
            eta = remaining / rate / 60 if rate > 0 else 0
            logger.info(
                "%s generate: %d/%d (%d new, %d cached, %d failed) ETA: %.0fm",
                model, done, total, success, skipped, failed, eta,
            )

    elapsed = (time.time() - start) / 60
    logger.info(
        "=== %s generate DONE: %d new, %d cached, %d failed [%.1fm] ===",
        model, success, skipped, failed, elapsed,
    )
    return success + skipped


def run_verify(model: str, total: int) -> int:
    cymbal_path = os.path.expanduser("~/go/bin/cymbal")
    cymbal_bak = cymbal_path + ".bak"
    renamed = False
    if os.path.isfile(cymbal_path):
        os.rename(cymbal_path, cymbal_bak)
        renamed = True
        logger.info("Renamed cymbal to cymbal.bak before verify")

    try:
        env = os.environ.copy()
        result = subprocess.run(
            [
                sys.executable, "-m", "eval.cybergym.run_pipeline", "verify",
                "--manifest", MANIFEST,
                "--reasoning-dir", REASONING_DIR,
                "--output-dir", RESULTS_DIR,
                "--extraction-llm", EXTRACTION_LLM,
            ],
            env=env,
            capture_output=False,
        )
        if result.returncode != 0:
            logger.error("%s verify exited with code %d", model, result.returncode)
    finally:
        if renamed and os.path.isfile(cymbal_bak):
            os.rename(cymbal_bak, cymbal_path)
            logger.info("Restored cymbal")

    count = results_count(model)
    logger.info("%s verify: %d/%d results", model, count, total)
    return count


def run_analysis() -> None:
    result = subprocess.run(
        [
            sys.executable, "-m", "eval.cybergym.run_pipeline", "analyze",
            "--results-dir", RESULTS_DIR,
            "--output-dir", ANALYSIS_DIR,
        ],
        capture_output=False,
    )
    if result.returncode != 0:
        logger.error("Analysis failed (exit %d)", result.returncode)


def process_model(model: str, manifest: list[dict], unique_total: int) -> bool:
    total = len(manifest)
    r_count = reasoning_count(model)
    v_count = results_count(model)

    # Use unique_total as the completion threshold (manifest may have duplicate vuln_ids)
    if r_count >= unique_total and v_count >= unique_total:
        logger.info("%s: already complete (%d reasoning, %d results) — skipping", model, r_count, v_count)
        return True

    logger.info("=== %s: %d/%d reasoning, %d/%d results (unique: %d) ===",
                model, r_count, total, v_count, total, unique_total)

    if r_count < unique_total:
        run_generate(model, manifest)
        r_count = reasoning_count(model)
        logger.info("%s: %d/%d reasoning files after generate", model, r_count, unique_total)
    else:
        logger.info("%s: reasoning already complete (%d/%d), skipping generate", model, r_count, unique_total)

    if v_count < unique_total:
        run_verify(model, unique_total)
        v_count = results_count(model)
    else:
        logger.info("%s: verify already complete (%d/%d), skipping", model, v_count, unique_total)

    success = v_count >= unique_total
    if not success:
        logger.warning("%s: only %d/%d results after verify", model, v_count, unique_total)
    return success


def main() -> None:
    parser = argparse.ArgumentParser(description="PolyVuln multi-model evaluation")
    parser.add_argument("--skip-models-corp", action="store_true",
                        help="Skip models-corp models even if VPN is up")
    parser.add_argument("--models-corp-only", action="store_true",
                        help="Run only models-corp models")
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

    manifest = load_jsonl(MANIFEST)
    total = len(manifest)
    unique_total = len({e["vuln_id"] for e in manifest})
    logger.info("Manifest: %d entries (%d unique vuln_ids)", total, unique_total)

    models_to_run: list[str] = []

    if not args.models_corp_only:
        models_to_run.extend(VERTEX_MODELS)

    if not args.skip_models_corp:
        logger.info("Checking VPN for models-corp models...")
        if check_vpn():
            logger.info("VPN up — adding models-corp models")
            models_to_run.extend(MODELS_CORP_MODELS)
        else:
            logger.warning("VPN not reachable (%s) — skipping models-corp models: %s",
                           VPN_CHECK_URL, MODELS_CORP_MODELS)

    if not models_to_run:
        logger.error("No models to run. Check VPN or use --skip-models-corp.")
        sys.exit(1)

    logger.info("Models to run: %s", models_to_run)

    results: dict[str, bool] = {}
    for model in models_to_run:
        try:
            ok = process_model(model, manifest, unique_total)
            results[model] = ok
        except Exception as e:
            logger.exception("ERROR processing %s: %s", model, e)
            results[model] = False

    logger.info("Running final analysis across all models...")
    run_analysis()

    print("\n=== Multi-model eval summary ===")
    for model, ok in results.items():
        v = results_count(model)
        status = "OK" if ok else "INCOMPLETE"
        print(f"  {model}: {v}/{unique_total} results — {status}")

    failed = [m for m, ok in results.items() if not ok]
    if failed:
        print(f"\nIncomplete models: {failed}")
        sys.exit(1)
    else:
        print("\nAll models complete.")


if __name__ == "__main__":
    main()
