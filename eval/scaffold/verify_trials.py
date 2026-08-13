#!/usr/bin/env python3
"""Run CCV verification on parsed scaffold-effects trials. Use with nohup."""
from __future__ import annotations

import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from code_claim_verifier.extractor import extract_claims
from code_claim_verifier.engine import VerificationEngine
from code_claim_verifier.calibrator import calibrate
from code_claim_verifier.language import detect_language
from eval.cybergym.models import get_model
from eval.cybergym.utils import save_json

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")

TRIALS_JSONL = "eval/scaffold/trials.jsonl"
RESULTS_DIR = "eval/scaffold/results"
EXTRACTION_LLM = "claude-sonnet-4"


def verify_trial(trial: dict, extractor_llm) -> dict | None:
    """Run CCV extraction + verification on a single trial's reasoning."""
    reasoning = trial.get("reasoning", "")
    source_root = trial.get("source_root", "")

    if not reasoning or not source_root or not os.path.isdir(source_root):
        return None

    claims = extract_claims(reasoning, {}, extractor_llm)
    if not claims:
        return {
            "trial_id": trial["trial_id"],
            "harness": trial["harness"],
            "model": trial["model"],
            "task_name": trial["task_name"],
            "solved": trial["solved"],
            "failure_category": trial["failure_category"],
            "tokens_total": trial["tokens_total"],
            "ccv": {
                "total_claims": 0, "verified": 0, "refuted": 0,
                "unverifiable": 0, "verification_rate": 0.0,
                "action": "NO_CHANGE", "claims": [],
            },
        }

    src_files = []
    for root, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")]
        for f in files:
            src_files.append(os.path.join(root, f))
        if len(src_files) > 100:
            break

    lang = "unknown"
    for f in src_files[:20]:
        detected = detect_language(f)
        if detected != "unknown":
            lang = detected
            break

    engine = VerificationEngine()
    verified = engine.verify_claims_with_chaining(claims, source_root, lang)
    report = calibrate(verified)

    return {
        "trial_id": trial["trial_id"],
        "harness": trial["harness"],
        "model": trial["model"],
        "task_name": trial["task_name"],
        "solved": trial["solved"],
        "failure_category": trial["failure_category"],
        "tokens_total": trial["tokens_total"],
        "reasoning_length": trial["reasoning_length"],
        "ccv": {
            "total_claims": report.total_claims,
            "verified": report.verified,
            "refuted": report.refuted,
            "unverifiable": report.unverifiable,
            "verification_rate": report.verification_rate,
            "action": report.action,
            "claims": [
                {
                    "claim_type": vc.claim.claim_type,
                    "parameters": vc.claim.parameters,
                    "verdict": vc.verdict,
                    "confidence": vc.method_confidence,
                    "evidence": vc.evidence[:200],
                    "method": vc.method,
                }
                for vc in verified if not vc.synthesized
            ],
        },
    }


def main():
    with open(TRIALS_JSONL) as f:
        trials = [json.loads(l) for l in f]

    trials = [t for t in trials if t.get("reasoning") and t.get("source_root")]
    print(f"Trials to verify: {len(trials)}", flush=True)

    extractor = get_model(EXTRACTION_LLM)

    start = time.time()
    ok = fail = 0

    for i, trial in enumerate(trials):
        task = trial["task_name"]
        harness = trial["harness"]
        model = trial["model"].split("/")[-1]

        out_path = os.path.join(RESULTS_DIR, harness, model, f"{task}.json")
        if os.path.isfile(out_path):
            ok += 1
            continue

        result = verify_trial(trial, extractor)
        if result:
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            save_json(result, out_path)
            ok += 1
        else:
            fail += 1

        if (i + 1) % 50 == 0:
            elapsed = (time.time() - start) / 60
            print(f"  {i+1}/{len(trials)} [{elapsed:.0f}m] ({ok} ok, {fail} fail)", flush=True)

    elapsed = (time.time() - start) / 60
    print(f"Done: {ok} ok, {fail} fail [{elapsed:.1f}m]", flush=True)


if __name__ == "__main__":
    main()
