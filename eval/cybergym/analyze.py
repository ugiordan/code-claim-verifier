from __future__ import annotations

import logging
import os
from collections import defaultdict

from eval.cybergym.utils import load_json, save_json

logger = logging.getLogger(__name__)


def compute_rq1(results: list[dict]) -> dict:
    by_model: dict[str, dict] = defaultdict(
        lambda: {"total_claims": 0, "total_verified": 0,
                 "total_refuted": 0, "total_unverifiable": 0, "samples": 0}
    )
    for r in results:
        model = r.get("model", "unknown")
        ccv = r.get("ccv", {})
        by_model[model]["total_claims"] += ccv.get("total_claims", 0)
        by_model[model]["total_verified"] += ccv.get("verified", 0)
        by_model[model]["total_refuted"] += ccv.get("refuted", 0)
        by_model[model]["total_unverifiable"] += ccv.get("unverifiable", 0)
        by_model[model]["samples"] += 1
    for model, data in by_model.items():
        total = data["total_claims"]
        data["hallucination_rate"] = round(data["total_refuted"] / total, 4) if total > 0 else 0.0
    return dict(by_model)


def compute_rq2(results: list[dict]) -> dict:
    correct = 0
    total = 0
    false_verified = 0
    false_refuted = 0
    for r in results:
        for m in r.get("gt_comparison", {}).get("results", []):
            total += 1
            if m["expected"] == m["actual"]:
                correct += 1
            if m["expected"] == "REFUTED" and m["actual"] == "VERIFIED":
                false_verified += 1
            if m["expected"] == "VERIFIED" and m["actual"] == "REFUTED":
                false_refuted += 1
    return {
        "accuracy": round(correct / total, 4) if total > 0 else 0.0,
        "false_verified": false_verified,
        "false_refuted": false_refuted,
        "total": total,
    }


def compute_rq4(results: list[dict]) -> dict:
    by_type: dict[str, dict] = defaultdict(
        lambda: {"correct": 0, "total": 0, "confidences": []}
    )
    for r in results:
        for m in r.get("gt_comparison", {}).get("results", []):
            ct = m["claim_type"]
            by_type[ct]["total"] += 1
            if m["expected"] == m["actual"]:
                by_type[ct]["correct"] += 1
            by_type[ct]["confidences"].append(m.get("confidence", 0.0))
    result: dict[str, dict] = {}
    for ct, data in by_type.items():
        result[ct] = {
            "accuracy": round(data["correct"] / data["total"], 4) if data["total"] > 0 else 0.0,
            "count": data["total"],
            "avg_confidence": round(
                sum(data["confidences"]) / len(data["confidences"]), 4
            ) if data["confidences"] else 0.0,
        }
    return result


def run_analyze(results_dir: str, output_dir: str) -> None:
    all_results: list[dict] = []
    for model_dir in sorted(os.listdir(results_dir)):
        model_path = os.path.join(results_dir, model_dir)
        if not os.path.isdir(model_path):
            continue
        for cond_dir in sorted(os.listdir(model_path)):
            cond_path = os.path.join(model_path, cond_dir)
            if not os.path.isdir(cond_path):
                continue
            for fname in sorted(os.listdir(cond_path)):
                if not fname.endswith(".json"):
                    continue
                data = load_json(os.path.join(cond_path, fname))
                if data:
                    all_results.append(data)

    os.makedirs(output_dir, exist_ok=True)
    rq1 = compute_rq1(all_results)
    rq2 = compute_rq2(all_results)
    rq4 = compute_rq4(all_results)

    summary = {"rq1": rq1, "rq2": rq2, "rq4": rq4, "total_results": len(all_results)}
    save_json(summary, os.path.join(output_dir, "summary.json"))
    logger.info("Analysis complete: %d results, written to %s", len(all_results), output_dir)
