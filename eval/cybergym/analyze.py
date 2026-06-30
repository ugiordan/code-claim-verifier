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
    ccv_correct = 0
    ccv_total = 0
    ccv_false_verified = 0
    ccv_false_refuted = 0
    for r in results:
        for m in r.get("gt_comparison", {}).get("results", []):
            ccv_total += 1
            if m["expected"] == m["actual"]:
                ccv_correct += 1
            if m["expected"] == "REFUTED" and m["actual"] == "VERIFIED":
                ccv_false_verified += 1
            if m["expected"] == "VERIFIED" and m["actual"] == "REFUTED":
                ccv_false_refuted += 1

    rq2 = {
        "ccv_accuracy": round(ccv_correct / ccv_total, 4) if ccv_total > 0 else 0.0,
        "ccv_false_verified": ccv_false_verified,
        "ccv_false_refuted": ccv_false_refuted,
        "ccv_total": ccv_total,
    }

    judge_results = [r for r in results if "llm_judge" in r]
    if judge_results:
        j_total = sum(r["llm_judge"]["total_claims"] for r in judge_results)
        j_verified = sum(r["llm_judge"]["verified"] for r in judge_results)
        j_refuted = sum(r["llm_judge"]["refuted"] for r in judge_results)
        ccv_claims_count = sum(r["ccv"]["total_claims"] for r in judge_results)

        disagree_ccv_right = 0
        disagree_judge_right = 0
        both_wrong = 0
        for r in judge_results:
            ccv_claims = r["ccv"].get("claims", [])
            judge_claims = r["llm_judge"].get("claims", [])
            for cc, jc in zip(ccv_claims, judge_claims):
                if cc["verdict"] != jc["verdict"]:
                    if cc["verdict"] in ("VERIFIED", "REFUTED"):
                        disagree_ccv_right += 1
                    else:
                        disagree_judge_right += 1

        rq2["judge_total_claims"] = j_total
        rq2["judge_verified"] = j_verified
        rq2["judge_refuted"] = j_refuted
        rq2["judge_samples"] = len(judge_results)
        rq2["disagreements"] = {
            "ccv_right": disagree_ccv_right,
            "judge_right": disagree_judge_right,
        }

    return rq2


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
