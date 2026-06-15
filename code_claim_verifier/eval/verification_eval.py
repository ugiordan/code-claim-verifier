from __future__ import annotations

from collections import defaultdict


def compute_verification_metrics(results: list[dict]) -> dict:
    """Compute verification accuracy and error rates.

    Each result dict must have:
        - expected_verdict: the ground truth verdict
        - actual_verdict: the verdict from the verifier
        - claim_type: the type of the claim

    Returns accuracy, false_refuted_rate, false_verified_rate,
    confusion_matrix, and per_type breakdown.
    """
    if not results:
        return {
            "accuracy": 0.0,
            "false_refuted_rate": 0.0,
            "false_verified_rate": 0.0,
            "total": 0,
            "confusion_matrix": {},
            "per_type": {},
        }

    total = len(results)
    correct = 0
    false_refuted = 0
    false_verified = 0

    # Confusion matrix: {expected: {actual: count}}
    confusion: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    # Per-type metrics: {claim_type: {correct, total}}
    per_type: dict[str, dict[str, int]] = defaultdict(lambda: {"correct": 0, "total": 0})

    for r in results:
        expected = r["expected_verdict"]
        actual = r["actual_verdict"]
        claim_type = r.get("claim_type", "unknown")

        confusion[expected][actual] += 1
        per_type[claim_type]["total"] += 1

        if expected == actual:
            correct += 1
            per_type[claim_type]["correct"] += 1
        elif expected == "VERIFIED" and actual == "REFUTED":
            false_refuted += 1
        elif expected == "REFUTED" and actual == "VERIFIED":
            false_verified += 1

    accuracy = correct / total if total > 0 else 0.0
    false_refuted_rate = false_refuted / total if total > 0 else 0.0
    false_verified_rate = false_verified / total if total > 0 else 0.0

    # Convert per_type to include accuracy
    per_type_final: dict[str, dict] = {}
    for ct, counts in per_type.items():
        ct_acc = counts["correct"] / counts["total"] if counts["total"] > 0 else 0.0
        per_type_final[ct] = {
            "correct": counts["correct"],
            "total": counts["total"],
            "accuracy": round(ct_acc, 4),
        }

    return {
        "accuracy": round(accuracy, 4),
        "false_refuted_rate": round(false_refuted_rate, 4),
        "false_verified_rate": round(false_verified_rate, 4),
        "total": total,
        "confusion_matrix": {k: dict(v) for k, v in confusion.items()},
        "per_type": per_type_final,
    }
