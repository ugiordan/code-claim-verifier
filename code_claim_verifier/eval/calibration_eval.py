from __future__ import annotations

from collections import defaultdict


def compute_calibration_metrics(results: list[dict]) -> dict:
    """Compute calibration metrics for verification results.

    Each result dict must have:
        - expected_verdict: the ground truth verdict
        - actual_verdict: the verdict from the verifier
        - claim_type: the type of the claim
        - confidence: the method_confidence from the verifier

    Returns per_type_accuracy, ECE (expected calibration error),
    and confidence_adjustments.
    """
    if not results:
        return {
            "per_type_accuracy": {},
            "ece": 0.0,
            "confidence_adjustments": {},
        }

    # Per-type accuracy
    per_type: dict[str, dict[str, int]] = defaultdict(lambda: {"correct": 0, "total": 0})
    for r in results:
        claim_type = r.get("claim_type", "unknown")
        per_type[claim_type]["total"] += 1
        if r["expected_verdict"] == r["actual_verdict"]:
            per_type[claim_type]["correct"] += 1

    per_type_accuracy: dict[str, float] = {}
    for ct, counts in per_type.items():
        per_type_accuracy[ct] = round(
            counts["correct"] / counts["total"] if counts["total"] > 0 else 0.0,
            4,
        )

    # ECE: bin results by confidence, compute |accuracy - avg_confidence| per bin
    num_bins = 10
    bins: list[list[dict]] = [[] for _ in range(num_bins)]
    for r in results:
        conf = r.get("confidence", 1.0)
        # Clamp to [0, 1] and assign to bin
        conf = max(0.0, min(1.0, conf))
        bin_idx = min(int(conf * num_bins), num_bins - 1)
        bins[bin_idx].append(r)

    ece = 0.0
    total = len(results)
    for bin_results in bins:
        if not bin_results:
            continue
        bin_size = len(bin_results)
        avg_conf = sum(r.get("confidence", 1.0) for r in bin_results) / bin_size
        bin_acc = sum(
            1 for r in bin_results if r["expected_verdict"] == r["actual_verdict"]
        ) / bin_size
        ece += (bin_size / total) * abs(bin_acc - avg_conf)

    # Confidence adjustments: suggested confidence per type based on actual accuracy
    confidence_adjustments: dict[str, float] = {}
    for ct, acc in per_type_accuracy.items():
        confidence_adjustments[ct] = acc

    return {
        "per_type_accuracy": per_type_accuracy,
        "ece": round(ece, 4),
        "confidence_adjustments": confidence_adjustments,
    }
