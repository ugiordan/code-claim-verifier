from __future__ import annotations

from code_claim_verifier.types import TypedClaim


def claims_match(ground_truth: dict, predicted: TypedClaim) -> bool:
    """Check if a ground truth claim dict matches a predicted TypedClaim.

    Match criteria: same claim_type AND all ground truth parameters
    exist in predicted with equal values. Extra predicted params are OK.
    """
    if ground_truth.get("claim_type") != predicted.claim_type:
        return False
    gt_params = ground_truth.get("parameters", {})
    for key, value in gt_params.items():
        if key not in predicted.parameters:
            return False
        if predicted.parameters[key] != value:
            return False
    return True


def compute_extraction_metrics(
    ground_truth: list[dict],
    predicted: list[TypedClaim],
) -> dict:
    """Compute precision, recall, and F1 for claim extraction.

    Each ground truth claim is matched to at most one predicted claim.
    Each predicted claim is matched to at most one ground truth claim.
    """
    if not ground_truth and not predicted:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0, "matched": 0, "gt_total": 0, "pred_total": 0}

    matched_gt: set[int] = set()
    matched_pred: set[int] = set()

    for gi, gt in enumerate(ground_truth):
        for pi, pred in enumerate(predicted):
            if pi in matched_pred:
                continue
            if claims_match(gt, pred):
                matched_gt.add(gi)
                matched_pred.add(pi)
                break

    num_matched = len(matched_gt)
    precision = num_matched / len(predicted) if predicted else 0.0
    recall = num_matched / len(ground_truth) if ground_truth else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "matched": num_matched,
        "gt_total": len(ground_truth),
        "pred_total": len(predicted),
    }
